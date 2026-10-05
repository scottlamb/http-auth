// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Server side of the `Digest` scheme, as in
//! [RFC 7616](https://datatracker.ietf.org/doc/html/rfc7616).

use std::time::{Duration, SystemTime};

use super::response::{DigestResponse, NonceChecked, Unchecked, Username};
use super::{h_a1, h_a2, is_hex, nonce, nonce::NonceKey, Algorithm, Qop, QopSet};
use crate::render::{is_quotable, HeaderWriter};
use crate::server::{check_realm, ct_eq, Challenge, ServerError};

/// The request being authenticated, as the server received it.
#[derive(Copy, Clone, Debug)]
pub struct Request<'a> {
    /// The method, e.g. `GET`, or RTSP's `DESCRIBE`.
    pub method: &'a str,

    /// The request-target exactly as on the request line, e.g.
    /// `/dir/index.html?x=1`, `*`, or an absolute URI.
    pub uri: &'a str,

    /// The entity body. Required (use `Some(&[])` if empty) when the
    /// response uses `qop=auth-int`.
    pub body: Option<&'a [u8]>,
}

/// The stored secret for the user being authenticated.
#[derive(Copy, Clone)]
#[non_exhaustive]
pub enum Secret<'a> {
    /// [`Algorithm::ha1`] for the response's algorithm.
    Ha1(&'a str),

    /// The plaintext password. `username` is the canonical stored username.
    Password {
        username: &'a str,
        password: &'a str,
    },
}

impl std::fmt::Debug for Secret<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Secret::Ha1(_) => f.write_str("Ha1(<redacted>)"),
            Secret::Password { username, .. } => f
                .debug_struct("Password")
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
        }
    }
}

/// Issues `Digest` challenges and verifies responses.
///
/// Build once with [`DigestServer::builder`]. Each request is parsed,
/// nonce-checked, then verified:
///
/// ```rust
/// use std::time::SystemTime;
/// use http_auth::digest::{Algorithm, DigestResponse, DigestServer, Request, Secret, Username};
///
/// let server = DigestServer::builder("cams@example.com")
///     .algorithms(&[Algorithm::Sha256, Algorithm::Md5])
///     .build()?;
///
/// // Without credentials, respond 401 with one `WWW-Authenticate` header per challenge.
/// let challenges = server.challenges(false, SystemTime::now());
/// # let header = {
/// #     use std::convert::TryFrom as _;
/// #     let c = http_auth::parse_challenges(challenges[0].as_str()).unwrap();
/// #     http_auth::DigestClient::try_from(&c[0]).unwrap().respond(&http_auth::PasswordParams {
/// #         username: "Mufasa", password: "Circle of Life", uri: "/", method: "GET", body: None,
/// #     }).unwrap()
/// # };
///
/// // On a request with an `Authorization` header:
/// let response = DigestResponse::parse(&header)?;
/// let response = server.check_nonce(response, SystemTime::now())?;
/// // Look up the user here (possibly with .await).
/// assert_eq!(response.username(), Username::Plain("Mufasa"));
/// server.verify(
///     &response,
///     Request { method: "GET", uri: "/", body: None },
///     Secret::Password { username: "Mufasa", password: "Circle of Life" },
/// )?;
/// # Ok::<(), http_auth::server::ServerError>(())
/// ```
///
/// ## Security considerations
///
/// See [`crate::digest::DigestClient`]'s security considerations.
///
/// [`DigestServer::check_nonce`] doesn't detect replays; see
/// [`DigestResponse::nonce_checked_externally`].
#[derive(Clone, Debug)]
pub struct DigestServer {
    realm: Box<str>,
    algorithms: Vec<Algorithm>,
    session: bool,
    qop: QopSet,
    userhash: bool,
    opaque: Option<Box<str>>,
    domain: Option<Box<str>>,
    nonce_key: NonceKey,
    nonce_lifetime: Duration,
}

/// Builds a [`DigestServer`].
#[derive(Clone, Debug)]
pub struct DigestServerBuilder(DigestServer);

impl DigestServerBuilder {
    /// Algorithms to offer, most preferred first; one challenge is issued per
    /// algorithm. Default: `[Md5]`.
    pub fn algorithms(mut self, algorithms: &[Algorithm]) -> Self {
        self.0.algorithms = algorithms.to_vec();
        self
    }

    /// Offers the `-sess` variants instead. Default: `false`.
    pub fn session(mut self, session: bool) -> Self {
        self.0.session = session;
        self
    }

    /// Qualities of protection to offer; must be non-empty. Default:
    /// `Qop::Auth`.
    pub fn qop(mut self, qop: QopSet) -> Self {
        self.0.qop = qop;
        self
    }

    /// Asks clients to hash usernames (RFC 7616 section 3.4.4). Default: `false`.
    pub fn userhash(mut self, userhash: bool) -> Self {
        self.0.userhash = userhash;
        self
    }

    /// An `opaque` value for clients to echo. Default: none.
    pub fn opaque(mut self, opaque: impl Into<String>) -> Self {
        self.0.opaque = Some(opaque.into().into_boxed_str());
        self
    }

    /// URIs defining the protection space (`domain`). Default: none.
    pub fn domain(mut self, uris: &[&str]) -> Self {
        self.0.domain = if uris.is_empty() {
            None
        } else {
            Some(uris.join(" ").into_boxed_str())
        };
        self
    }

    /// The HMAC key for nonces. Default: 32 random bytes. Server instances
    /// behind one load balancer must share a key.
    pub fn nonce_key(mut self, key: [u8; 32]) -> Self {
        self.0.nonce_key = NonceKey(key);
        self
    }

    /// How long an issued nonce stays valid. Default: 5 minutes.
    pub fn nonce_lifetime(mut self, lifetime: Duration) -> Self {
        self.0.nonce_lifetime = lifetime;
        self
    }

    /// Validates the configuration.
    pub fn build(self) -> Result<DigestServer, ServerError> {
        use ServerError::InvalidConfig;
        let s = self.0;
        if s.algorithms.is_empty() {
            return Err(InvalidConfig("no algorithms"));
        }
        for (i, a) in s.algorithms.iter().enumerate() {
            if s.algorithms[..i].contains(a) {
                return Err(InvalidConfig("duplicate algorithm"));
            }
        }
        if s.qop.is_empty() {
            return Err(InvalidConfig("no qop"));
        }
        check_realm(&s.realm)?;
        if s.nonce_lifetime < Duration::from_secs(1) {
            return Err(InvalidConfig("nonce_lifetime must be at least 1 second"));
        }
        if let Some(o) = &s.opaque {
            if !is_quotable(o) {
                return Err(InvalidConfig("opaque must be quotable"));
            }
        }
        if let Some(d) = &s.domain {
            for d in d.split(' ') {
                if d.is_empty() || !d.bytes().all(|b| b.is_ascii_graphic()) {
                    return Err(InvalidConfig("domain URIs must be non-empty visible ASCII"));
                }
            }
        }
        Ok(s)
    }
}

impl DigestServer {
    /// Starts building a server for the given realm.
    pub fn builder(realm: impl Into<String>) -> DigestServerBuilder {
        DigestServerBuilder(DigestServer {
            realm: realm.into().into_boxed_str(),
            algorithms: vec![Algorithm::Md5],
            session: false,
            qop: Qop::Auth.into(),
            userhash: false,
            opaque: None,
            domain: None,
            nonce_key: NonceKey(rand::random()),
            nonce_lifetime: Duration::from_secs(300),
        })
    }

    /// Returns one challenge per offered algorithm, in preference order,
    /// sharing a fresh nonce. Set `stale` after [`ServerError::Stale`].
    pub fn challenges(&self, stale: bool, now: SystemTime) -> Vec<Challenge> {
        let nonce = nonce::issue(&self.nonce_key.0, &self.realm, now, rand::random());
        let qop = [Qop::Auth, Qop::AuthInt]
            .iter()
            .filter(|q| self.qop.contains(**q))
            .map(|q| q.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        self.algorithms
            .iter()
            .map(|a| {
                let mut w = HeaderWriter::new("Digest");
                w.quoted("realm", &self.realm);
                if let Some(d) = &self.domain {
                    w.quoted("domain", d);
                }
                w.quoted("nonce", &nonce);
                if let Some(o) = &self.opaque {
                    w.quoted("opaque", o);
                }
                if stale {
                    w.token("stale", "true");
                }
                w.token("algorithm", a.as_str(self.session));
                w.quoted("qop", &qop);
                w.token("charset", "UTF-8");
                if self.userhash {
                    w.token("userhash", "true");
                }
                Challenge(w.finish())
            })
            .collect()
    }

    /// Checks the nonce's HMAC: [`ServerError::BadNonce`] if not issued by
    /// this server. An expired nonce is marked [`DigestResponse::stale`].
    pub fn check_nonce<'i>(
        &self,
        response: DigestResponse<'i, Unchecked>,
        now: SystemTime,
    ) -> Result<DigestResponse<'i, NonceChecked>, ServerError> {
        let validity = nonce::check(
            &self.nonce_key.0,
            &self.realm,
            response.nonce(),
            now,
            self.nonce_lifetime,
        )?;
        Ok(response.into_checked(matches!(validity, nonce::Validity::Stale)))
    }

    /// Returns the [`Username::Hashed`] form of `username`; use it to index
    /// users.
    pub fn hash_username(&self, username: &str, algorithm: Algorithm) -> String {
        algorithm.h(&[username.as_bytes(), self.realm.as_bytes()])
    }

    /// Verifies `response` against `request` and `secret`
    /// ([RFC 7616 section 3.4](https://datatracker.ietf.org/doc/html/rfc7616#section-3.4)).
    /// Returns [`ServerError::Stale`] only if everything else verifies.
    pub fn verify(
        &self,
        response: &DigestResponse<'_, NonceChecked>,
        request: Request<'_>,
        secret: Secret<'_>,
    ) -> Result<(), ServerError> {
        if response.realm() != &*self.realm {
            return Err(ServerError::WrongRealm);
        }
        let algorithm = response.algorithm();
        if response.session() != self.session || !self.algorithms.contains(&algorithm) {
            return Err(ServerError::UnofferedAlgorithm);
        }
        if !self.qop.contains(response.qop()) {
            return Err(ServerError::UnofferedQop);
        }
        if response.opaque() != self.opaque.as_deref() {
            return Err(ServerError::WrongOpaque);
        }
        if response.userhash() && !self.userhash {
            return Err(ServerError::UnofferedUserhash);
        }
        if response.uri() != request.uri {
            return Err(ServerError::UriMismatch);
        }
        let body = match (response.qop(), request.body) {
            (Qop::AuthInt, None) => return Err(ServerError::BodyRequired),
            (_, body) => body.unwrap_or(&[]),
        };
        let ha1 = match secret {
            Secret::Ha1(ha1) => {
                if !is_hex(ha1, algorithm.hex_len()) {
                    return Err(ServerError::SecretMismatch);
                }
                ha1.to_ascii_lowercase()
            }
            Secret::Password { username, password } => {
                let same_user = match response.username() {
                    Username::Plain(u) => u == username,
                    Username::Hashed(h) => ct_eq(
                        h.as_bytes(),
                        self.hash_username(username, algorithm).as_bytes(),
                    ),
                };
                if !same_user {
                    return Err(ServerError::BadCredentials);
                }
                algorithm.ha1(username, &self.realm, password)
            }
        };
        let (nonce, cnonce) = (response.nonce(), response.cnonce());
        let h_a1 = h_a1(algorithm, response.session(), &ha1, nonce, cnonce);
        let h_a2 = h_a2(
            algorithm,
            response.qop(),
            request.method,
            response.uri(),
            body,
        );
        let expected = algorithm.h(&[
            h_a1.as_bytes(),
            nonce.as_bytes(),
            response.nc_hex().as_bytes(),
            cnonce.as_bytes(),
            response.qop_str().as_bytes(),
            h_a2.as_bytes(),
        ]);
        if ct_eq(
            expected.as_bytes(),
            response.response_hex().to_ascii_lowercase().as_bytes(),
        ) {
            if response.stale() {
                Err(ServerError::Stale)
            } else {
                Ok(())
            }
        } else {
            Err(ServerError::BadCredentials)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{
        RFC2617, RFC7616_MD5, RFC7616_SHA256, RFC7616_USERHASH, RFC7616_USERNAME_STAR,
    };
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn pw(u: &'static str, p: &'static str) -> Secret<'static> {
        Secret::Password {
            username: u,
            password: p,
        }
    }

    fn b() -> DigestServerBuilder {
        DigestServer::builder("testrealm@host.com").opaque("5ccc069c403ebaf9f0171e9517f40e41")
    }

    fn s() -> DigestServer {
        b().qop(Qop::Auth | Qop::AuthInt).build().unwrap()
    }

    fn get(uri: &str) -> Request<'_> {
        Request {
            method: "GET",
            uri,
            body: None,
        }
    }

    fn verify(
        server: &DigestServer,
        header: &str,
        request: Request<'_>,
        secret: Secret<'_>,
    ) -> Result<(), ServerError> {
        let r = DigestResponse::parse(header)?.nonce_checked_externally();
        server.verify(&r, request, secret)
    }

    #[test]
    fn rfc2617_3_5() {
        let s = s();
        let ha1 = Algorithm::Md5.ha1("Mufasa", "testrealm@host.com", "Circle Of Life");
        let upper_resp = RFC2617.replace(
            "6629fae49393a05397450978507c4ef1",
            "6629FAE49393A05397450978507C4EF1",
        );
        for (res, secret) in [
            (RFC2617, pw("Mufasa", "Circle Of Life")),
            (RFC2617, Secret::Ha1(&ha1)),
            (RFC2617, Secret::Ha1(&ha1.to_ascii_uppercase())),
            (upper_resp.as_str(), pw("Mufasa", "Circle Of Life")),
        ] {
            assert_eq!(verify(&s, res, get("/dir/index.html"), secret), Ok(()));
        }
    }

    #[test]
    fn rfc7616_3_9() {
        let s = DigestServer::builder("http-auth@example.org")
            .algorithms(&[Algorithm::Sha256, Algorithm::Md5])
            .qop(Qop::Auth | Qop::AuthInt)
            .opaque("FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS")
            .build()
            .unwrap();
        let secret = pw("Mufasa", "Circle of Life");
        for header in [RFC7616_SHA256, RFC7616_MD5] {
            assert_eq!(verify(&s, header, get("/dir/index.html"), secret), Ok(()));
        }
        let builder = DigestServer::builder("api@example.org")
            .algorithms(&[Algorithm::Sha512Trunc256])
            .opaque("HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS");
        let s = builder.clone().userhash(true).build().unwrap();
        let user = "J\u{e4}s\u{f8}n Doe";
        #[rustfmt::skip]
        assert_eq!(s.hash_username(user, Algorithm::Sha512Trunc256), "793263caabb707a56211940d90411ea4a575adeccb7e360aeb624ed06ece9b0b");
        let pw = pw(user, "Secret, or not?");
        assert_eq!(verify(&s, RFC7616_USERHASH, get("/doe.json"), pw), Ok(()));
        #[rustfmt::skip]
        assert_eq!(verify(&builder.build().unwrap(), RFC7616_USERNAME_STAR, get("/doe.json"), pw), Ok(()));
    }

    #[test]
    fn verify_errors() {
        use ServerError::*;
        let s = s();
        let ok = get("/dir/index.html");
        let r = |from: &str, to: &str| RFC2617.replace(from, to);
        let sha = b().algorithms(&[Algorithm::Sha256]).build().unwrap();
        let int = b().qop(Qop::AuthInt.into()).build().unwrap();
        let noop = DigestServer::builder("testrealm@host.com")
            .qop(Qop::Auth.into())
            .build()
            .unwrap();
        let uh = b().qop(Qop::Auth.into()).userhash(true).build().unwrap();
        let h = s.hash_username("Mufasa", Algorithm::Md5);
        let simba = uh.hash_username("Simba", Algorithm::Md5);
        let z = "z".repeat(32);
        #[rustfmt::skip]
        let cases: [(&DigestServer, String, Request<'_>, Secret<'_>, ServerError); 14] = [
            (&s, r("realm=\"testrealm@host.com\"", "realm=\"other\""), ok, pw("Mufasa", "Circle Of Life"), WrongRealm),
            (&sha, RFC2617.into(), ok, pw("Mufasa", "Circle Of Life"), UnofferedAlgorithm),
            (&s, r("opaque=", "algorithm=MD5-sess, opaque="), ok, pw("Mufasa", "Circle Of Life"), UnofferedAlgorithm),
            (&int, RFC2617.into(), ok, pw("Mufasa", "Circle Of Life"), UnofferedQop),
            (&s, r(", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"", ""), ok, pw("Mufasa", "Circle Of Life"), WrongOpaque),
            (&noop, RFC2617.into(), ok, pw("Mufasa", "Circle Of Life"), WrongOpaque),
            (&s, r("username=\"Mufasa\"", &format!("username=\"{}\", userhash=true", h)), ok, pw("Mufasa", "Circle Of Life"), UnofferedUserhash),
            (&s, RFC2617.into(), get("/dir/other.html"), pw("Mufasa", "Circle Of Life"), UriMismatch),
            (&s, r("qop=auth", "qop=auth-int"), ok, pw("Mufasa", "Circle Of Life"), BodyRequired),
            (&s, RFC2617.into(), ok, Secret::Ha1("abc"), SecretMismatch),
            (&s, RFC2617.into(), ok, Secret::Ha1(&z), SecretMismatch),
            (&s, RFC2617.into(), ok, pw("Mufasa", "Circle of Life"), BadCredentials),
            (&s, RFC2617.into(), ok, pw("Simba", "Circle Of Life"), BadCredentials),
            (&uh, r("username=\"Mufasa\"", &format!("username=\"{}\", userhash=true", simba)), ok, pw("Mufasa", "Circle Of Life"), BadCredentials),
        ];
        for (server, header, req, secret, expected) in cases {
            assert_eq!(verify(server, &header, req, secret), Err(expected));
        }
    }

    #[test]
    fn nc_hashed_as_sent() {
        let ha1 = Algorithm::Md5.ha1("Mufasa", "testrealm@host.com", "Circle Of Life");
        let h_a2 = h_a2(Algorithm::Md5, Qop::Auth, "GET", "/dir/index.html", b"");
        let resp = Algorithm::Md5.h(&[
            ha1.as_bytes(),
            b"dcd98b7102dd2f0e8b11d0f600bfb0c093",
            b"0000000A",
            b"0a4f113b",
            b"auth",
            h_a2.as_bytes(),
        ]);
        let h = RFC2617
            .replace("nc=00000001", "nc=0000000A")
            .replace("6629fae49393a05397450978507c4ef1", &resp);
        #[rustfmt::skip]
        assert_eq!(verify(&s(), &h, get("/dir/index.html"), pw("Mufasa", "Circle Of Life")), Ok(()));
    }

    #[test]
    fn challenges() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        #[rustfmt::skip]
        let nonce = |c: &Challenge| {
            crate::parse_challenges(c.as_str()).unwrap()[0].params.iter()
                .find(|(k, _)| *k == "nonce").unwrap().1.to_unescaped().into_owned()
        };
        let s = DigestServer::builder("cams@example.com")
            .algorithms(&[Algorithm::Sha256, Algorithm::Md5])
            .opaque("xyz")
            .userhash(true)
            .build()
            .unwrap();
        let c = s.challenges(false, now);
        assert_eq!(c.len(), 2);
        assert_eq!(nonce(&c[0]), nonce(&c[1]));
        #[rustfmt::skip]
        assert_eq!(c[0].as_str(), format!("Digest realm=\"cams@example.com\", nonce=\"{}\", opaque=\"xyz\", algorithm=SHA-256, qop=\"auth\", charset=UTF-8, userhash=true", nonce(&c[0])));
        assert!(c[1].as_str().contains("algorithm=MD5, "));
        assert!(s.challenges(true, now)[0]
            .as_str()
            .contains("\", stale=true, algorithm=SHA-256"));
        let sess = DigestServer::builder("r")
            .session(true)
            .qop(Qop::Auth | Qop::AuthInt)
            .domain(&["/a", "/b"])
            .build()
            .unwrap();
        #[rustfmt::skip]
        let sc = sess.challenges(false, now);
        #[rustfmt::skip]
        assert_eq!(sc[0].as_str(), format!("Digest realm=\"r\", domain=\"/a /b\", nonce=\"{}\", algorithm=MD5-sess, qop=\"auth, auth-int\", charset=UTF-8", nonce(&sc[0])));
    }

    #[test]
    fn builder_errors() {
        let b = || DigestServer::builder("r");
        for result in [
            b().algorithms(&[]).build(),
            b().algorithms(&[Algorithm::Md5, Algorithm::Md5]).build(),
            b().qop(QopSet(0)).build(),
            DigestServer::builder("r\n").build(),
            b().opaque("caf\u{e9}").build(),
            b().domain(&["/a\0b"]).build(),
            b().domain(&[""]).build(),
            b().nonce_lifetime(Duration::from_millis(999)).build(),
            b().nonce_lifetime(Duration::from_secs(0)).build(),
        ] {
            assert!(matches!(result, Err(ServerError::InvalidConfig(_))));
        }
    }

    #[test]
    fn check_nonce_cycle() {
        let s = DigestServer::builder("r").build().unwrap();
        let t0 = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let nonce = nonce::issue(&s.nonce_key.0, "r", t0, [1; 8]);
        let header = format!(
            "Digest username=\"u\", realm=\"r\", nonce=\"{}\", uri=\"/x\", nc=00000001, cnonce=\"0a4f113b\", qop=auth, response=\"{}\"",
            nonce,
            "0".repeat(32)
        );
        #[rustfmt::skip]
        assert!(!s.check_nonce(DigestResponse::parse(&header).unwrap(), t0).unwrap().stale());
        assert!(s
            .check_nonce(
                DigestResponse::parse(&header).unwrap(),
                t0 + Duration::from_secs(301)
            )
            .unwrap()
            .stale());
        let other = DigestServer::builder("r").build().unwrap();
        #[rustfmt::skip]
        assert_eq!(other.check_nonce(DigestResponse::parse(&header).unwrap(), t0).unwrap_err(), ServerError::BadNonce);
    }

    #[test]
    fn shared_across_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DigestServer>();
    }

    #[test]
    fn debug_redacts() {
        let d = format!("{:?}", s());
        assert!(
            d.contains("testrealm@host.com") && !d.contains("nonce_key: ["),
            "{}",
            d
        );
        assert!(!format!("{:?}", pw("Mufasa", "Circle Of Life")).contains("Circle"));
        let d = format!("{:?}", DigestServer::builder("r").nonce_key([9; 32]));
        assert!(d.contains("<redacted>") && !d.contains("[9, 9, 9"), "{}", d);
    }
}
