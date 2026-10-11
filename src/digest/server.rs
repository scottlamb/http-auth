// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Server side of the `Digest` scheme, as in
//! [RFC 7616](https://datatracker.ietf.org/doc/html/rfc7616).

use std::borrow::Cow;
use std::time::{Duration, SystemTime};

use super::response::{CredentialsRef, NonceChecked, Unchecked, Username};
use super::{h_a1, h_a2, is_hex, nonce, nonce::NonceKey, Algorithm, Qop, QopSet};
use crate::render::{is_quotable, HeaderWriter};
use crate::server::{check_realm, Challenge, ConfigError, ServerError};
use subtle::ConstantTimeEq as _;

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

/// `H(username ":" realm ":" password)` for one algorithm: a
/// password-equivalent secret to store in place of the password.
///
/// Create with [`Algorithm::ha1`], or [`Ha1::from_hex`] for a stored value.
#[derive(Clone, Eq, PartialEq)]
pub struct Ha1 {
    pub(crate) algorithm: Algorithm,
    pub(crate) hex: String,
}

impl Ha1 {
    /// Parses a stored value: hex (either case) of `algorithm`'s digest
    /// length.
    pub fn from_hex(algorithm: Algorithm, hex: &str) -> Result<Self, ConfigError> {
        if !is_hex(hex, algorithm.hex_len()) {
            return Err(ConfigError("HA1 is not hex of the algorithm's length"));
        }
        Ok(Ha1 {
            algorithm,
            hex: hex.to_ascii_lowercase(),
        })
    }

    /// Returns the algorithm.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns the digest in lowercase hex, for storage.
    pub fn as_hex(&self) -> &str {
        &self.hex
    }
}

impl std::fmt::Debug for Ha1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ha1")
            .field("algorithm", &self.algorithm)
            .field("hex", &"<redacted>")
            .finish()
    }
}

/// The stored secret for the user being authenticated.
#[derive(Copy, Clone)]
#[non_exhaustive]
pub enum Secret<'a> {
    /// The HA1 for the response's [`CredentialsRef::algorithm`]; others
    /// fail with [`ServerError::SecretMismatch`].
    Ha1(&'a Ha1),

    /// The plaintext password. `username` is the canonical stored username.
    Password {
        username: &'a str,
        password: &'a str,
    },
}

impl std::fmt::Debug for Secret<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Secret::Ha1(ha1) => f.debug_tuple("Ha1").field(ha1).finish(),
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
/// Build once with [`Server::builder`]. Each request is parsed,
/// nonce-checked, then verified:
///
/// ```rust
/// use std::time::SystemTime;
/// use http_auth::digest::{Algorithm, CredentialsRef, Server, Request, Secret, Username};
///
/// let server = Server::builder("cams@example.com", &[Algorithm::Sha256, Algorithm::Md5])
///     .build()?;
///
/// // Without credentials, respond 401 with one `WWW-Authenticate` header per challenge.
/// let challenges = server.challenges(false, SystemTime::now());
/// # let header = {
/// #     use std::convert::TryFrom as _;
/// #     let c = http_auth::parse_challenges(challenges[0].as_str()).unwrap();
/// #     http_auth::digest::Client::try_from(&c[0]).unwrap().respond(&http_auth::PasswordParams {
/// #         username: "Mufasa", password: "Circle of Life", uri: "/", method: "GET", body: None,
/// #     }).unwrap()
/// # };
///
/// // On a request with an `Authorization` header:
/// let response = CredentialsRef::parse(&header)?;
/// let response = server.check_nonce(response, SystemTime::now())?;
/// // Look up the user here (possibly with .await); `None` if unknown.
/// assert_eq!(response.username(), Username::Plain("Mufasa"));
/// let secret = Some(Secret::Password { username: "Mufasa", password: "Circle of Life" });
/// server.verify(&response, Request { method: "GET", uri: "/", body: None }, secret)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// ## Security considerations
///
/// See [`crate::digest::Client`]'s security considerations.
///
/// [`Server::check_nonce`] doesn't detect replays; see
/// [`CredentialsRef::nonce_checked_externally`].
#[derive(Clone, Debug)]
pub struct Server {
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

/// Builds a [`Server`].
#[derive(Clone, Debug)]
pub struct ServerBuilder(Server);

impl ServerBuilder {
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
    pub fn build(self) -> Result<Server, ConfigError> {
        let s = self.0;
        if s.algorithms.is_empty() {
            return Err(ConfigError("no algorithms"));
        }
        for (i, a) in s.algorithms.iter().enumerate() {
            if s.algorithms[..i].contains(a) {
                return Err(ConfigError("duplicate algorithm"));
            }
        }
        if s.qop.is_empty() {
            return Err(ConfigError("no qop"));
        }
        check_realm(&s.realm)?;
        if s.nonce_lifetime < Duration::from_secs(1) {
            return Err(ConfigError("nonce_lifetime must be at least 1 second"));
        }
        if let Some(o) = &s.opaque {
            if !is_quotable(o) {
                return Err(ConfigError("opaque must be quotable"));
            }
        }
        if let Some(d) = &s.domain {
            for d in d.split(' ') {
                if d.is_empty() || !d.bytes().all(|b| b.is_ascii_graphic()) {
                    return Err(ConfigError("domain URIs must be non-empty visible ASCII"));
                }
            }
        }
        Ok(s)
    }
}

impl Server {
    /// Starts building a server for the given realm, offering `algorithms`
    /// (non-empty, most preferred first). One challenge is issued per
    /// algorithm.
    ///
    /// Offering [`Algorithm::Md5`] alongside stronger algorithms allows
    /// downgrade ([RFC 7616 section
    /// 5.6](https://datatracker.ietf.org/doc/html/rfc7616#section-5.6)), but
    /// some clients support only `MD5`.
    pub fn builder(realm: impl Into<String>, algorithms: &[Algorithm]) -> ServerBuilder {
        ServerBuilder(Server {
            realm: realm.into().into_boxed_str(),
            algorithms: algorithms.to_vec(),
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
    /// this server. An expired nonce is marked [`CredentialsRef::stale`].
    pub fn check_nonce<'i>(
        &self,
        response: CredentialsRef<'i, Unchecked>,
        now: SystemTime,
    ) -> Result<CredentialsRef<'i, NonceChecked>, ServerError> {
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
    ///
    /// Pass `None` for an unknown user: this returns
    /// [`ServerError::BadCredentials`] after the same work as for a wrong
    /// password, so response timing doesn't reveal whether the user exists
    /// (beyond any difference in the caller's own lookup).
    pub fn verify(
        &self,
        response: &CredentialsRef<'_, NonceChecked>,
        request: Request<'_>,
        secret: Option<Secret<'_>>,
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
        let (ha1, known_user) = match secret {
            Some(Secret::Ha1(ha1)) => {
                if ha1.algorithm != algorithm {
                    return Err(ServerError::SecretMismatch);
                }
                (Cow::Borrowed(ha1.hex.as_str()), true)
            }
            Some(Secret::Password { username, password }) => {
                let same_user = match response.username() {
                    Username::Plain(u) => u == username,
                    Username::Hashed(h) => bool::from(
                        h.as_bytes()
                            .ct_eq(self.hash_username(username, algorithm).as_bytes()),
                    ),
                };
                if !same_user {
                    return Err(ServerError::BadCredentials);
                }
                (
                    Cow::Owned(algorithm.ha1_hex(username, &self.realm, password)),
                    true,
                )
            }
            None => (Cow::Owned(algorithm.ha1_hex("", &self.realm, "")), false),
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
        let actual = response.response_hex().to_ascii_lowercase();
        if bool::from(expected.as_bytes().ct_eq(actual.as_bytes())) && known_user {
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

    fn pw(u: &'static str, p: &'static str) -> Option<Secret<'static>> {
        Some(Secret::Password {
            username: u,
            password: p,
        })
    }

    fn b() -> ServerBuilder {
        Server::builder("testrealm@host.com", &[Algorithm::Md5])
            .opaque("5ccc069c403ebaf9f0171e9517f40e41")
    }

    fn s() -> Server {
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
        server: &Server,
        header: &str,
        request: Request<'_>,
        secret: Option<Secret<'_>>,
    ) -> Result<(), ServerError> {
        let r = CredentialsRef::parse(header)?.nonce_checked_externally();
        server.verify(&r, request, secret)
    }

    #[test]
    fn rfc2617_3_5() {
        let s = s();
        let ha1 = Algorithm::Md5.ha1("Mufasa", "testrealm@host.com", "Circle Of Life");
        let upper_ha1 = Ha1::from_hex(Algorithm::Md5, &ha1.as_hex().to_ascii_uppercase()).unwrap();
        assert_eq!(upper_ha1, ha1);
        let upper_resp = RFC2617.replace(
            "6629fae49393a05397450978507c4ef1",
            "6629FAE49393A05397450978507C4EF1",
        );
        for (res, secret) in [
            (RFC2617, pw("Mufasa", "Circle Of Life")),
            (RFC2617, Some(Secret::Ha1(&ha1))),
            (upper_resp.as_str(), pw("Mufasa", "Circle Of Life")),
        ] {
            assert_eq!(verify(&s, res, get("/dir/index.html"), secret), Ok(()));
        }
    }

    #[test]
    fn rfc7616_3_9() {
        let s = Server::builder(
            "http-auth@example.org",
            &[Algorithm::Sha256, Algorithm::Md5],
        )
        .qop(Qop::Auth | Qop::AuthInt)
        .opaque("FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS")
        .build()
        .unwrap();
        let secret = pw("Mufasa", "Circle of Life");
        for header in [RFC7616_SHA256, RFC7616_MD5] {
            assert_eq!(verify(&s, header, get("/dir/index.html"), secret), Ok(()));
        }
        let builder = Server::builder("api@example.org", &[Algorithm::Sha512_256])
            .opaque("HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS");
        let s = builder.clone().userhash(true).build().unwrap();
        let user = "J\u{e4}s\u{f8}n Doe";
        #[rustfmt::skip]
        assert_eq!(s.hash_username(user, Algorithm::Sha512_256), "793263caabb707a56211940d90411ea4a575adeccb7e360aeb624ed06ece9b0b");
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
        let sha = Server::builder("testrealm@host.com", &[Algorithm::Sha256])
            .opaque("5ccc069c403ebaf9f0171e9517f40e41")
            .build()
            .unwrap();
        let int = b().qop(Qop::AuthInt.into()).build().unwrap();
        let noop = Server::builder("testrealm@host.com", &[Algorithm::Md5])
            .qop(Qop::Auth.into())
            .build()
            .unwrap();
        let uh = b().qop(Qop::Auth.into()).userhash(true).build().unwrap();
        let h = s.hash_username("Mufasa", Algorithm::Md5);
        let simba = uh.hash_username("Simba", Algorithm::Md5);
        // Right password, but for SHA-512-256 (same hex length as SHA-256).
        let sha512_256 =
            Algorithm::Sha512_256.ha1("Mufasa", "testrealm@host.com", "Circle Of Life");
        let sha_header = RFC2617
            .replace(", opaque=", ", algorithm=SHA-256, opaque=")
            .replace("6629fae49393a05397450978507c4ef1", &"0".repeat(64));
        #[rustfmt::skip]
        let cases: [(&Server, String, Request<'_>, Option<Secret<'_>>, ServerError); 15] = [
            (&s, r("realm=\"testrealm@host.com\"", "realm=\"other\""), ok, pw("Mufasa", "Circle Of Life"), WrongRealm),
            (&sha, RFC2617.into(), ok, pw("Mufasa", "Circle Of Life"), UnofferedAlgorithm),
            (&s, r("opaque=", "algorithm=MD5-sess, opaque="), ok, pw("Mufasa", "Circle Of Life"), UnofferedAlgorithm),
            (&int, RFC2617.into(), ok, pw("Mufasa", "Circle Of Life"), UnofferedQop),
            (&s, r(", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"", ""), ok, pw("Mufasa", "Circle Of Life"), WrongOpaque),
            (&noop, RFC2617.into(), ok, pw("Mufasa", "Circle Of Life"), WrongOpaque),
            (&s, r("username=\"Mufasa\"", &format!("username=\"{}\", userhash=true", h)), ok, pw("Mufasa", "Circle Of Life"), UnofferedUserhash),
            (&s, RFC2617.into(), get("/dir/other.html"), pw("Mufasa", "Circle Of Life"), UriMismatch),
            (&s, r("qop=auth", "qop=auth-int"), ok, pw("Mufasa", "Circle Of Life"), BodyRequired),
            (&s, RFC2617.into(), ok, Some(Secret::Ha1(&sha512_256)), SecretMismatch),
            (&sha, sha_header, ok, Some(Secret::Ha1(&sha512_256)), SecretMismatch),
            (&s, RFC2617.into(), ok, None, BadCredentials),
            (&s, RFC2617.into(), ok, pw("Mufasa", "Circle of Life"), BadCredentials),
            (&s, RFC2617.into(), ok, pw("Simba", "Circle Of Life"), BadCredentials),
            (&uh, r("username=\"Mufasa\"", &format!("username=\"{}\", userhash=true", simba)), ok, pw("Mufasa", "Circle Of Life"), BadCredentials),
        ];
        for (server, header, req, secret, expected) in cases {
            assert_eq!(verify(server, &header, req, secret), Err(expected));
        }
    }

    #[test]
    fn ha1_from_hex() {
        for (algorithm, hex) in [
            (Algorithm::Md5, "abc".to_owned()),
            (Algorithm::Md5, "z".repeat(32)),
            (Algorithm::Sha256, "0".repeat(32)),
        ] {
            assert!(
                Ha1::from_hex(algorithm, &hex).is_err(),
                "{:?} {}",
                algorithm,
                hex
            );
        }
        let h = Ha1::from_hex(Algorithm::Sha256, &"A".repeat(64)).unwrap();
        assert_eq!(
            (h.algorithm(), h.as_hex()),
            (Algorithm::Sha256, &*"a".repeat(64))
        );
        assert!(!format!("{:?}", h).contains("aaaa"));
    }

    #[test]
    fn nc_hashed_as_sent() {
        let ha1 = Algorithm::Md5.ha1_hex("Mufasa", "testrealm@host.com", "Circle Of Life");
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
            crate::parse_challenges(c.as_str()).unwrap()[0].body.params().unwrap().iter()
                .find(|(k, _)| *k == "nonce").unwrap().1.to_unescaped().into_owned()
        };
        let s = Server::builder("cams@example.com", &[Algorithm::Sha256, Algorithm::Md5])
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
        let sess = Server::builder("r", &[Algorithm::Md5])
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
        let b = || Server::builder("r", &[Algorithm::Md5]);
        for result in [
            Server::builder("r", &[]).build(),
            Server::builder("r", &[Algorithm::Md5, Algorithm::Md5]).build(),
            b().qop(QopSet(0)).build(),
            Server::builder("r\n", &[Algorithm::Md5]).build(),
            b().opaque("caf\u{e9}").build(),
            b().domain(&["/a\0b"]).build(),
            b().domain(&[""]).build(),
            b().nonce_lifetime(Duration::from_millis(999)).build(),
            b().nonce_lifetime(Duration::from_secs(0)).build(),
        ] {
            assert!(result.is_err());
        }
    }

    #[test]
    fn check_nonce_cycle() {
        let s = Server::builder("r", &[Algorithm::Md5]).build().unwrap();
        let t0 = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let nonce = nonce::issue(&s.nonce_key.0, "r", t0, [1; 8]);
        let header = format!(
            "Digest username=\"u\", realm=\"r\", nonce=\"{}\", uri=\"/x\", nc=00000001, cnonce=\"0a4f113b\", qop=auth, response=\"{}\"",
            nonce,
            "0".repeat(32)
        );
        #[rustfmt::skip]
        assert!(!s.check_nonce(CredentialsRef::parse(&header).unwrap(), t0).unwrap().stale());
        assert!(s
            .check_nonce(
                CredentialsRef::parse(&header).unwrap(),
                t0 + Duration::from_secs(301)
            )
            .unwrap()
            .stale());
        let other = Server::builder("r", &[Algorithm::Md5]).build().unwrap();
        #[rustfmt::skip]
        assert_eq!(other.check_nonce(CredentialsRef::parse(&header).unwrap(), t0).unwrap_err(), ServerError::BadNonce);
    }

    #[test]
    fn stale() {
        use std::convert::TryFrom as _;
        let s = Server::builder("r", &[Algorithm::Md5]).build().unwrap();
        let t0 = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let later = t0 + Duration::from_secs(301);
        let c = &s.challenges(false, t0)[0];
        let c = &crate::parse_challenges(c.as_str()).unwrap()[0];
        let mut client = crate::digest::Client::try_from(c).unwrap();
        for (password, expected) in [
            ("p", ServerError::Stale),
            ("q", ServerError::BadCredentials),
        ] {
            let header = client
                .respond(&crate::PasswordParams {
                    username: "u",
                    password,
                    uri: "/x",
                    method: "GET",
                    body: None,
                })
                .unwrap();
            let r = s
                .check_nonce(CredentialsRef::parse(&header).unwrap(), later)
                .unwrap();
            assert_eq!(s.verify(&r, get("/x"), pw("u", "p")), Err(expected));
        }
        assert!(s.challenges(true, later)[0]
            .as_str()
            .contains(", stale=true, "));
    }

    #[test]
    fn shared_across_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Server>();
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
        let ha1 = Algorithm::Md5.ha1("Mufasa", "testrealm@host.com", "Circle Of Life");
        let d = format!("{:?}", Secret::Ha1(&ha1));
        assert!(!d.contains(ha1.as_hex()), "{}", d);
        let d = format!(
            "{:?}",
            Server::builder("r", &[Algorithm::Md5]).nonce_key([9; 32])
        );
        assert!(d.contains("<redacted>") && !d.contains("[9, 9, 9"), "{}", d);
    }
}
