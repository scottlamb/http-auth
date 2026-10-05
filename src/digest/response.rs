// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parsing of `Digest` credentials, as in
//! [RFC 7616 section 3.4](https://datatracker.ietf.org/doc/html/rfc7616#section-3.4).

use std::{borrow::Cow, marker::PhantomData};

use super::{is_hex, Algorithm, Qop};
use crate::server::{parse_scheme, ServerError};

/// Typestate for a [`DigestResponse`] whose nonce hasn't been checked yet.
#[derive(Debug)]
pub enum Unchecked {}

/// Typestate for a [`DigestResponse`] whose nonce was checked by
/// [`super::DigestServer::check_nonce`] or vouched for via
/// [`DigestResponse::nonce_checked_externally`].
#[derive(Debug)]
pub enum NonceChecked {}

/// Who the client claims to be.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Username<'a> {
    /// A plain username, from `username` or decoded from `username*`.
    Plain(&'a str),

    /// The userhash sent with `userhash=true` ([RFC 7616 section
    /// 3.4.4](https://datatracker.ietf.org/doc/html/rfc7616#section-3.4.4));
    /// see [`super::DigestServer::hash_username`].
    Hashed(&'a str),
}

/// A parsed `Digest` `Authorization` or `Proxy-Authorization` header.
///
/// `S` is [`Unchecked`] after [`DigestResponse::parse`] and [`NonceChecked`]
/// once the nonce has been checked; only the latter can be verified.
#[derive(Debug)]
pub struct DigestResponse<'i, S = Unchecked> {
    username: Cow<'i, str>,
    userhash: bool,
    realm: Cow<'i, str>,
    uri: Cow<'i, str>,
    nonce: Cow<'i, str>,
    cnonce: Cow<'i, str>,
    opaque: Option<Cow<'i, str>>,
    response: &'i str,
    nc: u32,
    nc_hex: Cow<'i, str>,
    algorithm: Algorithm,
    session: bool,
    qop: Qop,
    qop_str: Cow<'i, str>,
    stale: bool,
    state: PhantomData<S>,
}

impl<'i> DigestResponse<'i, Unchecked> {
    /// Parses a header value. This checks syntax only; see
    /// [`super::DigestServer::check_nonce`] and [`super::DigestServer::verify`].
    ///
    /// Unknown parameters are ignored; `algorithm`, `qop` and `nc` may be
    /// quoted.
    ///
    /// Non-ASCII usernames must use `username*`
    /// ([RFC 8187](https://datatracker.ietf.org/doc/html/rfc8187)).
    pub fn parse(header_value: &'i str) -> Result<Self, ServerError> {
        use ServerError::Malformed;
        let c = parse_scheme(header_value, "Digest")?;
        if c.token68.is_some() {
            return Err(Malformed("expected auth-params"));
        }
        let [username, username_ext, realm, uri, nonce, cnonce, nc, qop, response, opaque, algorithm, userhash] =
            crate::find_params(
                &c.params,
                [
                    "username",
                    "username*",
                    "realm",
                    "uri",
                    "nonce",
                    "cnonce",
                    "nc",
                    "qop",
                    "response",
                    "opaque",
                    "algorithm",
                    "userhash",
                ],
            )
            .map_err(|_| Malformed("duplicate parameter"))?;

        let (algorithm, session) = match algorithm {
            None => (Algorithm::Md5, false),
            Some(v) => {
                Algorithm::parse(&v.to_unescaped()).map_err(|_| Malformed("unknown algorithm"))?
            }
        };
        let userhash = match userhash.map(|v| v.to_unescaped()) {
            None => false,
            Some(s) if s.eq_ignore_ascii_case("true") => true,
            Some(s) if s.eq_ignore_ascii_case("false") => false,
            Some(_) => return Err(Malformed("invalid userhash")),
        };
        let username = match (username, username_ext) {
            (Some(u), None) => u.to_unescaped(),
            (None, Some(u)) => {
                if userhash {
                    return Err(Malformed("username* with userhash=true"));
                }
                Cow::Owned(
                    crate::parser::decode_ext_value(&u.to_unescaped())
                        .ok_or(Malformed("invalid username*"))?,
                )
            }
            (Some(_), Some(_)) => return Err(Malformed("both username and username*")),
            (None, None) => return Err(Malformed("missing username")),
        };
        let username = if userhash {
            if !is_hex(&username, algorithm.hex_len()) {
                return Err(Malformed("userhash username is not a hex digest"));
            }
            Cow::Owned(username.to_ascii_lowercase())
        } else {
            username
        };
        let nc_hex = nc.ok_or(Malformed("missing nc"))?.to_unescaped();
        if !is_hex(&nc_hex, 8) {
            return Err(Malformed("nc must be 8 hex digits"));
        }
        let nc = u32::from_str_radix(&nc_hex, 16).expect("8 hex digits");
        let qop_str = qop.ok_or(Malformed("missing qop"))?.to_unescaped();
        let qop = Qop::parse(&qop_str).ok_or(Malformed("unknown qop"))?;
        let response = response.ok_or(Malformed("missing response"))?;
        if response.escapes != 0 || !is_hex(response.escaped, algorithm.hex_len()) {
            return Err(Malformed(
                "response is not a hex digest of the algorithm's length",
            ));
        }
        Ok(DigestResponse {
            username,
            userhash,
            realm: realm.ok_or(Malformed("missing realm"))?.to_unescaped(),
            uri: uri.ok_or(Malformed("missing uri"))?.to_unescaped(),
            nonce: nonce.ok_or(Malformed("missing nonce"))?.to_unescaped(),
            cnonce: cnonce.ok_or(Malformed("missing cnonce"))?.to_unescaped(),
            opaque: opaque.map(|v| v.to_unescaped()),
            response: response.escaped,
            nc,
            nc_hex,
            algorithm,
            session,
            qop,
            qop_str,
            stale: false,
            state: PhantomData,
        })
    }

    /// Declares that the caller checked the nonce itself, e.g. against a
    /// store tracking the highest `nc` per `(nonce, cnonce)` for replay
    /// protection ([RFC 7616 section 5.5](https://datatracker.ietf.org/doc/html/rfc7616#section-5.5)).
    pub fn nonce_checked_externally(self) -> DigestResponse<'i, NonceChecked> {
        self.into_checked(false)
    }

    pub(crate) fn into_checked(self, stale: bool) -> DigestResponse<'i, NonceChecked> {
        DigestResponse {
            username: self.username,
            userhash: self.userhash,
            realm: self.realm,
            uri: self.uri,
            nonce: self.nonce,
            cnonce: self.cnonce,
            opaque: self.opaque,
            response: self.response,
            nc: self.nc,
            nc_hex: self.nc_hex,
            algorithm: self.algorithm,
            session: self.session,
            qop: self.qop,
            qop_str: self.qop_str,
            stale,
            state: PhantomData,
        }
    }
}

impl<'i, S> DigestResponse<'i, S> {
    /// Returns who the client claims to be.
    pub fn username(&self) -> Username<'_> {
        if self.userhash {
            Username::Hashed(&self.username)
        } else {
            Username::Plain(&self.username)
        }
    }

    /// Returns the unescaped `realm`.
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Returns the unescaped `uri`.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Returns the unescaped `nonce`.
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Returns the unescaped `cnonce`.
    pub fn cnonce(&self) -> &str {
        &self.cnonce
    }

    /// Returns the unescaped `opaque`, if present.
    pub fn opaque(&self) -> Option<&str> {
        self.opaque.as_deref()
    }

    /// Returns the nonce count.
    pub fn nc(&self) -> u32 {
        self.nc
    }

    /// Returns the nonce count exactly as sent (8 hex digits).
    pub(crate) fn nc_hex(&self) -> &str {
        &self.nc_hex
    }

    /// Returns the algorithm (`MD5` if absent).
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns true for a `-sess` algorithm.
    pub fn session(&self) -> bool {
        self.session
    }

    /// Returns the quality of protection.
    pub fn qop(&self) -> Qop {
        self.qop
    }

    /// Returns `qop` exactly as sent.
    pub(crate) fn qop_str(&self) -> &str {
        &self.qop_str
    }

    /// Returns true if `username` is a userhash.
    pub(crate) fn userhash(&self) -> bool {
        self.userhash
    }

    pub(crate) fn response_hex(&self) -> &str {
        self.response
    }
}

impl<'i> DigestResponse<'i, NonceChecked> {
    /// Returns true if the nonce is authentic but expired.
    pub fn stale(&self) -> bool {
        self.stale
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::tests::RFC2617;
    use super::*;

    #[test]
    fn parses_rfc2617() {
        let r = DigestResponse::parse(RFC2617).unwrap();
        assert_eq!(r.username(), Username::Plain("Mufasa"));
        assert_eq!(r.realm(), "testrealm@host.com");
        assert_eq!(r.nonce(), "dcd98b7102dd2f0e8b11d0f600bfb0c093");
        assert_eq!(r.uri(), "/dir/index.html");
        assert_eq!(r.qop(), Qop::Auth);
        assert_eq!(r.qop_str(), "auth");
        assert_eq!((r.nc(), r.nc_hex()), (1, "00000001"));
        assert_eq!(r.cnonce(), "0a4f113b");
        assert_eq!(r.opaque(), Some("5ccc069c403ebaf9f0171e9517f40e41"));
        assert_eq!(
            (r.algorithm(), r.session(), r.userhash()),
            (Algorithm::Md5, false, false)
        );
        assert_eq!(r.response_hex(), "6629fae49393a05397450978507c4ef1");
    }

    #[test]
    fn username_star() {
        let utf8 = RFC2617.replace(
            "username=\"Mufasa\"",
            "username*=UTF-8''J%C3%A4s%C3%B8n%20Doe",
        );
        assert_eq!(
            DigestResponse::parse(&utf8).unwrap().username(),
            Username::Plain("J\u{e4}s\u{f8}n Doe")
        );
        let latin1 = RFC2617.replace(
            "username=\"Mufasa\"",
            "username*=iso-8859-1'en'J%E4s%F8n%20Doe",
        );
        assert_eq!(
            DigestResponse::parse(&latin1).unwrap().username(),
            Username::Plain("J\u{e4}s\u{f8}n Doe")
        );
    }

    #[test]
    fn lenient_forms() {
        let s = format!(
            "  {}  ",
            RFC2617
                .replace("username=", "USERNAME=")
                .replace("qop=auth", "qop=\"auth\"")
                .replace("nc=00000001", "nc=\"0000000A\"")
                .replace("opaque=", "algorithm=md5, foo=bar, opaque=")
        );
        let r = DigestResponse::parse(&s).unwrap();
        assert_eq!((r.nc(), r.nc_hex()), (10, "0000000A"));
        assert_eq!(r.algorithm(), Algorithm::Md5);
        assert_eq!(r.qop(), Qop::Auth);
        // A userhash username is lowercased.
        let s = RFC2617.replace(
            "username=\"Mufasa\"",
            "username=\"ABCDEF0123456789ABCDEF0123456789\", userhash=true",
        );
        assert_eq!(
            DigestResponse::parse(&s).unwrap().username(),
            Username::Hashed("abcdef0123456789abcdef0123456789")
        );
    }

    #[test]
    fn errors() {
        use ServerError::{Malformed, WrongScheme};
        let r = |from: &str, to: &str| RFC2617.replace(from, to);
        let cases: Vec<(String, ServerError)> = vec![
            ("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==".into(), WrongScheme),
            ("Digest abc".into(), Malformed("expected auth-params")),
            (r("qop=auth, ", ""), Malformed("missing qop")),
            (
                r("nc=00000001", "nc=1"),
                Malformed("nc must be 8 hex digits"),
            ),
            (r("qop=auth", "qop=auth-conf"), Malformed("unknown qop")),
            (
                r(
                    "response=\"6629fae49393a05397450978507c4ef1\"",
                    "response=\"6629\"",
                ),
                Malformed("response is not a hex digest of the algorithm's length"),
            ),
            (
                r("opaque=", "algorithm=SHA-1, opaque="),
                Malformed("unknown algorithm"),
            ),
            (
                r("username=\"Mufasa\"", "username*=KOI8-R''abc"),
                Malformed("invalid username*"),
            ),
            (
                r("username=\"Mufasa\"", "username*=UTF-8''a%2"),
                Malformed("invalid username*"),
            ),
            (
                r(
                    "username=\"Mufasa\"",
                    "username*=UTF-8''Mufasa, userhash=true",
                ),
                Malformed("username* with userhash=true"),
            ),
            (
                r("username=\"Mufasa\"", "username=\"Mufasa\", userhash=true"),
                Malformed("userhash username is not a hex digest"),
            ),
            (
                r("uri=", "uri=\"/a\", URI="),
                Malformed("duplicate parameter"),
            ),
            (
                r("username=\"Mufasa\"", "username=\"Mufas\u{e4}\""),
                Malformed("invalid credentials syntax"),
            ),
            (
                r("username=\"Mufasa\"", "username=\"Muf\r\nasa\""),
                Malformed("invalid credentials syntax"),
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(
                DigestResponse::parse(&input).unwrap_err(),
                expected,
                "{:?}",
                input
            );
        }
    }
}
