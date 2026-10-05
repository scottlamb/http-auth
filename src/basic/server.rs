// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Server side of the `Basic` scheme, as in
//! [RFC 7617](https://datatracker.ietf.org/doc/html/rfc7617).

use base64::Engine as _;

use crate::render::HeaderWriter;
use crate::server::{check_realm, ct_eq, parse_scheme, Challenge, ServerError};

/// Issues `Basic` challenges.
///
/// ```rust
/// use http_auth::basic::{BasicCredentials, BasicServer};
/// let server = BasicServer::new("WallyWorld")?.charset_utf8(true);
/// assert_eq!(
///     server.challenge().as_str(),
///     r#"Basic realm="WallyWorld", charset="UTF-8""#,
/// );
/// let creds = BasicCredentials::parse("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==").unwrap();
/// assert_eq!(creds.username(), "Aladdin");
/// assert!(creds.verify_password("open sesame"));
/// # Ok::<(), http_auth::server::ServerError>(())
/// ```
///
/// `Basic` sends the password in cleartext; use TLS, and store password hashes
/// ([OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)).
#[derive(Clone, Debug)]
pub struct BasicServer {
    realm: Box<str>,
    charset_utf8: bool,
}

impl BasicServer {
    /// Creates a server for the given realm.
    ///
    /// Fails with [`ServerError::InvalidConfig`] if the realm isn't printable
    /// ASCII.
    pub fn new(realm: impl Into<String>) -> Result<Self, ServerError> {
        let realm = realm.into();
        check_realm(&realm)?;
        Ok(Self {
            realm: realm.into_boxed_str(),
            charset_utf8: false,
        })
    }

    /// Adds `charset="UTF-8"` to the challenge, telling clients to send
    /// UTF-8 in Unicode Normalization Form C ([RFC 7617 section
    /// 2.1](https://datatracker.ietf.org/doc/html/rfc7617#section-2.1)).
    pub fn charset_utf8(mut self, charset_utf8: bool) -> Self {
        self.charset_utf8 = charset_utf8;
        self
    }

    /// Returns the challenge.
    pub fn challenge(&self) -> Challenge {
        let mut w = HeaderWriter::new("Basic");
        w.quoted("realm", &self.realm);
        if self.charset_utf8 {
            w.quoted("charset", "UTF-8");
        }
        Challenge(w.finish())
    }
}

/// Credentials from a `Basic` `Authorization` or `Proxy-Authorization` header.
#[derive(Clone)]
pub struct BasicCredentials {
    user_pass: String,
    colon: usize,
}

impl BasicCredentials {
    /// Parses a header value as in [RFC 7617 section
    /// 2](https://datatracker.ietf.org/doc/html/rfc7617#section-2).
    ///
    /// *   Base64 decoding is strict: canonical padding, no embedded whitespace.
    /// *   `user-pass` is split at the first `:`; a missing colon is an error.
    /// *   Control characters are rejected.
    /// *   The decoded octets must be UTF-8.
    pub fn parse(header_value: &str) -> Result<Self, ServerError> {
        let c = parse_scheme(header_value, "Basic")?;
        let encoded = c
            .token68
            .ok_or(ServerError::Malformed("expected token68"))?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| ServerError::Malformed("invalid base64"))?;
        let user_pass =
            String::from_utf8(decoded).map_err(|_| ServerError::Malformed("not UTF-8"))?;
        if user_pass.bytes().any(|b| b < 0x20 || b == 0x7F) {
            return Err(ServerError::Malformed("control character"));
        }
        let colon = user_pass
            .find(':')
            .ok_or(ServerError::Malformed("missing colon"))?;
        Ok(Self { user_pass, colon })
    }

    /// Returns the user-id.
    pub fn username(&self) -> &str {
        &self.user_pass[..self.colon]
    }

    /// Returns the password.
    pub fn password(&self) -> &str {
        &self.user_pass[self.colon + 1..]
    }

    /// Compares the password to a plaintext `expected` value, in constant
    /// time for passwords of equal length.
    pub fn verify_password(&self, expected: &str) -> bool {
        ct_eq(self.password().as_bytes(), expected.as_bytes())
    }
}

impl std::fmt::Debug for BasicCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasicCredentials")
            .field("username", &self.username())
            .field("password", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7617_examples() {
        // RFC 7617 section 2.
        let c = BasicCredentials::parse("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==").unwrap();
        assert_eq!(c.username(), "Aladdin");
        assert_eq!(c.password(), "open sesame");
        assert!(c.verify_password("open sesame"));
        assert!(!c.verify_password("open sesame!"));
        // RFC 7617 section 2.1: UTF-8 user-pass "test:123£".
        let c = BasicCredentials::parse("Basic dGVzdDoxMjPCow==").unwrap();
        assert_eq!((c.username(), c.password()), ("test", "123\u{a3}"));
        // Surrounding OWS and lowercase scheme.
        let c = BasicCredentials::parse("  basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\t").unwrap();
        assert_eq!(c.username(), "Aladdin");
        // Text after the first colon is part of the password (base64 of "user:pa:ss").
        let c = BasicCredentials::parse("Basic dXNlcjpwYTpzcw==").unwrap();
        assert_eq!((c.username(), c.password()), ("user", "pa:ss"));
        // Empty user-id and password (base64 of ":").
        let c = BasicCredentials::parse("Basic Og==").unwrap();
        assert_eq!((c.username(), c.password()), ("", ""));
        // Debug redacts the password.
        let d = format!("{:?}", c);
        assert!(d.contains("user") && !d.contains("sesame"), "{}", d);
    }

    #[test]
    fn parse_errors() {
        use ServerError::{Malformed, WrongScheme};
        let cases: &[(&str, ServerError)] = &[
            ("Digest username=\"x\"", WrongScheme),
            (
                "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ",
                Malformed("invalid base64"),
            ), // missing padding
            ("Basic QWxh ZGRp", Malformed("invalid credentials syntax")),
            ("Basic", Malformed("expected token68")),
            ("Basic dXNlcg==", Malformed("missing colon")), // "user"
            ("Basic dXMKZXI6cHc=", Malformed("control character")), // "us\ner:pw"
            ("Basic /zpwdw==", Malformed("not UTF-8")),     // b"\xff:pw"
        ];
        for (input, expected) in cases {
            assert_eq!(
                BasicCredentials::parse(input).unwrap_err(),
                *expected,
                "{:?}",
                input
            );
        }
    }

    #[test]
    fn challenge() {
        let s = BasicServer::new("WallyWorld").unwrap();
        assert_eq!(s.challenge().as_str(), r#"Basic realm="WallyWorld""#);
        let s = BasicServer::new(r#"a "b""#).unwrap().charset_utf8(true);
        assert_eq!(
            s.challenge().as_str(),
            r#"Basic realm="a \"b\"", charset="UTF-8""#
        );
        assert!(matches!(
            BasicServer::new("caf\u{e9}"),
            Err(ServerError::InvalidConfig(_))
        ));
        assert!(matches!(
            BasicServer::new("a\nb"),
            Err(ServerError::InvalidConfig(_))
        ));
    }
}
