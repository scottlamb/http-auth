// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Server side of the `Basic` scheme, as in
//! [RFC 7617](https://datatracker.ietf.org/doc/html/rfc7617).

use base64::Engine as _;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use crate::render::HeaderWriter;
use crate::server::{check_realm, Challenge, ConfigError, CredentialsSource, ServerError};
use crate::AuthBodyRef;

/// Builds a `Basic` challenge.
///
/// The challenge is the same for every request, so build it once and clone it
/// as needed; see [`Challenge`] for a cheaper-to-clone form.
///
/// ```rust
/// use http_auth::basic::{ChallengeBuilder, Credentials};
/// let challenge = ChallengeBuilder::new("WallyWorld").charset_utf8(true).build()?;
/// assert_eq!(
///     challenge.as_str(),
///     r#"Basic realm="WallyWorld", charset="UTF-8""#,
/// );
/// let creds = Credentials::parse("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==").unwrap().unwrap();
/// assert_eq!(creds.username(), "Aladdin");
/// assert!(creds.verify_password(Some("open sesame")));
/// # Ok::<(), http_auth::ConfigError>(())
/// ```
///
/// `Basic` sends the password in cleartext; use TLS, and store password hashes
/// ([OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)).
#[derive(Clone, Debug)]
pub struct ChallengeBuilder {
    realm: String,
    charset_utf8: bool,
}

impl ChallengeBuilder {
    /// Starts building a challenge for the given realm.
    pub fn new(realm: impl Into<String>) -> Self {
        Self {
            realm: realm.into(),
            charset_utf8: false,
        }
    }

    /// Adds `charset="UTF-8"` to the challenge, telling clients to send
    /// UTF-8 in Unicode Normalization Form C ([RFC 7617 section
    /// 2.1](https://datatracker.ietf.org/doc/html/rfc7617#section-2.1)).
    pub fn charset_utf8(mut self, charset_utf8: bool) -> Self {
        self.charset_utf8 = charset_utf8;
        self
    }

    /// Returns the challenge, or [`ConfigError`] if the realm isn't printable
    /// ASCII.
    pub fn build(self) -> Result<Challenge, ConfigError> {
        check_realm(&self.realm)?;
        let mut w = HeaderWriter::new("Basic");
        w.quoted("realm", &self.realm);
        if self.charset_utf8 {
            w.quoted("charset", "UTF-8");
        }
        Ok(Challenge(w.finish()))
    }
}

/// Credentials from a `Basic` `Authorization` or `Proxy-Authorization` header.
#[derive(Clone)]
pub struct Credentials {
    user_pass: String,
    colon: usize,
}

impl Credentials {
    /// Parses a header value as in [RFC 7617 section
    /// 2](https://datatracker.ietf.org/doc/html/rfc7617#section-2).
    ///
    /// *   Base64 decoding is strict: canonical padding, no embedded whitespace.
    /// *   `user-pass` is split at the first `:`; a missing colon is an error.
    /// *   Control characters are rejected.
    /// *   The decoded octets must be UTF-8.
    ///
    /// Returns `None` if `source` uses another scheme. See
    /// [`CredentialsSource`] for accepted sources, including how to accept
    /// more than one scheme.
    pub fn parse<'i, S: CredentialsSource<'i>>(source: S) -> Option<Result<Self, ServerError>> {
        source.parse_scheme("Basic", Self::from_body)
    }

    /// Parses the body of credentials already known to use `Basic`.
    fn from_body(body: &AuthBodyRef<'_>) -> Result<Self, ServerError> {
        let &AuthBodyRef::Token68(encoded) = body else {
            return Err(ServerError::Malformed("expected token68"));
        };
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

    /// Checks the password against the stored plaintext `expected` password.
    ///
    /// This is for servers that keep plaintext passwords, typically to also
    /// offer `Digest` with `digest::Secret::Password`. Otherwise, store
    /// slow password hashes
    /// ([OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html))
    /// and verify [`Credentials::password`] against them instead.
    ///
    /// Timing doesn't reveal the contents of `expected`, and reveals at most
    /// a coarse bound on its length. (Currently this compares SHA-256 hashes
    /// in constant time, so it reveals only whether `expected` is at least
    /// 56 bytes. The implementation may change.)
    ///
    /// Pass `None` for an unknown user: this returns `false` after the same
    /// work as for a wrong password, so response timing doesn't reveal
    /// whether the user exists (beyond any difference in the caller's own
    /// lookup).
    pub fn verify_password(&self, expected: Option<&str>) -> bool {
        let actual = Sha256::digest(self.password());
        let matches = actual.ct_eq(&Sha256::digest(expected.unwrap_or("")));
        bool::from(matches & subtle::Choice::from(u8::from(expected.is_some())))
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
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
        let c = Credentials::parse("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
            .unwrap()
            .unwrap();
        assert_eq!(c.username(), "Aladdin");
        assert_eq!(c.password(), "open sesame");
        assert!(c.verify_password(Some("open sesame")));
        assert!(!c.verify_password(Some("open sesame!")));
        assert!(!c.verify_password(None));
        // An unknown user fails even when the supplied password is empty.
        let c = Credentials::parse("Basic QWxhZGRpbjo=").unwrap().unwrap();
        assert_eq!(c.password(), "");
        assert!(c.verify_password(Some("")));
        assert!(!c.verify_password(None));
        // RFC 7617 section 2.1: UTF-8 user-pass "test:123£".
        let c = Credentials::parse("Basic dGVzdDoxMjPCow==")
            .unwrap()
            .unwrap();
        assert_eq!((c.username(), c.password()), ("test", "123\u{a3}"));
        // Surrounding OWS and lowercase scheme.
        let c = Credentials::parse("  basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\t")
            .unwrap()
            .unwrap();
        assert_eq!(c.username(), "Aladdin");
        // Text after the first colon is part of the password (base64 of "user:pa:ss").
        let c = Credentials::parse("Basic dXNlcjpwYTpzcw==")
            .unwrap()
            .unwrap();
        assert_eq!((c.username(), c.password()), ("user", "pa:ss"));
        // Empty user-id and password (base64 of ":").
        let c = Credentials::parse("Basic Og==").unwrap().unwrap();
        assert_eq!((c.username(), c.password()), ("", ""));
        // Debug redacts the password.
        let d = format!("{:?}", c);
        assert!(d.contains("user") && !d.contains("sesame"), "{}", d);
    }

    #[test]
    fn parse_errors() {
        use ServerError::Malformed;
        assert!(Credentials::parse("Digest username=\"x\"").is_none());
        let cases: &[(&str, ServerError)] = &[
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
                Credentials::parse(*input).unwrap().unwrap_err(),
                *expected,
                "{:?}",
                input
            );
        }
    }

    #[test]
    fn challenge() {
        let c = ChallengeBuilder::new("WallyWorld").build().unwrap();
        assert_eq!(c.as_str(), r#"Basic realm="WallyWorld""#);
        let c = ChallengeBuilder::new(r#"a "b""#)
            .charset_utf8(true)
            .build()
            .unwrap();
        assert_eq!(c.as_str(), r#"Basic realm="a \"b\"", charset="UTF-8""#);
        for realm in ["caf\u{e9}", "a\nb"] {
            assert!(ChallengeBuilder::new(realm).build().is_err());
        }
    }
}
