// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Server-side code shared by [`crate::basic::ChallengeBuilder`] and
//! [`crate::digest::Server`]. The public types are re-exported at the crate
//! root.

/// A challenge, ready to send as a `WWW-Authenticate` (401) or
/// `Proxy-Authenticate` (407) value.
///
/// A challenge that doesn't change between requests, such as
/// [`crate::basic::ChallengeBuilder`]'s, can be built once and kept. With the
/// `http10` feature, keeping it as an `http::HeaderValue` makes each use a
/// cheap reference-counted clone:
///
/// ```rust
/// # #[cfg(all(feature = "basic-scheme", feature = "http10"))] {
/// let challenge = http::HeaderValue::from(
///     http_auth::basic::ChallengeBuilder::new("WallyWorld").build()?,
/// );
/// let mut headers = http::HeaderMap::new();
/// headers.append(http::header::WWW_AUTHENTICATE, challenge.clone());
/// # }
/// # Ok::<(), http_auth::ConfigError>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Challenge(pub(crate) String);

impl Challenge {
    /// Returns the header value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(feature = "http10")]
#[cfg_attr(docsrs, doc(cfg(feature = "http10")))]
impl From<Challenge> for http::HeaderValue {
    fn from(c: Challenge) -> Self {
        use std::convert::TryFrom as _;
        http::HeaderValue::try_from(c.0).expect("Challenge is always a valid header value")
    }
}

/// Why a server rejected credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[allow(clippy::module_name_repetitions)] // used via the crate root.
pub enum ServerError {
    /// The credentials are syntactically invalid; the string says why.
    Malformed(&'static str),

    /// The nonce wasn't issued by this server: bad encoding or HMAC.
    BadNonce,

    /// The nonce expired.
    Stale,

    /// `realm` differs from this server's.
    WrongRealm,

    /// The algorithm (or its `-sess` variant) wasn't offered.
    UnofferedAlgorithm,

    /// The `qop` wasn't offered.
    UnofferedQop,

    /// `opaque` differs from the one this server sends.
    WrongOpaque,

    /// `userhash=true` but this server didn't offer it.
    UnofferedUserhash,

    /// `uri` doesn't match the request-target.
    UriMismatch,

    /// The response uses `qop=auth-int` but no body was supplied to verify.
    BodyRequired,

    /// The supplied [`crate::digest::Secret::Ha1`] is for a different
    /// algorithm than the response's: a caller bug.
    SecretMismatch,

    /// Wrong username or password, or an unknown user.
    BadCredentials,
}

impl ServerError {
    /// The HTTP status code to respond with:
    ///
    /// *   400: a malformed request or `uri` mismatch.
    /// *   401: an authentication failure (including [`ServerError::Stale`]).
    /// *   500: a caller or configuration bug.
    pub fn status(&self) -> u16 {
        match self {
            ServerError::Malformed(_) | ServerError::UriMismatch => 400,
            ServerError::BadNonce
            | ServerError::Stale
            | ServerError::WrongRealm
            | ServerError::UnofferedAlgorithm
            | ServerError::UnofferedQop
            | ServerError::WrongOpaque
            | ServerError::UnofferedUserhash
            | ServerError::BadCredentials => 401,
            ServerError::BodyRequired | ServerError::SecretMismatch => 500,
        }
    }

    /// Like [`ServerError::status`], as an `http::StatusCode`.
    #[cfg(feature = "http10")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http10")))]
    pub fn status_code(&self) -> http::StatusCode {
        http::StatusCode::from_u16(self.status()).expect("status() is a valid status code")
    }
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::Malformed(why) => write!(f, "malformed credentials: {}", why),
            ServerError::BadNonce => f.write_str("nonce was not issued by this server"),
            ServerError::Stale => f.write_str("nonce has expired"),
            ServerError::WrongRealm => f.write_str("realm does not match"),
            ServerError::UnofferedAlgorithm => f.write_str("algorithm was not offered"),
            ServerError::UnofferedQop => f.write_str("qop was not offered"),
            ServerError::WrongOpaque => f.write_str("opaque does not match"),
            ServerError::UnofferedUserhash => f.write_str("userhash was not offered"),
            ServerError::UriMismatch => f.write_str("uri does not match the request-target"),
            ServerError::BodyRequired => f.write_str("qop=auth-int requires the request body"),
            ServerError::SecretMismatch => {
                f.write_str("secret does not fit the response's algorithm")
            }
            ServerError::BadCredentials => f.write_str("wrong username or password"),
        }
    }
}

impl std::error::Error for ServerError {}

/// Maps a [`crate::parse_credentials`] failure to [`ServerError::Malformed`].
impl From<crate::parser::Error<'_>> for ServerError {
    fn from(_: crate::parser::Error<'_>) -> Self {
        ServerError::Malformed("invalid credentials syntax")
    }
}

/// An invalid value given when configuring a server or challenge, or an
/// invalid stored secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigError(pub(crate) &'static str);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid configuration: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

/// `Authorization` or `Proxy-Authorization` credentials to parse with
/// [`crate::basic::Credentials::parse`] or
/// [`crate::digest::CredentialsRef::parse`].
///
/// This trait is sealed; it's implemented for the following types:
///
/// *   `&str`: an unparsed header value. Use `.as_str()` to pass a `String`.
/// *   [`crate::CredentialsRef`]: credentials already parsed via
///     [`crate::parse_credentials`]. A server accepting more than one scheme
///     can parse once and try each:
///
///     ```rust
///     # #[cfg(all(feature = "basic-scheme", feature = "digest-scheme"))] {
///     use http_auth::{basic, digest};
///     let c = http_auth::parse_credentials("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")?;
///     if let Some(b) = basic::Credentials::parse(&c) {
///         assert_eq!(b?.username(), "Aladdin");
///     } else if let Some(d) = digest::CredentialsRef::parse(&c) {
///         // ...
///     #   unreachable!();
///     } else {
///         // Another scheme: respond 401 with challenges, as with no
///         // credentials at all.
///     }
///     # }
///     # Ok::<(), http_auth::ServerError>(())
///     ```
///
/// *   [`http::HeaderValue`] (with the `http10` feature): an unparsed header
///     value.
///
/// Callers don't need to import this trait to use the `parse` functions.
pub trait CredentialsSource<'i>: sealed::Sealed<'i> {}

pub(crate) mod sealed {
    use super::ServerError;
    use crate::AuthBodyRef;

    pub trait Sealed<'i> {
        /// Returns `None` if the credentials use a scheme other than
        /// `scheme`, or `f`'s result on their body.
        fn parse_scheme<R>(
            self,
            scheme: &str,
            f: impl FnOnce(&AuthBodyRef<'i>) -> Result<R, ServerError>,
        ) -> Option<Result<R, ServerError>>;
    }
}

impl<'i> CredentialsSource<'i> for &'i str {}
impl<'i> sealed::Sealed<'i> for &'i str {
    fn parse_scheme<R>(
        self,
        scheme: &str,
        f: impl FnOnce(&crate::AuthBodyRef<'i>) -> Result<R, ServerError>,
    ) -> Option<Result<R, ServerError>> {
        match crate::parse_credentials(self) {
            Ok(c) => (&c).parse_scheme(scheme, f),
            Err(e) => Some(Err(e.into())),
        }
    }
}

impl<'i> CredentialsSource<'i> for &crate::CredentialsRef<'i> {}
impl<'i> sealed::Sealed<'i> for &crate::CredentialsRef<'i> {
    fn parse_scheme<R>(
        self,
        scheme: &str,
        f: impl FnOnce(&crate::AuthBodyRef<'i>) -> Result<R, ServerError>,
    ) -> Option<Result<R, ServerError>> {
        self.scheme()
            .eq_ignore_ascii_case(scheme)
            .then(|| f(self.body()))
    }
}

#[cfg(feature = "http10")]
impl<'i> CredentialsSource<'i> for &'i http::HeaderValue {}
#[cfg(feature = "http10")]
impl<'i> sealed::Sealed<'i> for &'i http::HeaderValue {
    fn parse_scheme<R>(
        self,
        scheme: &str,
        f: impl FnOnce(&crate::AuthBodyRef<'i>) -> Result<R, ServerError>,
    ) -> Option<Result<R, ServerError>> {
        match self.to_str() {
            Ok(s) => s.parse_scheme(scheme, f),
            Err(_) => Some(Err(ServerError::Malformed("invalid credentials syntax"))),
        }
    }
}

/// Validates a realm value.
pub(crate) fn check_realm(realm: &str) -> Result<(), ConfigError> {
    if crate::render::is_quotable(realm) {
        Ok(())
    } else {
        Err(ConfigError("realm must be quotable"))
    }
}

#[cfg(test)]
mod tests {
    use super::ServerError;

    #[test]
    fn status() {
        assert_eq!(ServerError::Malformed("x").status(), 400);
        assert_eq!(ServerError::BadCredentials.status(), 401);
        assert_eq!(ServerError::Stale.status(), 401);
        assert_eq!(ServerError::SecretMismatch.status(), 500);
        assert_eq!(ServerError::BodyRequired.status(), 500);
    }

    #[cfg(feature = "http10")]
    #[test]
    fn status_code() {
        assert_eq!(
            ServerError::Stale.status_code(),
            http::StatusCode::UNAUTHORIZED
        );
    }

    #[cfg(feature = "http10")]
    #[test]
    fn into_http_header_value() {
        use crate::render::HeaderWriter;
        let mut w = HeaderWriter::new("Basic");
        w.quoted("realm", "a \"b\"");
        let v = http::HeaderValue::from(super::Challenge(w.finish()));
        assert_eq!(v.to_str().unwrap(), r#"Basic realm="a \"b\"""#);
    }
}
