// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Types shared by the server-side [`crate::basic::BasicServer`] and
//! [`crate::digest::DigestServer`].

/// A challenge, ready to send as a `WWW-Authenticate` (401) or
/// `Proxy-Authenticate` (407) value.
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

#[cfg(feature = "http")]
impl From<Challenge> for http::HeaderValue {
    fn from(c: Challenge) -> Self {
        use std::convert::TryFrom as _;
        http::HeaderValue::try_from(c.0).expect("Challenge is always a valid header value")
    }
}

#[cfg(feature = "http10")]
impl From<Challenge> for http10::HeaderValue {
    fn from(c: Challenge) -> Self {
        use std::convert::TryFrom as _;
        http10::HeaderValue::try_from(c.0).expect("Challenge is always a valid header value")
    }
}

/// Why a server rejected credentials, or why a server couldn't be configured.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ServerError {
    /// The credentials use a different scheme.
    WrongScheme,

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

    /// The supplied secret doesn't fit the response's algorithm.
    SecretMismatch,

    /// Wrong username or password.
    BadCredentials,

    /// A server was configured with an invalid value.
    InvalidConfig(&'static str),
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
            ServerError::WrongScheme
            | ServerError::BadNonce
            | ServerError::Stale
            | ServerError::WrongRealm
            | ServerError::UnofferedAlgorithm
            | ServerError::UnofferedQop
            | ServerError::WrongOpaque
            | ServerError::UnofferedUserhash
            | ServerError::SecretMismatch
            | ServerError::BadCredentials => 401,
            ServerError::BodyRequired | ServerError::InvalidConfig(_) => 500,
        }
    }
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::WrongScheme => f.write_str("credentials use a different scheme"),
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
            ServerError::InvalidConfig(why) => write!(f, "invalid server configuration: {}", why),
        }
    }
}

impl std::error::Error for ServerError {}

/// Compares in constant time (for inputs of equal length).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq as _;
    bool::from(a.ct_eq(b))
}

/// Parses a scheme's credentials and checks the scheme name.
pub(crate) fn parse_scheme<'i>(
    header: &'i str,
    scheme: &str,
) -> Result<crate::ChallengeRef<'i>, ServerError> {
    use crate::parse_credentials;
    let c = parse_credentials(header)
        .map_err(|_| ServerError::Malformed("invalid credentials syntax"))?;
    if !c.scheme.eq_ignore_ascii_case(scheme) {
        return Err(ServerError::WrongScheme);
    }
    Ok(c)
}

/// Validates a realm value.
pub(crate) fn check_realm(realm: &str) -> Result<(), ServerError> {
    if crate::render::is_quotable(realm) {
        Ok(())
    } else {
        Err(ServerError::InvalidConfig("realm must be quotable"))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "http")]
    #[test]
    fn into_http_header_value() {
        use crate::render::HeaderWriter;
        let mut w = HeaderWriter::new("Basic");
        w.quoted("realm", "a \"b\"");
        let v = http::HeaderValue::from(super::Challenge(w.finish()));
        assert_eq!(v.to_str().unwrap(), r#"Basic realm="a \"b\"""#);
    }
}
