// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Server side of the `Bearer` scheme, as in
//! [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750).

use crate::render::HeaderWriter;
use crate::server::{Challenge, ConfigError, CredentialsSource, ServerError};
use crate::AuthBodyRef;

/// An `error` value for a `Bearer` challenge, as in
/// [RFC 6750 section 3.1](https://datatracker.ietf.org/doc/html/rfc6750#section-3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    /// The request is missing a required parameter or is otherwise malformed.
    InvalidRequest,
    /// The access token is expired, revoked, or otherwise invalid.
    InvalidToken,
    /// The token doesn't grant the requested scope.
    InsufficientScope,
}

impl ErrorCode {
    /// The HTTP status code to respond with.
    pub fn status(&self) -> u16 {
        match self {
            ErrorCode::InvalidRequest => 400,
            ErrorCode::InvalidToken => 401,
            ErrorCode::InsufficientScope => 403,
        }
    }

    /// The wire form of this error code.
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::InvalidRequest => "invalid_request",
            ErrorCode::InvalidToken => "invalid_token",
            ErrorCode::InsufficientScope => "insufficient_scope",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Builds a `Bearer` challenge.
///
/// ```rust
/// use http_auth::bearer::{ChallengeBuilder, Credentials, ErrorCode};
/// let challenge = ChallengeBuilder::new().realm("example").build()?;
/// assert_eq!(challenge.as_str(), r#"Bearer realm="example""#);
/// let creds = Credentials::parse("Bearer mF_9.B5f-4.1JqM").unwrap().unwrap();
/// assert_eq!(creds.token(), "mF_9.B5f-4.1JqM");
/// # Ok::<(), http_auth::ConfigError>(())
/// ```
#[derive(Clone, Debug)]
pub struct ChallengeBuilder {
    params: crate::bearer::Params,
}

impl ChallengeBuilder {
    /// Starts building a challenge with no parameters.
    pub fn new() -> Self {
        Self {
            params: crate::bearer::Params::new(),
        }
    }

    /// Sets the `realm`.
    pub fn realm(mut self, realm: impl Into<String>) -> Self {
        self.params.set(crate::bearer::REALM, realm.into());
        self
    }

    /// Sets the `scope`.
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.params.set(crate::bearer::SCOPE, scope.into());
        self
    }

    /// Sets the `error`.
    pub fn error(mut self, error: ErrorCode) -> Self {
        self.params
            .set(crate::bearer::ERROR, error.as_str().to_owned());
        self
    }

    /// Sets the `error_description`.
    pub fn error_description(mut self, error_description: impl Into<String>) -> Self {
        self.params
            .set(crate::bearer::ERROR_DESCRIPTION, error_description.into());
        self
    }

    /// Sets the `error_uri`.
    pub fn error_uri(mut self, error_uri: impl Into<String>) -> Self {
        self.params.set(crate::bearer::ERROR_URI, error_uri.into());
        self
    }

    /// Sets the `resource_metadata`.
    pub fn resource_metadata(mut self, resource_metadata: impl Into<String>) -> Self {
        self.params
            .set(crate::bearer::RESOURCE_METADATA, resource_metadata.into());
        self
    }

    /// Returns the challenge, or [`ConfigError`] for an invalid value.
    pub fn build(self) -> Result<Challenge, ConfigError> {
        self.params.validate().map_err(ConfigError)?;
        let mut w = HeaderWriter::new("Bearer");
        for (name, value) in self.params.fields() {
            if let Some(value) = value {
                w.quoted(name, value);
            }
        }
        Ok(Challenge(w.finish()))
    }
}

impl Default for ChallengeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Credentials from a `Bearer` `Authorization` or `Proxy-Authorization` header.
#[derive(Clone)]
pub struct Credentials {
    token: String,
}

impl Credentials {
    /// Parses a header value as in [RFC 6750 section
    /// 2.1](https://datatracker.ietf.org/doc/html/rfc6750#section-2.1).
    ///
    /// Returns `None` if `source` uses another scheme. See
    /// [`CredentialsSource`] for accepted sources.
    pub fn parse<'i, S: CredentialsSource<'i>>(source: S) -> Option<Result<Self, ServerError>> {
        source.parse_scheme("Bearer", Self::from_body)
    }

    fn from_body(body: &AuthBodyRef<'_>) -> Result<Self, ServerError> {
        let &AuthBodyRef::Token68(token) = body else {
            return Err(ServerError::Malformed("expected token68"));
        };
        Ok(Self {
            token: token.to_owned(),
        })
    }

    /// Returns the access token.
    pub fn token(&self) -> &str {
        &self.token
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("token", &"<redacted>")
            .finish()
    }
}
