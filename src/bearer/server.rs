// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Server side of the `Bearer` scheme, as in
//! [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750).

use crate::render::HeaderWriter;
use crate::server::{check_realm, Challenge, ConfigError, CredentialsSource, ServerError};
use crate::table::{char_classes, C_SCOPE_TOKEN};
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
    realm: Option<String>,
    scope: Option<String>,
    error: Option<ErrorCode>,
    error_description: Option<String>,
    error_uri: Option<String>,
    resource_metadata: Option<String>,
}

impl ChallengeBuilder {
    /// Starts building a challenge with no parameters.
    pub fn new() -> Self {
        Self {
            realm: None,
            scope: None,
            error: None,
            error_description: None,
            error_uri: None,
            resource_metadata: None,
        }
    }

    /// Sets the `realm`.
    pub fn realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = Some(realm.into());
        self
    }

    /// Sets the `scope`.
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Sets the `error`.
    pub fn error(mut self, error: ErrorCode) -> Self {
        self.error = Some(error);
        self
    }

    /// Sets the `error_description`.
    pub fn error_description(mut self, error_description: impl Into<String>) -> Self {
        self.error_description = Some(error_description.into());
        self
    }

    /// Sets the `error_uri`.
    pub fn error_uri(mut self, error_uri: impl Into<String>) -> Self {
        self.error_uri = Some(error_uri.into());
        self
    }

    /// Sets the `resource_metadata`.
    pub fn resource_metadata(mut self, resource_metadata: impl Into<String>) -> Self {
        self.resource_metadata = Some(resource_metadata.into());
        self
    }

    /// Returns the challenge, or [`ConfigError`] for an invalid value.
    pub fn build(self) -> Result<Challenge, ConfigError> {
        if let Some(realm) = &self.realm {
            check_realm(realm)?;
        }
        if let Some(scope) = &self.scope {
            if !valid_scope(scope) {
                return Err(ConfigError("scope must be space-separated scope-tokens"));
            }
        }
        let values = [
            self.error_description.as_deref(),
            self.error_uri.as_deref(),
            self.resource_metadata.as_deref(),
        ];
        for value in values.iter().filter_map(|v| *v) {
            if !crate::render::is_bearer_param(value) {
                return Err(ConfigError("must be printable ASCII without \" or \\"));
            }
        }

        let mut w = HeaderWriter::new("Bearer");
        if let Some(realm) = &self.realm {
            w.quoted("realm", realm);
        }
        if let Some(scope) = &self.scope {
            w.quoted("scope", scope);
        }
        if let Some(error) = &self.error {
            w.quoted("error", error.as_str());
        }
        if let Some(error_description) = &self.error_description {
            w.quoted("error_description", error_description);
        }
        if let Some(error_uri) = &self.error_uri {
            w.quoted("error_uri", error_uri);
        }
        if let Some(resource_metadata) = &self.resource_metadata {
            w.quoted("resource_metadata", resource_metadata);
        }
        Ok(Challenge(w.finish()))
    }
}

impl Default for ChallengeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn valid_scope(s: &str) -> bool {
    !s.is_empty()
        && s.split(' ').all(|part| {
            !part.is_empty() && part.bytes().all(|b| (char_classes(b) & C_SCOPE_TOKEN) != 0)
        })
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
