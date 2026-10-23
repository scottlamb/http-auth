// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `Bearer` authentication scheme, as in
//! [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750).

use std::convert::TryFrom;

use crate::{ChallengeRef, ClientError};

#[cfg(feature = "server")]
mod server;

#[cfg(feature = "server")]
#[cfg_attr(docsrs, doc(cfg(feature = "server")))]
pub use self::server::{ChallengeBuilder, Credentials, ErrorCode};

use crate::render;
use crate::table::{char_classes, C_SCOPE_TOKEN};
use crate::uri;

pub(crate) const REALM: usize = 0;
pub(crate) const SCOPE: usize = 1;
pub(crate) const ERROR: usize = 2;
pub(crate) const ERROR_DESCRIPTION: usize = 3;
pub(crate) const ERROR_URI: usize = 4;
pub(crate) const RESOURCE_METADATA: usize = 5;

/// Client for a `Bearer` challenge, as in
/// [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750).
#[derive(Clone, Debug)]
pub struct Client {
    params: Params,
}

impl Client {
    /// Returns the `realm`, if present.
    pub fn realm(&self) -> Option<&str> {
        self.params.get(REALM)
    }

    /// Returns the `scope`, if present.
    pub fn scope(&self) -> Option<&str> {
        self.params.get(SCOPE)
    }

    /// Returns the `error`, if present.
    pub fn error(&self) -> Option<&str> {
        self.params.get(ERROR)
    }

    /// Returns the `error_description`, if present.
    pub fn error_description(&self) -> Option<&str> {
        self.params.get(ERROR_DESCRIPTION)
    }

    /// Returns the `error_uri`, if present.
    pub fn error_uri(&self) -> Option<&str> {
        self.params.get(ERROR_URI)
    }

    /// Returns the `resource_metadata`, if present.
    pub fn resource_metadata(&self) -> Option<&str> {
        self.params.get(RESOURCE_METADATA)
    }

    /// Responds to the challenge with the supplied token.
    pub fn respond(&self, token: &str) -> Result<String, ClientError> {
        encode_credentials(token)
    }
}

impl TryFrom<&ChallengeRef<'_>> for Client {
    type Error = ClientError;

    fn try_from(value: &ChallengeRef<'_>) -> Result<Self, Self::Error> {
        if !value.scheme().eq_ignore_ascii_case("Bearer") {
            return Err(ClientError::new(format!(
                "bearer::Client doesn't support challenge scheme {:?}",
                value.scheme()
            )));
        }
        let raw = match value.body() {
            crate::AuthBodyRef::Params(p) => p,
            crate::AuthBodyRef::Token68(_) => return Err(ClientError::new("expected auth-params")),
        };
        let mut params = Params::new();
        for (name, val) in raw {
            let value = val.to_unescaped().into_owned();
            let idx = PARAMS
                .iter()
                .position(|(n, _, _)| n.eq_ignore_ascii_case(name));
            let Some(idx) = idx else {
                continue;
            };
            if params.0[idx].is_some() {
                return Err(ClientError::new("repeated auth-param"));
            }
            params.0[idx] = Some(value);
        }
        params.validate().map_err(ClientError::new)?;
        Ok(Client { params })
    }
}

/// Encodes the given token as a `Bearer` credential.
pub fn encode_credentials(token: &str) -> Result<String, ClientError> {
    if !crate::parser::is_b64token(token) {
        return Err(ClientError::new("token must be a b64token"));
    }
    Ok(format!("Bearer {}", token))
}

type Validator = fn(&str) -> bool;
type ParamSpec = (&'static str, Validator, &'static str);

const PARAMS: [ParamSpec; 6] = [
    ("realm", render::is_quotable, "realm must be quotable"),
    (
        "scope",
        valid_scope,
        "scope must be space-separated scope-tokens",
    ),
    ("error", valid_nqschar, "error must be printable ASCII"),
    (
        "error_description",
        valid_nqschar,
        "error_description must be printable ASCII",
    ),
    (
        "error_uri",
        valid_error_uri,
        "error_uri must be an absolute URI",
    ),
    (
        "resource_metadata",
        valid_resource_metadata,
        "resource_metadata must be an https URI with a host and no fragment",
    ),
];

#[derive(Clone, Debug)]
pub(crate) struct Params([Option<String>; 6]);

impl Params {
    pub(crate) fn new() -> Self {
        Self(std::array::from_fn(|_| None))
    }

    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.0.iter().all(|v| v.is_none()) {
            return Err("at least one auth-param is required");
        }
        for (i, value) in self.0.iter().enumerate() {
            if let Some(value) = value {
                if !(PARAMS[i].1)(value) {
                    return Err(PARAMS[i].2);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn get(&self, i: usize) -> Option<&str> {
        self.0[i].as_deref()
    }

    #[cfg(feature = "server")]
    pub(crate) fn fields(&self) -> [(&'static str, Option<&str>); 6] {
        let mut out = [("", None); 6];
        for (i, (name, _, _)) in PARAMS.iter().enumerate() {
            out[i] = (name, self.0[i].as_deref());
        }
        out
    }

    #[cfg(feature = "server")]
    pub(crate) fn set(&mut self, i: usize, value: String) {
        self.0[i] = Some(value);
    }
}

pub(crate) fn valid_scope(s: &str) -> bool {
    !s.is_empty()
        && s.split(' ').all(|part| {
            !part.is_empty() && part.bytes().all(|b| (char_classes(b) & C_SCOPE_TOKEN) != 0)
        })
}

pub(crate) fn valid_nqschar(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b == b' ' || (char_classes(b) & C_SCOPE_TOKEN) != 0)
}

pub(crate) fn valid_error_uri(s: &str) -> bool {
    uri::parse(s).is_some()
}

pub(crate) fn valid_resource_metadata(s: &str) -> bool {
    match uri::parse(s) {
        Some(u) => {
            u.scheme.eq_ignore_ascii_case("https")
                && u.host.map(|h| !h.is_empty()).unwrap_or(false)
                && u.fragment.is_none()
        }
        None => false,
    }
}
