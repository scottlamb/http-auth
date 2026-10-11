// Copyright (C) 2021 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HTTP authentication, for clients and servers.
//!
//! As described in the following documents and specifications:
//!
//! *   [MDN documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication).
//! *   [RFC 7235](https://datatracker.ietf.org/doc/html/rfc7235):
//!     Hypertext Transfer Protocol (HTTP/1.1): Authentication.
//! *   [RFC 7617](https://datatracker.ietf.org/doc/html/rfc7617):
//!     The 'Basic' HTTP Authentication Scheme
//! *   [RFC 7616](https://datatracker.ietf.org/doc/html/rfc7616):
//!     HTTP Digest Access Authentication
//!
//! This framework is primarily used with HTTP, as suggested by the name. It is
//! also used by some other protocols such as RTSP.
//!
//! ## Cargo Features
//!
//! | feature         | default? | description                                                  |
//! |-----------------|----------|--------------------------------------------------------------|
//! | `basic-scheme`  | yes      | support for the `Basic` auth scheme                          |
//! | `digest-scheme` | yes      | support for the `Digest` auth scheme                         |
//! | `server`        | no       | server side: issue challenges and verify credentials (see [`server`]) |
//! | `http`          | no       | convenient conversion from `http` crate types, version 0.2 |
//! | `http10`        | no       | convenient conversion from `http` crate types, version 1.0 |
//!
//! ## Example
//!
//! In most cases, callers only need to use [`PasswordClient`] and
//! [`PasswordParams`] to handle `Basic` and `Digest` authentication schemes.
//!
#![cfg_attr(
    any(feature = "http", feature = "http10"),
    doc = r##"
```rust
use std::convert::TryFrom as _;
use http_auth::PasswordClient;

let WWW_AUTHENTICATE_VAL = "UnsupportedSchemeA, Basic realm=\"foo\", UnsupportedSchemeB";
let mut pw_client = http_auth::PasswordClient::try_from(WWW_AUTHENTICATE_VAL).unwrap();
assert!(matches!(pw_client, http_auth::PasswordClient::Basic(_)));
let response = pw_client.respond(&http_auth::PasswordParams {
    username: "Aladdin",
    password: "open sesame",
    uri: "/",
    method: "GET",
    body: Some(&[]),
}).unwrap();
assert_eq!(response, "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
```
"##
)]
//!
//! The `http` or `http10` features allow parsing all `WWW-Authenticate` headers within a
//! [`http::HeaderMap`] in one call.
//!
#![cfg_attr(
    any(feature = "http", feature = "http10"),
    doc = r##"
```rust
# use std::convert::TryFrom as _;
use http::header::{HeaderMap, WWW_AUTHENTICATE};
# use http_auth::PasswordClient;

let mut headers = HeaderMap::new();
headers.append(WWW_AUTHENTICATE, "UnsupportedSchemeA".parse().unwrap());
headers.append(WWW_AUTHENTICATE, "Basic realm=\"foo\", UnsupportedSchemeB".parse().unwrap());

let mut pw_client = PasswordClient::try_from(headers.get_all(WWW_AUTHENTICATE)).unwrap();
assert!(matches!(pw_client, http_auth::PasswordClient::Basic(_)));
```
"##
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
// e.g. `basic::Client`, not `basic::BasicClient`.
#![warn(clippy::module_name_repetitions)]

use std::convert::TryFrom;

pub mod parser;

#[cfg(feature = "basic-scheme")]
#[cfg_attr(docsrs, doc(cfg(feature = "basic-scheme")))]
pub mod basic;

#[cfg(feature = "digest-scheme")]
#[cfg_attr(docsrs, doc(cfg(feature = "digest-scheme")))]
pub mod digest;

mod table;

#[cfg(all(
    feature = "server",
    any(feature = "basic-scheme", feature = "digest-scheme")
))]
#[cfg_attr(
    docsrs,
    doc(cfg(all(
        feature = "server",
        any(feature = "basic-scheme", feature = "digest-scheme")
    )))
)]
pub mod server;

#[cfg(any(
    feature = "digest-scheme",
    all(feature = "server", feature = "basic-scheme")
))]
mod render;

pub use parser::{parse_credentials, ChallengeParser};

use crate::table::{char_classes, C_ESCAPABLE, C_OWS, C_QDTEXT, C_TCHAR};

/// Returns true if `s` is a valid token (RFC 9110 section 5.6.2).
pub(crate) fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| (char_classes(b) & C_TCHAR) != 0)
}

/// Parsed challenge (scheme and body) using references to the original header value.
/// Produced by [`crate::parser::ChallengeParser`].
///
/// This is not directly useful for responding to a challenge; it's an
/// intermediary for constructing a client that knows how to respond to a specific
/// challenge scheme. In most cases, callers should construct a [`PasswordClient`]
/// without directly using `ChallengeRef`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeRef<'i> {
    /// The scheme name, which should be compared case-insensitively.
    pub scheme: &'i str,

    /// The `token68` or auth-params.
    pub body: AuthBodyRef<'i>,
}

impl<'i> ChallengeRef<'i> {
    pub fn new(scheme: &'i str) -> Self {
        ChallengeRef {
            scheme,
            body: AuthBodyRef::Params(Vec::new()),
        }
    }
}

/// Renders as a header value, quoting `realm` and any value that isn't a
/// token. Round-trips values produced by [`ChallengeParser`].
impl std::fmt::Display for ChallengeRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.scheme)?;
        let params = match &self.body {
            AuthBodyRef::Token68(t) => return write!(f, " {}", t),
            AuthBodyRef::Params(p) => p,
        };
        for (i, (k, v)) in params.iter().enumerate() {
            f.write_str(if i == 0 { " " } else { ", " })?;
            f.write_str(k)?;
            f.write_str("=")?;
            // RFC 9110 section 11.5: a sender MUST only generate quoted-string for realm.
            let is_token =
                !k.eq_ignore_ascii_case("realm") && v.escapes == 0 && is_token(v.escaped);
            if is_token {
                f.write_str(v.escaped)?;
            } else {
                write!(f, "\"{}\"", v.escaped)?;
            }
        }
        Ok(())
    }
}

/// Parsed `Authorization` or `Proxy-Authorization` credentials using references
/// to the original header value. Produced by [`parse_credentials`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialsRef<'i> {
    /// The scheme name, which should be compared case-insensitively.
    pub scheme: &'i str,

    /// The `token68` or auth-params.
    pub body: AuthBodyRef<'i>,
}

/// Body of a [`ChallengeRef`] or [`CredentialsRef`].
#[derive(Clone, Eq, PartialEq)]
pub enum AuthBodyRef<'i> {
    /// A `token68` ([RFC 9110 section 11.2](https://datatracker.ietf.org/doc/html/rfc9110#section-11.2)).
    Token68(&'i str),

    /// Zero or more parameters, as a `Vec` of key-value pairs rather than a map.
    Params(Vec<ChallengeParamRef<'i>>),
}

impl<'i> AuthBodyRef<'i> {
    /// Returns the parameters, or `None` for a `token68` body.
    #[cfg(any(feature = "basic-scheme", feature = "digest-scheme"))]
    pub(crate) fn params(&self) -> Option<&[ChallengeParamRef<'i>]> {
        match self {
            AuthBodyRef::Token68(_) => None,
            AuthBodyRef::Params(p) => Some(p),
        }
    }
}

impl std::fmt::Debug for AuthBodyRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthBodyRef::Token68(t) => f.debug_tuple("Token68").field(t).finish(),
            AuthBodyRef::Params(p) => f.debug_tuple("Params").field(&ParamsPrinter(p)).finish(),
        }
    }
}

type ChallengeParamRef<'i> = (&'i str, ParamValueRef<'i>);

struct ParamsPrinter<'i>(&'i [ChallengeParamRef<'i>]);

impl std::fmt::Debug for ParamsPrinter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map().entries(self.0.iter().copied()).finish()
    }
}

/// Builds a [`PasswordClient`] from the supplied challenges; create via
/// [`PasswordClient::builder`].
///
/// Often you can just use [`PasswordClient`]'s [`TryFrom`] implementations
/// to convert from a parsed challenge ([`crate::ChallengeRef`]) or
/// unparsed challenges (`str`, [`http::header::HeaderValue`], or
/// [`http::header::GetAll`]).
///
/// The builder allows more flexibility. For example, if you are using a HTTP
/// library which is not based on a `http` crate, you might need to create
/// a `PasswordClient` from an iterator over multiple `WWW-Authenticate`
/// headers. You can feed each to [`PasswordClientBuilder::with`].
///
/// Prefers `Digest` over `Basic`, consistent with the [RFC 7235 section
/// 2.1](https://datatracker.ietf.org/doc/html/rfc7235#section-2.1) advice
/// for a user-agent to pick the most secure auth-scheme it understands.
///
/// When there are multiple `Digest` challenges, currently uses the first,
/// consistent with the [RFC 7616 section
/// 3.7](https://datatracker.ietf.org/doc/html/rfc7616#section-3.7)
/// advice to "use the first challenge it supports, unless a local policy
/// dictates otherwise". In the future, it may prioritize by algorithm.
///
/// Ignores parse errors as long as there's at least one parseable, supported
/// challenge.
///
/// ## Example
///
#[cfg_attr(
    feature = "digest-scheme",
    doc = r##"
```rust
use http_auth::PasswordClient;
let client = PasswordClient::builder()
    .with("UnsupportedSchemeA, Basic realm=\"foo\", UnsupportedSchemeB")
    .with("Digest \
                 realm=\"http-auth@example.org\", \
                 qop=\"auth, auth-int\", \
                 algorithm=MD5, \
                 nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", \
                 opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"")
    .build()
    .unwrap();
assert!(matches!(client, PasswordClient::Digest(_)));
```
"##
)]
#[derive(Default)]
pub struct PasswordClientBuilder(
    /// The current result:
    /// *   `Some(Ok(_))` if there is a suitable client.
    /// *   `Some(Err(_))` if there is no suitable client and has been a parse error.
    /// *   `None` otherwise.
    Option<Result<PasswordClient, String>>,
);

/// Challenge(s) which can be fed to [`PasswordClientBuilder::with`].
///
/// This trait is sealed; it's implemented for the following types:
///
/// *   [`ChallengeRef`]: a single parsed challenge.
/// *   `&str`: an unparsed challenge list. Use `.as_str()` to pass a
///     `String`.
/// *   [`http::HeaderValue`] (with the `http` or `http10` feature): an
///     unparsed challenge list.
/// *   [`http::header::GetAll`] (with the `http` or `http10` feature): all
///     the challenge lists from the `WWW-Authenticate` headers of a response.
///
/// Callers don't need to import this trait to use
/// [`PasswordClientBuilder::with`].
pub trait ChallengeSource: sealed::Sealed {}

mod sealed {
    pub trait Sealed {
        fn add_to(self, builder: &mut super::PasswordClientBuilder);
    }
}

impl ChallengeSource for &ChallengeRef<'_> {}
impl sealed::Sealed for &ChallengeRef<'_> {
    fn add_to(self, builder: &mut PasswordClientBuilder) {
        if builder.complete() {
            return;
        }

        #[cfg(feature = "digest-scheme")]
        if self.scheme.eq_ignore_ascii_case("Digest") {
            match digest::Client::try_from(self) {
                Ok(c) => builder.0 = Some(Ok(PasswordClient::Digest(c))),
                Err(e) if builder.0.is_none() => builder.0 = Some(Err(e)),
                _ => {}
            }
            return;
        }

        #[cfg(feature = "basic-scheme")]
        if self.scheme.eq_ignore_ascii_case("Basic") && !matches!(builder.0, Some(Ok(_))) {
            match basic::Client::try_from(self) {
                Ok(c) => builder.0 = Some(Ok(PasswordClient::Basic(c))),
                Err(e) if builder.0.is_none() => builder.0 = Some(Err(e)),
                _ => {}
            }
            return;
        }

        if builder.0.is_none() {
            builder.0 = Some(Err(format!("Unsupported scheme {:?}", self.scheme)));
        }
    }
}

impl ChallengeSource for &str {}
impl sealed::Sealed for &str {
    fn add_to(self, builder: &mut PasswordClientBuilder) {
        let mut parser = ChallengeParser::new(self);
        while !builder.complete() {
            match parser.next() {
                Some(Ok(c)) => c.add_to(builder),
                Some(Err(e)) if builder.0.is_none() => builder.0 = Some(Err(e.to_string())),
                _ => break,
            }
        }
    }
}

macro_rules! impl_http_sources {
    ($feature:literal, $http:ident) => {
        #[cfg(feature = $feature)]
        #[cfg_attr(docsrs, doc(cfg(feature = $feature)))]
        impl ChallengeSource for &$http::HeaderValue {}

        #[cfg(feature = $feature)]
        impl sealed::Sealed for &$http::HeaderValue {
            fn add_to(self, builder: &mut PasswordClientBuilder) {
                if builder.complete() {
                    return;
                }
                match self.to_str() {
                    Ok(v) => v.add_to(builder),
                    Err(_) if builder.0.is_none() => {
                        builder.0 = Some(Err("non-ASCII header value".into()))
                    }
                    Err(_) => {}
                }
            }
        }

        #[cfg(feature = $feature)]
        #[cfg_attr(docsrs, doc(cfg(feature = $feature)))]
        impl ChallengeSource for $http::header::GetAll<'_, $http::HeaderValue> {}

        #[cfg(feature = $feature)]
        impl sealed::Sealed for $http::header::GetAll<'_, $http::HeaderValue> {
            fn add_to(self, builder: &mut PasswordClientBuilder) {
                for v in self {
                    if builder.complete() {
                        break;
                    }
                    v.add_to(builder);
                }
            }
        }
    };
}

impl_http_sources!("http", http);
impl_http_sources!("http10", http10);

impl PasswordClientBuilder {
    /// Considers the given challenge(s).
    ///
    /// Accepts a single parsed [`ChallengeRef`], an unparsed `&str`
    /// challenge list, or (with the `http` or `http10` feature) a
    /// [`http::HeaderValue`] or [`http::header::GetAll`]. See
    /// [`ChallengeSource`].
    #[cfg_attr(
        all(feature = "http10", feature = "basic-scheme"),
        doc = r##"

## Example

```rust
use http10::header::{HeaderMap, HeaderValue, WWW_AUTHENTICATE};
use http_auth::{ChallengeParser, PasswordClient};

let mut headers = HeaderMap::new();
headers.append(WWW_AUTHENTICATE, HeaderValue::from_static("UnsupportedSchemeA"));
let parsed = ChallengeParser::new("UnsupportedSchemeB").next().unwrap().unwrap();
let owned = String::from("UnsupportedSchemeD");
let client = PasswordClient::builder()
    .with(headers.get_all(WWW_AUTHENTICATE))
    .with(&HeaderValue::from_static("UnsupportedSchemeC"))
    .with(&parsed)
    .with(owned.as_str())
    .with("Basic realm=\"foo\"")
    .build()
    .unwrap();
assert!(matches!(client, PasswordClient::Basic(_)));
```
"##
    )]
    #[inline]
    pub fn with<S: ChallengeSource>(mut self, source: S) -> Self {
        source.add_to(&mut self);
        self
    }

    /// Returns true if no more challenges need to be examined.
    #[cfg(feature = "digest-scheme")]
    fn complete(&self) -> bool {
        matches!(self.0, Some(Ok(PasswordClient::Digest(_))))
    }

    /// Returns true if no more challenges need to be examined.
    #[cfg(not(feature = "digest-scheme"))]
    fn complete(&self) -> bool {
        matches!(self.0, Some(Ok(_)))
    }

    /// Returns a new [`PasswordClient`] or fails.
    pub fn build(self) -> Result<PasswordClient, String> {
        self.0.unwrap_or_else(|| Err("no challenges given".into()))
    }
}

/// Client for responding to a password challenge.
///
/// Typically created via [`TryFrom`] implementations for a parsed challenge
/// ([`crate::ChallengeRef`]) or unparsed challenges (`str`,
/// [`http::header::HeaderValue`], or [`http::header::GetAll`]). See full
/// example in the [crate-level documentation](crate).
///
/// For more complex scenarios, see [`PasswordClientBuilder`].
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PasswordClient {
    #[cfg(feature = "basic-scheme")]
    #[cfg_attr(docsrs, doc(cfg(feature = "basic-scheme")))]
    Basic(basic::Client),

    #[cfg(feature = "digest-scheme")]
    #[cfg_attr(docsrs, doc(cfg(feature = "digest-scheme")))]
    Digest(digest::Client),
}

/// Tries to create a `PasswordClient` from the single supplied challenge.
///
/// This is a convenience wrapper around [`PasswordClientBuilder`].
impl TryFrom<&ChallengeRef<'_>> for PasswordClient {
    type Error = String;

    fn try_from(value: &ChallengeRef<'_>) -> Result<Self, Self::Error> {
        #[cfg(feature = "basic-scheme")]
        if value.scheme.eq_ignore_ascii_case("Basic") {
            return Ok(PasswordClient::Basic(basic::Client::try_from(value)?));
        }
        #[cfg(feature = "digest-scheme")]
        if value.scheme.eq_ignore_ascii_case("Digest") {
            return Ok(PasswordClient::Digest(digest::Client::try_from(value)?));
        }

        Err(format!("unsupported challenge scheme {:?}", value.scheme))
    }
}

/// Tries to create a `PasswordClient` from the supplied `str` challenge list.
///
/// This is a convenience wrapper around [`PasswordClientBuilder`].
impl TryFrom<&str> for PasswordClient {
    type Error = String;

    #[inline]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        PasswordClient::builder().with(value).build()
    }
}

/// Tries to create a `PasswordClient` from the supplied `HeaderValue` challenge list.
///
/// This is a convenience wrapper around [`PasswordClientBuilder`].
#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
impl TryFrom<&http::HeaderValue> for PasswordClient {
    type Error = String;

    #[inline]
    fn try_from(value: &http::HeaderValue) -> Result<Self, Self::Error> {
        PasswordClient::builder().with(value).build()
    }
}

/// Tries to create a `PasswordClient` from the supplied `HeaderValue` challenge list.
///
/// This is a convenience wrapper around [`PasswordClientBuilder`].
#[cfg(feature = "http10")]
#[cfg_attr(docsrs, doc(cfg(feature = "http10")))]
impl TryFrom<&http10::HeaderValue> for PasswordClient {
    type Error = String;

    #[inline]
    fn try_from(value: &http10::HeaderValue) -> Result<Self, Self::Error> {
        PasswordClient::builder().with(value).build()
    }
}

/// Tries to create a `PasswordClient` from the supplied `http::header::GetAll` challenge lists.
///
/// This is a convenience wrapper around [`PasswordClientBuilder`].
#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
impl TryFrom<http::header::GetAll<'_, http::HeaderValue>> for PasswordClient {
    type Error = String;

    fn try_from(value: http::header::GetAll<'_, http::HeaderValue>) -> Result<Self, Self::Error> {
        PasswordClient::builder().with(value).build()
    }
}

/// Tries to create a `PasswordClient` from the supplied `http::header::GetAll` challenge lists.
///
/// This is a convenience wrapper around [`PasswordClientBuilder`].
#[cfg(feature = "http10")]
#[cfg_attr(docsrs, doc(cfg(feature = "http10")))]
impl TryFrom<http10::header::GetAll<'_, http10::HeaderValue>> for PasswordClient {
    type Error = String;

    fn try_from(
        value: http10::header::GetAll<'_, http10::HeaderValue>,
    ) -> Result<Self, Self::Error> {
        PasswordClient::builder().with(value).build()
    }
}

impl PasswordClient {
    /// Builds a new `PasswordClient`.
    ///
    /// See example at [`PasswordClientBuilder`].
    pub fn builder() -> PasswordClientBuilder {
        PasswordClientBuilder::default()
    }

    /// Responds to the challenge with the supplied parameters.
    ///
    /// The caller should use the returned string as an `Authorization` or
    /// `Proxy-Authorization` header value.
    #[allow(unused_variables)] // p is unused with no features.
    pub fn respond(&mut self, p: &PasswordParams) -> Result<String, String> {
        match self {
            #[cfg(feature = "basic-scheme")]
            Self::Basic(c) => Ok(c.respond(p.username, p.password)),
            #[cfg(feature = "digest-scheme")]
            Self::Digest(c) => c.respond(p),

            // Rust 1.55 + --no-default-features produces a "non-exhaustive
            // patterns" error without this. I think this is a rustc bug given
            // that the enum is empty in this case. Work around it.
            #[cfg(not(any(feature = "basic-scheme", feature = "digest-scheme")))]
            _ => unreachable!(),
        }
    }
}

/// Parameters for responding to a password challenge.
///
/// This is cheap to construct; callers generally use a fresh `PasswordParams`
/// for each request.
///
/// The caller is responsible for supplying parameters in the correct
/// format. Servers may expect character data to be in Unicode Normalization
/// Form C as noted in [RFC 7617 section
/// 2.1](https://datatracker.ietf.org/doc/html/rfc7617#section-2.1) for the
/// `Basic` scheme and [RFC 7616 section
/// 4](https://datatracker.ietf.org/doc/html/rfc7616#section-4) for the `Digest`
/// scheme.
///
/// Note that most of these fields are only needed for [`digest::Client`]. Callers
/// that only care about the `Basic` challenge scheme can use
/// [`basic::Client::respond`] directly with only username and password.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PasswordParams<'a> {
    pub username: &'a str,
    pub password: &'a str,

    /// The URI from the Request-URI of the Request-Line, as described in
    /// [RFC 2617 section 3.2.2](https://datatracker.ietf.org/doc/html/rfc2617#section-3.2.2).
    ///
    /// [RFC 2617 section
    /// 3.2.2.5](https://datatracker.ietf.org/doc/html/rfc2617#section-3.2.2.5),
    /// which says the following:
    /// > This may be `*`, an `absoluteURL` or an `abs_path` as specified in
    /// > section 5.1.2 of [RFC 2616](https://datatracker.ietf.org/doc/html/rfc2616),
    /// > but it MUST agree with the Request-URI. In particular, it MUST
    /// > be an `absoluteURL` if the Request-URI is an `absoluteURL`.
    ///
    /// [RFC 7616 section 3.4](https://datatracker.ietf.org/doc/html/rfc7616#section-3.4)
    /// describes this as the "Effective Request URI", which is *always* an
    /// absolute form. This may be a mistake. [Section
    /// 3.4.6](https://datatracker.ietf.org/doc/html/rfc7616#section-3.4.6)
    /// matches RFC 2617 section 3.2.2.5, and [Appendix
    /// A](https://datatracker.ietf.org/doc/html/rfc7616#appendix-A) doesn't
    /// mention a change from RFC 2617.
    pub uri: &'a str,

    /// The HTTP method, such as `GET`.
    ///
    /// When using the `http` crate, use the return value of
    /// [`http::Method::as_str`].
    pub method: &'a str,

    /// The entity body, if available. Use `Some(&[])` for HTTP methods with no
    /// body.
    ///
    /// When `None`, `Digest` challenges will only be able to use
    /// [`crate::digest::Qop::Auth`], not
    /// [`crate::digest::Qop::AuthInt`].
    pub body: Option<&'a [u8]>,
}

/// Parses a list of challenges into a `Vec`.
///
/// Most callers don't need to directly parse; see [`PasswordClient`] instead.
///
/// This is a shorthand for `parser::ChallengeParser::new(input).collect()`. Use
/// [`crate::parser::ChallengeParser`] directly when you want to parse lazily,
/// avoid allocation, and/or see any well-formed challenges before an error.
///
/// ## Example
///
/// ```rust
/// use http_auth::{parse_challenges, AuthBodyRef, ChallengeRef, ParamValueRef};
///
/// // When all challenges are well-formed, returns them.
/// assert_eq!(
///     parse_challenges("UnsupportedSchemeA, Basic realm=\"foo\"").unwrap(),
///     vec![
///         ChallengeRef {
///             scheme: "UnsupportedSchemeA",
///             body: AuthBodyRef::Params(vec![]),
///         },
///         ChallengeRef {
///             scheme: "Basic",
///             body: AuthBodyRef::Params(vec![("realm", ParamValueRef::try_from_escaped("foo").unwrap())]),
///         },
///     ],
/// );
///
/// // Returns `Err` if there is a syntax error anywhere in the input.
/// parse_challenges("UnsupportedSchemeA, Basic realm=\"foo\", error realm=\"unclosed").unwrap_err();
/// ```
#[inline]
pub fn parse_challenges(input: &str) -> Result<Vec<ChallengeRef<'_>>, parser::Error<'_>> {
    parser::ChallengeParser::new(input).collect()
}

/// Returns the value of each of `names` (compared case-insensitively), or the
/// first repeated name.
#[cfg(feature = "digest-scheme")]
pub(crate) fn find_params<'a, 'i, const N: usize>(
    params: &'a [(&'i str, ParamValueRef<'i>)],
    names: [&str; N],
) -> Result<[Option<&'a ParamValueRef<'i>>; N], &'i str> {
    let mut found = [None; N];
    for (k, v) in params {
        if let Some(i) = names.iter().position(|n| k.eq_ignore_ascii_case(n)) {
            if found[i].replace(v).is_some() {
                return Err(k);
            }
        }
    }
    Ok(found)
}

/// Parsed parameter value used within [`AuthBodyRef`].
///
/// The unescaped value is always valid within a quoted-string.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct ParamValueRef<'i> {
    /// The number of backslash escapes in a quoted-text parameter; 0 for a plain token.
    escapes: usize,

    /// The escaped string, which must be pure ASCII (no bytes >= 128) and be
    /// consistent with `escapes`.
    escaped: &'i str,
}

impl<'i> ParamValueRef<'i> {
    /// Tries to create a new `ParamValueRef` from an escaped sequence, primarily for testing.
    ///
    /// Validates the sequence and counts the number of escapes.
    pub fn try_from_escaped(escaped: &'i str) -> Result<Self, String> {
        let mut escapes = 0;
        let mut pos = 0;
        while pos < escaped.len() {
            let slash = memchr::memchr(b'\\', &escaped.as_bytes()[pos..]).map(|off| pos + off);
            for i in pos..slash.unwrap_or(escaped.len()) {
                if (char_classes(escaped.as_bytes()[i]) & C_QDTEXT) == 0 {
                    return Err(format!("{:?} has non-qdtext at byte {}", escaped, i));
                }
            }
            if let Some(slash) = slash {
                escapes += 1;
                if escaped.len() <= slash + 1 {
                    return Err(format!("{:?} ends at a quoted-pair escape", escaped));
                }
                if (char_classes(escaped.as_bytes()[slash + 1]) & C_ESCAPABLE) == 0 {
                    return Err(format!(
                        "{:?} has an invalid quote-pair escape at byte {}",
                        escaped,
                        slash + 1
                    ));
                }
                pos = slash + 2;
            } else {
                break;
            }
        }
        Ok(Self { escaped, escapes })
    }

    /// Creates a new param, panicking if invariants are not satisfied.
    /// This is not part of the stable API; it's just for the fuzz tester to use.
    #[doc(hidden)]
    pub fn new(escapes: usize, escaped: &'i str) -> Self {
        let v = Self::try_from_escaped(escaped).unwrap();
        assert_eq!(v.escapes, escapes, "wrong escape count in {:?}", escaped);
        v
    }

    /// Appends the unescaped form of this parameter to the supplied string.
    pub fn append_unescaped(&self, to: &mut String) {
        to.reserve(self.escaped.len() - self.escapes);
        let mut first_unwritten = 0;
        for _ in 0..self.escapes {
            let i = match memchr::memchr(b'\\', &self.escaped.as_bytes()[first_unwritten..]) {
                Some(rel_i) => first_unwritten + rel_i,
                None => panic!("bad ParamValues; not as many backslash escapes as promised"),
            };
            to.push_str(&self.escaped[first_unwritten..i]);
            to.push_str(&self.escaped[i + 1..i + 2]);
            first_unwritten = i + 2;
        }
        to.push_str(&self.escaped[first_unwritten..]);
    }

    /// Returns the unescaped length of this parameter; cheap.
    #[inline]
    pub fn unescaped_len(&self) -> usize {
        self.escaped.len() - self.escapes
    }

    /// Returns the unescaped form of this parameter; borrowed when there are no
    /// escapes.
    pub fn to_unescaped(&self) -> std::borrow::Cow<'i, str> {
        if self.escapes == 0 {
            std::borrow::Cow::Borrowed(self.escaped)
        } else {
            let mut to = String::new();
            self.append_unescaped(&mut to);
            std::borrow::Cow::Owned(to)
        }
    }

    /// Returns the escaped string, unquoted.
    #[inline]
    pub fn as_escaped(&self) -> &'i str {
        self.escaped
    }
}

impl std::fmt::Debug for ParamValueRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", self.escaped)
    }
}

#[cfg(test)]
mod tests {
    use crate::table::{C_ATTR, C_ESCAPABLE, C_OWS, C_QDTEXT, C_TCHAR};
    use crate::ParamValueRef;

    /// Prints the character classes of all ASCII bytes from the table.
    ///
    /// ```console
    /// $ cargo test -- --nocapture tests::table
    /// ```
    #[test]
    fn table() {
        // Print the table to allow human inspection.
        println!("oct  dec  hex   char      tchar  qdtext  escapable  ows  attr");
        for b in 0..128 {
            let classes = crate::char_classes(b);
            let if_class =
                |class: u8, label: &'static str| if (classes & class) != 0 { label } else { "" };
            println!(
                "{:03o}  {:>3}  0x{:02x}  {:8}  {:5}  {:6}  {:9}  {:3}  {:4}",
                b,
                b,
                b,
                format!("{:?}", char::from(b)),
                if_class(C_TCHAR, "tchar"),
                if_class(C_QDTEXT, "qdtext"),
                if_class(C_ESCAPABLE, "escapable"),
                if_class(C_OWS, "ows"),
                if_class(C_ATTR, "attr")
            );

            // Do basic sanity checks: all tchar and ows should be qdtext; all
            // qdtext should be escapable.
            assert!(classes & (C_TCHAR | C_QDTEXT) != C_TCHAR);
            assert!(classes & (C_OWS | C_QDTEXT) != C_OWS);
            assert!(classes & (C_QDTEXT | C_ESCAPABLE) != C_QDTEXT);
        }
    }

    #[test]
    fn try_from_escaped() {
        assert_eq!(ParamValueRef::try_from_escaped("").unwrap().escapes, 0);
        assert_eq!(ParamValueRef::try_from_escaped("foo").unwrap().escapes, 0);
        assert_eq!(ParamValueRef::try_from_escaped("\\\"").unwrap().escapes, 1);
        assert_eq!(
            ParamValueRef::try_from_escaped("foo\\\"bar")
                .unwrap()
                .escapes,
            1
        );
        assert_eq!(
            ParamValueRef::try_from_escaped("foo\\\"bar\\\"baz")
                .unwrap()
                .escapes,
            2
        );
        ParamValueRef::try_from_escaped("\\").unwrap_err(); // ends in slash
        ParamValueRef::try_from_escaped("\"").unwrap_err(); // not valid qdtext
        ParamValueRef::try_from_escaped("\n").unwrap_err(); // not valid qdtext
        ParamValueRef::try_from_escaped("\\\n").unwrap_err(); // not valid escape
    }

    #[test]
    #[should_panic]
    fn new_rejects_unquotable() {
        ParamValueRef::new(0, "\n");
    }

    #[test]
    fn unescape() {
        assert_eq!(
            &ParamValueRef {
                escapes: 0,
                escaped: ""
            }
            .to_unescaped(),
            ""
        );
        assert_eq!(
            &ParamValueRef {
                escapes: 0,
                escaped: "foo"
            }
            .to_unescaped(),
            "foo"
        );
        assert_eq!(
            &ParamValueRef {
                escapes: 1,
                escaped: "\\foo"
            }
            .to_unescaped(),
            "foo"
        );
        assert_eq!(
            &ParamValueRef {
                escapes: 1,
                escaped: "fo\\o"
            }
            .to_unescaped(),
            "foo"
        );
        assert_eq!(
            &ParamValueRef {
                escapes: 1,
                escaped: "foo\\bar"
            }
            .to_unescaped(),
            "foobar"
        );
        assert_eq!(
            &ParamValueRef {
                escapes: 3,
                escaped: "\\foo\\ba\\r"
            }
            .to_unescaped(),
            "foobar"
        );
    }

    #[test]
    fn display_forms() {
        let c = &crate::parse_challenges(r#"Basic realm="foo", x="a b""#).unwrap()[0];
        assert_eq!(c.to_string(), r#"Basic realm="foo", x="a b""#);
        let c = &crate::parse_challenges("Digest realm=foo, nonce=abc").unwrap()[0];
        assert_eq!(c.to_string(), r#"Digest realm="foo", nonce=abc"#);
    }
}
