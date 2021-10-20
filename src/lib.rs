// Copyright (C) 2021 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HTTP authentication. Currently meant for clients; to be extended for servers.
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
//! Quick example:
//!
//! ```rust
//! use std::convert::TryFrom;
//! let WWW_AUTHENTICATE = "UnsupportedSchemeA, Basic realm=\"foo\", UnsupportedSchemeB";
//! let mut pw_client = http_auth::PasswordClient::try_from(WWW_AUTHENTICATE).unwrap();
//! assert!(matches!(pw_client, http_auth::PasswordClient::Basic(_)));
//! let response = pw_client.respond(&http_auth::PasswordParams {
//!     username: "Aladdin",
//!     password: "open sesame",
//!     uri: "/",
//!     method: "GET",
//!     body: Some(&[]),
//! }).unwrap();
//! assert_eq!(response, "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

use std::convert::TryFrom;

pub mod parser;

#[cfg(feature = "basic-scheme")]
#[cfg_attr(docsrs, doc(cfg(feature = "basic-scheme")))]
pub mod basic;

#[cfg(feature = "digest-scheme")]
#[cfg_attr(docsrs, doc(cfg(feature = "digest-scheme")))]
pub mod digest;

pub use parser::ChallengeParser;

#[cfg(feature = "basic-scheme")]
#[cfg_attr(docsrs, doc(cfg(feature = "basic-scheme")))]
pub use crate::basic::BasicClient;

#[cfg(feature = "digest-scheme")]
#[cfg_attr(docsrs, doc(cfg(feature = "digest-scheme")))]
pub use crate::digest::DigestClient;

// Must match build.rs exactly.
const C_TCHAR: u8 = 1;
const C_QDTEXT: u8 = 2;
const C_ESCAPABLE: u8 = 4;
const C_OWS: u8 = 8;

#[cfg_attr(not(feature = "digest-scheme"), allow(unused))]
const C_ATTR: u8 = 16;

/// Returns a bitmask of `C_*` values indicating character classes.
fn char_classes(b: u8) -> u8 {
    // This table is built by build.rs.
    const TABLE: &[u8; 128] = include_bytes!(concat!(env!("OUT_DIR"), "/char_class_table.bin"));
    if b > 128 {
        0
    } else {
        TABLE[usize::from(b)]
    }
}

/// Parsed challenge (scheme and body) using references to the original header value.
///
/// This is not directly useful for responding to a challenge; it's an
/// intermediary for constructing a [`PasswordClient`] or the like.
///
/// Only supports the param form, not the apocryphal `token68` form, as described
/// in [`crate::parser::ChallengeParser`].
#[derive(Clone, Eq, PartialEq)]
pub struct ChallengeRef<'i> {
    /// The scheme name, which should be compared case-insensitively.
    pub scheme: &'i str,

    /// Zero or more parameters.
    ///
    /// These are represented as a `Vec` of key-value pairs rather than a
    /// `HashMap`. Given that the parameters are generally only used once when
    /// constructing a challenge client and each challenge only supports a few
    /// parameter types, it's more efficient in terms of CPU usage and code size
    /// to scan through them directly without constructing a throw-away
    /// `HashMap`.
    pub params: Vec<ChallengeParamRef<'i>>,
}

impl<'i> ChallengeRef<'i> {
    pub fn new(scheme: &'i str) -> Self {
        ChallengeRef {
            scheme,
            params: Vec::new(),
        }
    }
}

impl<'i> std::fmt::Debug for ChallengeRef<'i> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChallengeRef")
            .field("scheme", &self.scheme)
            .field("params", &ParamsPrinter(&self.params))
            .finish()
    }
}

type ChallengeParamRef<'i> = (&'i str, ParamValue<'i>);

struct ParamsPrinter<'i>(&'i [ChallengeParamRef<'i>]);

impl<'i> std::fmt::Debug for ParamsPrinter<'i> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map()
            .entries(self.0.iter().map(|&(ref k, ref v)| (k, v)))
            .finish()
    }
}

/// Builds a [`PasswordClient`] from the supplied challenges.
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
#[derive(Default)]
pub struct PasswordClientBuilder {
    first_err: Option<String>,
    cur_client: Option<PasswordClient>,
}

impl PasswordClientBuilder {
    /// Considers all challenges from the given [`http::HeaderValue`] challenge list.
    #[cfg(feature = "http")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http")))]
    pub fn header_value(mut self, value: &http::HeaderValue) -> Self {
        if self.complete() {
            return self;
        }

        match value.to_str() {
            Ok(v) => self = self.challenges(v),
            Err(_) => {
                if self.first_err.is_none() {
                    self.first_err = Some("non-ASCII header value".into());
                }
            }
        }

        self
    }

    /// Returns true if no more challenges need to be examined.
    #[cfg(feature = "digest-scheme")]
    fn complete(&self) -> bool {
        matches!(self.cur_client, Some(PasswordClient::Digest(_)))
    }

    /// Returns true if no more challenges need to be examined.
    #[cfg(not(feature = "digest-scheme"))]
    fn complete(&self) -> bool {
        matches!(self.cur_client, Some(_))
    }

    /// Considers all challenges from the given `&str` challenge list.
    pub fn challenges(mut self, value: &str) -> Self {
        let mut parser = ChallengeParser::new(value);
        while !self.complete() {
            match parser.next() {
                Some(Ok(c)) => self = self.challenge(&c),
                Some(Err(e)) => {
                    if self.first_err.is_none() {
                        self.first_err = Some(e.to_string());
                    }
                }
                None => break,
            }
        }
        self
    }

    /// Considers a single challenge.
    pub fn challenge(mut self, challenge: &ChallengeRef<'_>) -> Self {
        if self.complete() {
            return self;
        }

        #[cfg(feature = "digest-scheme")]
        if challenge.scheme.eq_ignore_ascii_case("Digest") {
            match DigestClient::try_from(challenge) {
                Ok(c) => self.cur_client = Some(PasswordClient::Digest(c)),
                Err(e) => {
                    self.first_err.get_or_insert(e);
                }
            }
            return self;
        }

        #[cfg(feature = "basic-scheme")]
        if challenge.scheme.eq_ignore_ascii_case("Basic") && self.cur_client.is_none() {
            match BasicClient::try_from(challenge) {
                Ok(c) => self.cur_client = Some(PasswordClient::Basic(c)),
                Err(e) => {
                    self.first_err.get_or_insert(e);
                }
            }
            return self;
        }

        if self.first_err.is_none() {
            self.first_err = Some(format!("Unsupported scheme {:?}", challenge.scheme));
        }

        self
    }

    /// Returns a new [`PasswordClient`] or fails.
    pub fn build(self) -> Result<PasswordClient, String> {
        if let Some(c) = self.cur_client {
            return Ok(c);
        }
        if let Some(e) = self.first_err {
            return Err(e);
        }
        Err("no challenges given".into())
    }
}

/// Client for responding to a password challenge.
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PasswordClient {
    #[cfg(feature = "basic-scheme")]
    #[cfg_attr(docsrs, doc(cfg(feature = "basic-scheme")))]
    Basic(BasicClient),

    #[cfg(feature = "digest-scheme")]
    #[cfg_attr(docsrs, doc(cfg(feature = "digest-scheme")))]
    Digest(DigestClient),
}

/// Tries to create a `PasswordClient` from the single supplied challenge.
///
/// This is a convenience wrapper around [`PasswordClientBuilder`].
impl TryFrom<&ChallengeRef<'_>> for PasswordClient {
    type Error = String;

    fn try_from(value: &ChallengeRef<'_>) -> Result<Self, Self::Error> {
        #[cfg(feature = "basic-scheme")]
        if value.scheme.eq_ignore_ascii_case("Basic") {
            return Ok(PasswordClient::Basic(BasicClient::try_from(value)?));
        }
        #[cfg(feature = "digest-scheme")]
        if value.scheme.eq_ignore_ascii_case("Digest") {
            return Ok(PasswordClient::Digest(DigestClient::try_from(value)?));
        }

        Err(format!("unsupported challenge scheme {:?}", value.scheme))
    }
}

/// Tries to create a `PasswordClient` forom the supplied `str` challenge list.
///
/// This is a convenience wrapper around [`PasswordClientBuilder`].
impl TryFrom<&str> for PasswordClient {
    type Error = String;

    #[inline]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        PasswordClient::builder().challenges(value).build()
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
        PasswordClient::builder().header_value(value).build()
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
        let mut builder = PasswordClient::builder();
        for v in value {
            builder = builder.header_value(v);
        }
        builder.build()
    }
}

impl PasswordClient {
    /// Builds a new `PasswordClient`.
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
/// Note that most of these fields are only needed for [`DigestClient`]. Callers
/// that only care about the `Basic` challenge scheme can use
/// [`BasicClient::respond`] directly with only username and password.
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
/// This is a shorthand for `parser::ChallengeParser::new(input).collect()`.
#[inline]
pub fn parse_challenges(input: &str) -> Result<Vec<ChallengeRef>, parser::Error> {
    parser::ChallengeParser::new(input).collect()
}

/// Parsed parameter value.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct ParamValue<'i> {
    /// The number of backslash escapes in a quoted-text parameter; 0 for a plain token.
    escapes: usize,

    /// The raw string, which must be pure ASCII (no bytes >= 128) and be consistent with `escapes`.
    raw: &'i str,
}

impl<'i> ParamValue<'i> {
    /// Creates a new param, panicking if invariants are not satisfied.
    /// This not part of the stable API; it's just for the fuzz tester to use.
    #[doc(hidden)]
    pub fn new(escapes: usize, raw: &'i str) -> Self {
        let mut pos = 0;
        for escape in 0..escapes {
            match memchr::memchr(b'\\', &raw.as_bytes()[pos..]) {
                Some(rel_pos) => pos += rel_pos + 2,
                None => panic!(
                    "expected {} backslashes in {:?}, ran out after {}",
                    escapes, raw, escape
                ),
            };
        }
        if memchr::memchr(b'\\', &raw.as_bytes()[pos..]).is_some() {
            panic!("expected {} backslashes in {:?}, are more", escapes, raw);
        }
        ParamValue { escapes, raw }
    }

    /// Appends the unescaped form of this parameter to the supplied string.
    fn append_unescaped(&self, to: &mut String) {
        to.reserve(self.raw.len() - self.escapes);
        let mut first_unwritten = 0;
        for _ in 0..self.escapes {
            let i = match memchr::memchr(b'\\', &self.raw.as_bytes()[first_unwritten..]) {
                Some(rel_i) => first_unwritten + rel_i,
                None => panic!("bad ParamValues; not as many backslash escapes as promised"),
            };
            to.push_str(&self.raw[first_unwritten..i]);
            to.push_str(&self.raw[i + 1..i + 2]);
            first_unwritten = i + 2;
        }
        to.push_str(&self.raw[first_unwritten..]);
    }

    /// Returns the unescaped length of this parameter; cheap.
    #[inline]
    pub fn unescaped_len(&self) -> usize {
        self.raw.len() - self.escapes
    }

    /// Returns the unescaped form of this parameter as a fresh `String`.
    pub fn to_unescaped(&self) -> String {
        let mut to = String::new();
        self.append_unescaped(&mut to);
        to
    }
}

impl<'i> std::fmt::Debug for ParamValue<'i> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", self.raw)
    }
}

#[cfg(test)]
mod tests {
    use crate::ParamValue;
    use crate::{C_ATTR, C_ESCAPABLE, C_OWS, C_QDTEXT, C_TCHAR};

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
    fn unescape() {
        assert_eq!(
            &ParamValue {
                escapes: 0,
                raw: ""
            }
            .to_unescaped(),
            ""
        );
        assert_eq!(
            &ParamValue {
                escapes: 0,
                raw: "foo"
            }
            .to_unescaped(),
            "foo"
        );
        assert_eq!(
            &ParamValue {
                escapes: 1,
                raw: "\\foo"
            }
            .to_unescaped(),
            "foo"
        );
        assert_eq!(
            &ParamValue {
                escapes: 1,
                raw: "fo\\o"
            }
            .to_unescaped(),
            "foo"
        );
        assert_eq!(
            &ParamValue {
                escapes: 1,
                raw: "foo\\bar"
            }
            .to_unescaped(),
            "foobar"
        );
        assert_eq!(
            &ParamValue {
                escapes: 3,
                raw: "\\foo\\ba\\r"
            }
            .to_unescaped(),
            "foobar"
        );
    }
}
