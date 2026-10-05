// Copyright (C) 2021 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parses as in [RFC 7235](https://datatracker.ietf.org/doc/html/rfc7235).
//!
//! Most callers don't need to directly parse; see [`crate::PasswordClient`] instead.

// State machine implementation of challenge parsing with a state machine.
// Nice qualities: predictable performance (no backtracking), low dependencies.
//
// The implementation is *not* a straightforward translation of the ABNF
// grammar, so we verify correctness via a fuzz tester that compares with a
// nom-based parser. See `fuzz/fuzz_targets/parse_challenges.rs`.

use std::{fmt::Display, ops::Range};

use crate::{ChallengeRef, ParamValue};

use crate::{char_classes, C_ESCAPABLE, C_OWS, C_QDTEXT, C_TCHAR};

/// Calls `log::trace!` only if the `trace` cargo feature is enabled.
macro_rules! trace {
    ($($arg:tt)+) => (#[cfg(feature = "trace")] log::trace!($($arg)+))
}

/// Parses a list of challenges as in [RFC
/// 7235](https://datatracker.ietf.org/doc/html/rfc7235) `Proxy-Authenticate`
/// or `WWW-Authenticate` header values.
///
/// Most callers don't need to directly parse; see [`crate::PasswordClient`] instead.
///
/// This is an iterator that parses lazily, returning each challenge as soon as
/// its end has been found. (Due to the grammar's ambiguous use of commas to
/// separate both challenges and parameters, a challenge's end is found after
/// parsing the *following* challenge's scheme name.) On encountering a syntax
/// error, it yields `Some(Err(_))` and fuses: all subsequent calls to
/// [`Iterator::next`] will return `None`.
///
/// See also the [`crate::parse_challenges`] convenience wrapper.
///
/// ## Example
///
/// ```rust
/// use http_auth::{parser::ChallengeParser, ChallengeRef, ParamValue};
/// let challenges = "UnsupportedSchemeA, Basic realm=\"foo\", error realm=\"unclosed";
/// let mut parser = ChallengeParser::new(challenges);
/// let c = parser.next().unwrap().unwrap();
/// assert_eq!(c, ChallengeRef {
///     scheme: "UnsupportedSchemeA",
///     token68: None,
///     params: vec![],
/// });
/// let c = parser.next().unwrap().unwrap();
/// assert_eq!(c, ChallengeRef {
///     scheme: "Basic",
///     token68: None,
///     params: vec![("realm", ParamValue::try_from_escaped("foo").unwrap())],
/// });
/// let c = parser.next().unwrap().unwrap_err();
/// ```
///
/// ## Implementation notes
///
/// This rigorously matches the official ABNF grammar except as follows:
///
/// *   Doesn't allow non-ASCII characters. [RFC 7235 Appendix
///     B](https://datatracker.ietf.org/doc/html/rfc7235#appendix-B) references
///     the `quoted-string` rule from [RFC 7230 section
///     3.2.6](https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6),
///     which allows these via `obs-text`, but the meaning is ill-defined in
///     the context of RFC 7235.
/// *   Accepts `token68` challenges ([RFC 9110 section 11.2](https://datatracker.ietf.org/doc/html/rfc9110#section-11.2)).
pub struct ChallengeParser<'i> {
    input: &'i str,
    pos: usize,
    state: State<'i>,
}

impl<'i> ChallengeParser<'i> {
    pub fn new(input: &'i str) -> Self {
        ChallengeParser {
            input,
            pos: 0,
            state: State::PreToken {
                challenge: None,
                next: Possibilities(P_SCHEME),
            },
        }
    }
}

/// Describes a parse error and where in the input it occurs.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Error<'i> {
    input: &'i str,
    pos: usize,
    error: &'static str,
}

impl<'i> Error<'i> {
    fn invalid_byte(input: &'i str, pos: usize) -> Self {
        Self {
            input,
            pos,
            error: "invalid byte",
        }
    }
}

impl Display for Error<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} at byte {}: {:?}",
            self.error,
            self.pos,
            format_args!(
                "{}(HERE-->){}",
                &self.input[..self.pos],
                &self.input[self.pos..]
            ),
        )
    }
}

impl std::error::Error for Error<'_> {}

/// A set of zero or more `P_*` values indicating possibilities for the current
/// and/or upcoming tokens.
#[derive(Copy, Clone, PartialEq, Eq)]
struct Possibilities(u8);

const P_SCHEME: u8 = 1;
const P_PARAM_KEY: u8 = 2;
const P_EOF: u8 = 4;
const P_WHITESPACE: u8 = 8;
const P_COMMA_PARAM_KEY: u8 = 16; // a comma, then a param_key.
const P_COMMA_EOF: u8 = 32; // a comma, then eof.

impl std::fmt::Debug for Possibilities {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut l = f.debug_set();
        if (self.0 & P_SCHEME) != 0 {
            l.entry(&"scheme");
        }
        if (self.0 & P_PARAM_KEY) != 0 {
            l.entry(&"param_key");
        }
        if (self.0 & P_EOF) != 0 {
            l.entry(&"eof");
        }
        if (self.0 & P_WHITESPACE) != 0 {
            l.entry(&"whitespace");
        }
        if (self.0 & P_COMMA_PARAM_KEY) != 0 {
            l.entry(&"comma_param_key");
        }
        if (self.0 & P_COMMA_EOF) != 0 {
            l.entry(&"comma_eof");
        }
        l.finish()
    }
}

enum State<'i> {
    Done,

    /// Consuming OWS and commas, then advancing to `Token`.
    PreToken {
        challenge: Option<ChallengeRef<'i>>,
        next: Possibilities,
    },

    /// Parsing a scheme/parameter key, or the whitespace immediately following it.
    Token {
        /// Current `challenge`, if any. If none, this token must be a scheme.
        challenge: Option<ChallengeRef<'i>>,
        token_pos: Range<usize>,
        cur: Possibilities, // subset of P_SCHEME|P_PARAM_KEY
    },

    /// Transitioned from `Token` or `PostToken` on first `=` after parameter key.
    /// Kept there for BWS in param case.
    PostEquals {
        challenge: ChallengeRef<'i>,
        key_pos: Range<usize>,
    },

    /// Transitioned from `Equals` on initial `C_TCHAR`.
    ParamUnquotedValue {
        challenge: ChallengeRef<'i>,
        key_pos: Range<usize>,
        value_start: usize,
    },

    /// Transitioned from `Equals` on initial `"`.
    ParamQuotedValue {
        challenge: ChallengeRef<'i>,
        key_pos: Range<usize>,
        value_start: usize,
        escapes: usize,
        in_backslash: bool,
    },
}

impl<'i> Iterator for ChallengeParser<'i> {
    type Item = Result<ChallengeRef<'i>, Error<'i>>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.input.len() {
            let b = self.input.as_bytes()[self.pos];
            let classes = char_classes(b);
            match std::mem::replace(&mut self.state, State::Done) {
                State::Done => return None,
                State::PreToken { challenge, next } => {
                    trace!(
                        "PreToken({:?}) pos={} b={:?}",
                        next,
                        self.pos,
                        char::from(b)
                    );
                    if (classes & C_OWS) != 0 && (next.0 & P_WHITESPACE) != 0 {
                        self.state = State::PreToken {
                            challenge,
                            next: Possibilities(next.0 & !P_EOF),
                        }
                    } else if b == b',' {
                        let next = Possibilities(
                            next.0
                                | P_WHITESPACE
                                | P_SCHEME
                                | if (next.0 & P_COMMA_PARAM_KEY) != 0 {
                                    P_PARAM_KEY
                                } else {
                                    0
                                }
                                | if (next.0 & P_COMMA_EOF) != 0 {
                                    P_EOF
                                } else {
                                    0
                                },
                        );
                        self.state = State::PreToken { challenge, next }
                    } else if (classes & C_TCHAR) != 0 {
                        self.state = State::Token {
                            challenge,
                            token_pos: self.pos..self.pos + 1,
                            cur: Possibilities(next.0 & (P_SCHEME | P_PARAM_KEY)),
                        }
                    } else {
                        return Some(Err(Error::invalid_byte(self.input, self.pos)));
                    }
                }
                State::Token {
                    challenge,
                    token_pos,
                    cur,
                } => {
                    trace!(
                        "Token({:?}, {:?}) pos={} b={:?}, cur challenge = {:#?}",
                        token_pos,
                        cur,
                        self.pos,
                        char::from(b),
                        challenge
                    );
                    if (classes & C_TCHAR) != 0 {
                        if token_pos.end == self.pos {
                            self.state = State::Token {
                                challenge,
                                token_pos: token_pos.start..self.pos + 1,
                                cur,
                            };
                        } else {
                            // Ending a scheme, starting its body after 1*SP.
                            let gap = &self.input[token_pos.end..self.pos];
                            if (cur.0 & P_SCHEME) == 0
                                || gap.is_empty()
                                || gap.bytes().any(|b| b != b' ')
                            {
                                return Some(Err(Error::invalid_byte(self.input, self.pos)));
                            }
                            self.state = State::Token {
                                challenge: Some(ChallengeRef::new(&self.input[token_pos])),
                                token_pos: self.pos..self.pos + 1,
                                cur: Possibilities(P_PARAM_KEY),
                            };
                            if let Some(c) = challenge {
                                self.pos += 1;
                                return Some(Ok(c));
                            }
                        }
                    } else {
                        match b {
                            b',' if (cur.0 & P_SCHEME) != 0 => {
                                self.state = State::PreToken {
                                    challenge: Some(ChallengeRef::new(&self.input[token_pos])),
                                    next: Possibilities(
                                        P_SCHEME | P_WHITESPACE | P_EOF | P_COMMA_EOF,
                                    ),
                                };
                                if let Some(c) = challenge {
                                    self.pos += 1;
                                    return Some(Ok(c));
                                }
                            }
                            b'=' if (cur.0 & P_PARAM_KEY) != 0 => match challenge {
                                Some(challenge) => {
                                    self.state = State::PostEquals {
                                        challenge,
                                        key_pos: token_pos,
                                    }
                                }
                                None => {
                                    return Some(Err(Error {
                                        input: self.input,
                                        pos: self.pos,
                                        error: "= without existing challenge",
                                    }));
                                }
                            },

                            b' ' | b'\t' if (cur.0 & P_SCHEME) != 0 => {
                                let rest = &self.input[self.pos..];
                                let ws = rest.len() - rest.trim_start_matches([' ', '\t']).len();
                                if !rest[..ws].contains('\t') {
                                    // A token68 body follows 1*SP and may start with '/'.
                                    if let Some(end) = token68_end(self.input, self.pos + ws) {
                                        self.state = State::PreToken {
                                            challenge: Some(ChallengeRef {
                                                scheme: &self.input[token_pos],
                                                token68: Some(&self.input[self.pos + ws..end]),
                                                params: Vec::new(),
                                            }),
                                            next: Possibilities(
                                                P_WHITESPACE | P_SCHEME | P_COMMA_EOF | P_EOF,
                                            ),
                                        };
                                        self.pos = end;
                                        if let Some(c) = challenge {
                                            return Some(Ok(c));
                                        }
                                        continue;
                                    }
                                }
                                self.pos += ws;
                                self.state = State::Token {
                                    challenge,
                                    token_pos,
                                    cur,
                                };
                                continue;
                            }

                            b' ' | b'\t' => {
                                self.state = State::Token {
                                    challenge,
                                    token_pos,
                                    cur,
                                };
                            }

                            _ => return Some(Err(Error::invalid_byte(self.input, self.pos))),
                        }
                    }
                }
                State::PostEquals { challenge, key_pos } => {
                    trace!("PostEquals pos={} b={:?}", self.pos, char::from(b));
                    if (classes & C_OWS) != 0 {
                        // Note this doesn't advance key_pos.end, so in the token68 case, another
                        // `=` will not be allowed.
                        self.state = State::PostEquals { challenge, key_pos };
                    } else if b == b'"' {
                        self.state = State::ParamQuotedValue {
                            challenge,
                            key_pos,
                            value_start: self.pos + 1,
                            escapes: 0,
                            in_backslash: false,
                        };
                    } else if (classes & C_TCHAR) != 0 {
                        self.state = State::ParamUnquotedValue {
                            challenge,
                            key_pos,
                            value_start: self.pos,
                        };
                    } else {
                        return Some(Err(Error::invalid_byte(self.input, self.pos)));
                    }
                }
                State::ParamUnquotedValue {
                    mut challenge,
                    key_pos,
                    value_start,
                } => {
                    trace!("ParamUnquotedValue pos={} b={:?}", self.pos, char::from(b));
                    if (classes & C_TCHAR) != 0 {
                        self.state = State::ParamUnquotedValue {
                            challenge,
                            key_pos,
                            value_start,
                        };
                    } else if (classes & C_OWS) != 0 {
                        challenge.params.push((
                            &self.input[key_pos],
                            ParamValue {
                                escapes: 0,
                                escaped: &self.input[value_start..self.pos],
                            },
                        ));
                        self.state = State::PreToken {
                            challenge: Some(challenge),
                            next: Possibilities(P_WHITESPACE | P_COMMA_PARAM_KEY | P_COMMA_EOF),
                        };
                    } else if b == b',' {
                        challenge.params.push((
                            &self.input[key_pos],
                            ParamValue {
                                escapes: 0,
                                escaped: &self.input[value_start..self.pos],
                            },
                        ));
                        self.state = State::PreToken {
                            challenge: Some(challenge),
                            next: Possibilities(
                                P_WHITESPACE
                                    | P_PARAM_KEY
                                    | P_SCHEME
                                    | P_EOF
                                    | P_COMMA_PARAM_KEY
                                    | P_COMMA_EOF,
                            ),
                        };
                    } else {
                        return Some(Err(Error::invalid_byte(self.input, self.pos)));
                    }
                }
                State::ParamQuotedValue {
                    mut challenge,
                    key_pos,
                    value_start,
                    escapes,
                    in_backslash,
                } => {
                    trace!("ParamQuotedValue pos={} b={:?}", self.pos, char::from(b));
                    if in_backslash {
                        if (classes & C_ESCAPABLE) == 0 {
                            return Some(Err(Error::invalid_byte(self.input, self.pos)));
                        }
                        self.state = State::ParamQuotedValue {
                            challenge,
                            key_pos,
                            value_start,
                            escapes: escapes + 1,
                            in_backslash: false,
                        };
                    } else if b == b'\\' {
                        self.state = State::ParamQuotedValue {
                            challenge,
                            key_pos,
                            value_start,
                            escapes,
                            in_backslash: true,
                        };
                    } else if b == b'"' {
                        challenge.params.push((
                            &self.input[key_pos],
                            ParamValue {
                                escapes,
                                escaped: &self.input[value_start..self.pos],
                            },
                        ));
                        self.state = State::PreToken {
                            challenge: Some(challenge),
                            next: Possibilities(
                                P_WHITESPACE | P_EOF | P_COMMA_PARAM_KEY | P_COMMA_EOF,
                            ),
                        };
                    } else if (classes & C_QDTEXT) != 0 {
                        self.state = State::ParamQuotedValue {
                            challenge,
                            key_pos,
                            value_start,
                            escapes,
                            in_backslash,
                        };
                    } else {
                        return Some(Err(Error::invalid_byte(self.input, self.pos)));
                    }
                }
            };
            self.pos += 1;
        }
        match std::mem::replace(&mut self.state, State::Done) {
            State::Done => {}
            State::PreToken {
                challenge, next, ..
            } => {
                trace!("eof, PreToken({:?})", next);
                if (next.0 & P_EOF) == 0 {
                    return Some(Err(Error {
                        input: self.input,
                        pos: self.input.len(),
                        error: "unexpected EOF",
                    }));
                }
                if let Some(challenge) = challenge {
                    return Some(Ok(challenge));
                }
            }
            State::Token {
                challenge,
                token_pos,
                cur,
            } => {
                trace!("eof, Token({:?})", cur);
                if (cur.0 & P_SCHEME) == 0 {
                    return Some(Err(Error {
                        input: self.input,
                        pos: self.input.len(),
                        error: "unexpected EOF expecting =",
                    }));
                }
                if token_pos.end != self.input.len()
                    && self.input[token_pos.end..].bytes().any(|b| b != b' ')
                {
                    return Some(Err(Error {
                        input: self.input,
                        pos: self.input.len(),
                        error: "EOF after whitespace",
                    }));
                }
                if let Some(challenge) = challenge {
                    self.state = State::Token {
                        challenge: None,
                        token_pos,
                        cur,
                    };
                    return Some(Ok(challenge));
                }
                return Some(Ok(ChallengeRef::new(&self.input[token_pos])));
            }
            State::PostEquals { .. } => {
                trace!("eof, PostEquals");
                return Some(Err(Error {
                    input: self.input,
                    pos: self.input.len(),
                    error: "unexpected EOF expecting param value",
                }));
            }
            State::ParamUnquotedValue {
                mut challenge,
                key_pos,
                value_start,
            } => {
                trace!("eof, ParamUnquotedValue");
                challenge.params.push((
                    &self.input[key_pos],
                    ParamValue {
                        escapes: 0,
                        escaped: &self.input[value_start..],
                    },
                ));
                return Some(Ok(challenge));
            }
            State::ParamQuotedValue { .. } => {
                trace!("eof, ParamQuotedValue");
                return Some(Err(Error {
                    input: self.input,
                    pos: self.input.len(),
                    error: "unexpected EOF in quoted param value",
                }));
            }
        }
        None
    }
}

impl std::iter::FusedIterator for ChallengeParser<'_> {}

/// Parses `Authorization` or `Proxy-Authorization` credentials as in
/// [RFC 9110 section 11.4](https://datatracker.ietf.org/doc/html/rfc9110#section-11.4):
///
/// ```text
/// credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// token68     = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
/// ```
///
/// Trims surrounding OWS. Doesn't check for duplicate parameters.
///
/// ```rust
/// use http_auth::{parse_credentials, ChallengeRef};
/// let c = parse_credentials("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==").unwrap();
/// assert_eq!(c.scheme, "Basic");
/// assert_eq!(c.token68, Some("QWxhZGRpbjpvcGVuIHNlc2FtZQ=="));
/// ```
pub fn parse_credentials(input: &str) -> Result<ChallengeRef<'_>, Error<'_>> {
    let input = input.trim_matches(|c| c == ' ' || c == '\t');
    let err = |pos, error| Error { input, pos, error };
    let mut parser = ChallengeParser::new(input);
    let first = match (input.starts_with(','), parser.next()) {
        (false, Some(r)) => r?,
        _ => return Err(err(0, "expected credentials")),
    };
    if parser.next().is_some() || (first.token68.is_some() && input.ends_with(',')) {
        return Err(err(input.len(), "trailing input"));
    }
    Ok(first)
}

/// If `input[start..]` is a `token68` followed by a comma, OWS then a comma, or
/// EOF, returns its end offset.
fn token68_end(input: &str, start: usize) -> Option<usize> {
    let rest = &input[start..];
    let body = rest.trim_start_matches(|c: char| {
        c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '+' | '/')
    });
    if body.len() == rest.len() {
        return None;
    }
    let end = start + rest.len() - body.trim_start_matches('=').len();
    let after = input[end..].trim_start_matches([' ', '\t']);
    (after.is_empty() || after.starts_with(',')).then_some(end)
}

/// Returns the value of a hex digit.
#[cfg(all(feature = "server", feature = "digest-scheme"))]
fn hex_val(b: u8) -> Option<u8> {
    char::from(b).to_digit(16).map(|d| d as u8)
}

/// Decodes an [RFC 8187](https://datatracker.ietf.org/doc/html/rfc8187)
/// `ext-value`: `charset "'" [ language ] "'" value-chars`. Accepts the
/// `UTF-8` charset (required) and `ISO-8859-1`.
#[cfg(all(feature = "server", feature = "digest-scheme"))]
pub(crate) fn decode_ext_value(s: &str) -> Option<String> {
    let (charset, rest) = s.split_once('\'')?;
    let (language, value) = rest.split_once('\'')?;
    if !language
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return None;
    }
    let mut bytes = Vec::with_capacity(value.len());
    let mut it = value.bytes();
    while let Some(b) = it.next() {
        if b == b'%' {
            let hi = it.next().and_then(hex_val)?;
            let lo = it.next().and_then(hex_val)?;
            bytes.push((hi << 4) | lo);
        } else if (char_classes(b) & crate::table::C_ATTR) != 0 {
            bytes.push(b);
        } else {
            return None;
        }
    }
    if charset.eq_ignore_ascii_case("UTF-8") {
        String::from_utf8(bytes).ok()
    } else if charset.eq_ignore_ascii_case("ISO-8859-1") {
        Some(bytes.into_iter().map(char::from).collect())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::parse_credentials;
    use crate::{ChallengeRef, ParamValue};

    #[test]
    fn multi_challenge() {
        // https://datatracker.ietf.org/doc/html/rfc7235#section-4.1
        let input =
            r#"Newauth realm="apps", type=1, title="Login to \"apps\"", Basic realm="simple""#;
        let challenges = crate::parse_challenges(input).unwrap();
        assert_eq!(
            &challenges[..],
            &[
                ChallengeRef {
                    scheme: "Newauth",
                    token68: None,
                    params: vec![
                        ("realm", ParamValue::new(0, "apps")),
                        ("type", ParamValue::new(0, "1")),
                        ("title", ParamValue::new(2, r#"Login to \"apps\""#)),
                    ],
                },
                ChallengeRef {
                    scheme: "Basic",
                    token68: None,
                    params: vec![("realm", ParamValue::new(0, "simple")),],
                },
            ]
        );
    }

    #[test]
    fn empty() {
        crate::parse_challenges("").unwrap_err();
        crate::parse_challenges(",").unwrap_err();
    }

    #[test]
    fn token68_challenges() {
        assert_eq!(
            crate::parse_challenges("Basic abc=").unwrap(),
            vec![ChallengeRef {
                scheme: "Basic",
                token68: Some("abc="),
                params: vec![],
            }]
        );
        assert_eq!(
            crate::parse_challenges("Negotiate abc, Basic realm=\"x\"").unwrap(),
            vec![
                ChallengeRef {
                    scheme: "Negotiate",
                    token68: Some("abc"),
                    params: vec![],
                },
                ChallengeRef {
                    scheme: "Basic",
                    token68: None,
                    params: vec![("realm", ParamValue::new(0, "x"))],
                },
            ]
        );
        assert_eq!(
            crate::parse_challenges("Basic  abc==").unwrap(),
            vec![ChallengeRef {
                scheme: "Basic",
                token68: Some("abc=="),
                params: vec![],
            }]
        );
    }

    #[test]
    fn credentials() {
        type Params<'a> = Vec<(&'a str, ParamValue<'a>)>;
        let cases: &[(&str, Option<&str>, Params<'_>)] = &[
            (
                "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
                Some("QWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
                vec![],
            ),
            ("Basic   abc=", Some("abc="), vec![]),
            ("Digest a", Some("a"), vec![]),
            ("Negotiate", None, vec![]),
            ("Basic ", None, vec![]),
            ("Basic \t ", None, vec![]),
            ("  Basic   abc=  ", Some("abc="), vec![]),
            (
                r#"Digest username="Mufasa", qop=auth, nc=00000001"#,
                None,
                vec![
                    ("username", ParamValue::new(0, "Mufasa")),
                    ("qop", ParamValue::new(0, "auth")),
                    ("nc", ParamValue::new(0, "00000001")),
                ],
            ),
            (
                r#"Digest  a="x \"y\"", b=c,"#,
                None,
                vec![
                    ("a", ParamValue::new(2, r#"x \"y\""#)),
                    ("b", ParamValue::new(0, "c")),
                ],
            ),
            (
                "\tDigest a=b, c=d \t",
                None,
                vec![
                    ("a", ParamValue::new(0, "b")),
                    ("c", ParamValue::new(0, "d")),
                ],
            ),
        ];
        for (input, token68, params) in cases {
            let c = parse_credentials(input).unwrap();
            assert_eq!(c.token68, *token68, "{:?}", input);
            assert_eq!(&c.params, params, "{:?}", input);
        }
    }

    #[test]
    fn long_space_run_is_linear() {
        let mut s = String::from("Foo");
        s.push_str(&" ".repeat(200_000));
        s.push_str("a=b");
        let challenges = crate::parse_challenges(&s).unwrap();
        assert_eq!(challenges.len(), 1);
        assert!(challenges[0].token68.is_none());
        assert_eq!(parse_credentials(&s).unwrap().params.len(), 1);
        let mut s = String::from("Foo");
        s.push_str(&" ".repeat(200_000));
        s.push('\t');
        s.push_str(&" ".repeat(200_000));
        s.push_str("a=b");
        let _ = crate::parse_challenges(&s);
    }
}
