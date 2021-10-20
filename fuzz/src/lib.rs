// Copyright (C) 2021 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! nom-based parser which is a fairly straightforward translation of the ABNF
//! from [RFC 7235](https://datatracker.ietf.org/doc/html/rfc7235):
//!
//! *   Some functional differences are noted in [`http_auth::parser::ChallengeParser`].
//! *   We alter the `challenge` definition to avoid ambiguities when placing it
//!     into `1#challenge`. You can see this effect by adjusting `test_2level_list1`
//!     to not use the `_inner` form.

use log::trace;
use nom::branch::alt;
use nom::bytes::complete::is_a;
use nom::character::complete::{char, satisfy};
use nom::combinator::{all_consuming, consumed, map, opt, value};
use nom::multi::{fold_many0, many0_count, many1, many1_count, separated_list0, separated_list1};
use nom::sequence::{delimited, pair, preceded, separated_pair, tuple};

use http_auth::{ChallengeRef, ParamValue};

/// Parses optional whitespace as in [RFC 7230 section 3.2.3](https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.3).
///
/// ```text
///      OWS            = *( SP / HTAB )
///                     ; optional whitespace
/// ```
use nom::character::complete::space0 as ows;

/// Parses "bad" whitespace as in [RFC 7230 section 3.2.3](https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.3).
///
/// This is functionally identical to `ows`.
use nom::character::complete::space0 as bws;

/// Parses a token as in RFC 7230 section 3.2.6.
///
/// ```text
///      token          = 1*tchar
///
///      tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
///                     / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
///                     / DIGIT / ALPHA
///                     ; any VCHAR, except delimiters
/// ```
fn token(input: &str) -> nom::IResult<&str, &str> {
    trace!("token attempt on {:?}", input);
    is_a("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvxwyzABCDEFGHIJKLMNOPQRSTUVWXYZ")(input)
}

/// Parses `quoted-string` as in [RFC 7230 section 3.2.6](https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6).
///
/// ```text
/// quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE
/// qdtext         = HTAB / SP /%x21 / %x23-5B / %x5D-7E / obs-text
/// obs-text       = %x80-FF
/// quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )
/// VCHAR          =  %x21-7E
///                ; visible (printing) characters
/// ```
fn quoted_string(input: &str) -> nom::IResult<&str, ParamValue> {
    trace!("quoted_string attempt on {:?}", input);
    let is_qdtext = |c| match c {
        '\t' | ' ' | '\x21' | '\x23'..='\x5B' | '\x5D'..='\x7E' => true,
        _ => false,
    };
    let is_escapable = |c| match c {
        '\t' | ' ' | '\x21'..='\x7E' => true,
        _ => false,
    };
    delimited(
        char('"'),
        map(
            consumed(fold_many0(
                alt((
                    value(0, many1(satisfy(is_qdtext))),
                    value(1, pair(char('\\'), satisfy(is_escapable))),
                )),
                || 0,
                |acc: usize, item: usize| acc + item,
            )),
            |(raw, escapes)| ParamValue::new(escapes, raw),
        ),
        char('"'),
    )(input)
}

/// Parses `auth-param` as in [RFC 7235 section
/// 2.1](https://datatracker.ietf.org/doc/html/rfc7235#section-2.1).
///
/// ```text
///   auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
fn auth_param(input: &str) -> nom::IResult<&str, (&str, ParamValue)> {
    trace!("auth_param attempt on {:?}", input);
    separated_pair(
        token,
        tuple((bws, char('='), bws)),
        alt((map(token, |raw| ParamValue::new(0, raw)), quoted_string)),
    )(input)
}

/// Parses `1#element` as defined in
/// [RFC 7230 section 7](https://datatracker.ietf.org/doc/html/rfc7230#section-7).
///
/// > A recipient MUST accept lists that satisfy the following syntax:
/// > ```text
/// > 1#element => *( "," OWS ) element *( OWS "," [ OWS element ] )
/// > ```
fn list1_relaxed<'i, O, F>(f: F) -> impl FnMut(&'i str) -> nom::IResult<&'i str, Vec<O>>
where
    F: nom::Parser<&'i str, O, nom::error::Error<&'i str>>,
{
    delimited(
        // *( "," OWS )
        many0_count(pair(char(','), ows)),
        list1_relaxed_inner(f),
        // *( OWS "," )
        many0_count(pair(ows, char(','))),
    )
}

/// Parses `1#element` minus the leading and trailing portions.
fn list1_relaxed_inner<'i, O, F>(f: F) -> impl FnMut(&'i str) -> nom::IResult<&'i str, Vec<O>>
where
    F: nom::Parser<&'i str, O, nom::error::Error<&'i str>>,
{
    // element *( OWS 1*( "," OWS ) element )
    separated_list1(pair(ows, many1_count(pair(char(','), ows))), f)
}

/// Parses `#element` as defined in [RFC 7230 section 7](https://datatracker.ietf.org/doc/html/rfc7230#section-7).
///
/// > A recipient MUST accept lists that satisfy the following syntax:
/// > ```text
/// > #element => [ ( "," / element ) *( OWS "," [ OWS element ] ) ]
/// > ```
#[cfg(test)]
fn list0_relaxed<'i, O, F>(f: F) -> impl FnMut(&'i str) -> nom::IResult<&'i str, Vec<O>>
where
    F: nom::Parser<&'i str, O, nom::error::Error<&'i str>>,
{
    delimited(
        // *( "," OWS )
        many0_count(pair(char(','), ows)),
        list0_relaxed_inner(f),
        // *( OWS "," )
        many0_count(pair(ows, char(','))),
    )
}

/// Parses `1#element` minus the leading and trailing portions.
///
/// This is used in the `challenge` definition; it avoids ambiguities with
/// the outer list1.
fn list0_relaxed_inner<'i, O, F>(f: F) -> impl FnMut(&'i str) -> nom::IResult<&'i str, Vec<O>>
where
    F: nom::Parser<&'i str, O, nom::error::Error<&'i str>>,
{
    // [ element *( OWS 1*( "," OWS ) element ) ]
    separated_list0(pair(ows, many1_count(pair(char(','), ows))), f)
}

/// Parses a challenge as in [RFC 7235].
///
/// Section 2.1 defines this rule as follows:
/// ```text
/// auth-scheme = token
/// challenge   = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// ```
///
/// Although in practice this is ambiguous when placed into a `1#challenge`,
/// which we resolve by using `list0_relaxed_inner` rather than `list0_relaxed`.
fn challenge(input: &str) -> nom::IResult<&str, ChallengeRef> {
    trace!("challenge attempt on {:?}", input);
    map(
        tuple((
            token,
            opt(preceded(char(' '), list0_relaxed_inner(auth_param))),
        )),
        |(scheme, opt_params)| ChallengeRef {
            scheme,
            params: opt_params.unwrap_or_default(),
        },
    )(input)
}

/// Appends the challenges described by `value` into `challenges`.
///
/// This can be used to parse `Proxy-Authenticate` and/or `WWW-Authenticate` header values.
///
/// ```text
///   Proxy-Authenticate = *( "," OWS ) challenge *( OWS "," [ OWS
///    challenge ] )
///
///   WWW-Authenticate = *( "," OWS ) challenge *( OWS "," [ OWS challenge
///    ] )
/// ```
pub fn challenges(input: &str) -> nom::IResult<&str, Vec<ChallengeRef>> {
    all_consuming(list1_relaxed(challenge))(input)
}

#[cfg(test)]
mod tests {
    use nom::bytes::complete::tag;
    use nom::error::{Error, ErrorKind};
    use nom::Err;

    use super::*;

    #[test]
    fn test_quoted_string() {
        assert_eq!(
            quoted_string(&r#""foo""#),
            Ok(("", ParamValue::new(0, "foo")))
        );
        assert_eq!(
            quoted_string(&r#""foo bar""#),
            Ok(("", ParamValue::new(0, "foo bar")))
        );
        assert_eq!(
            quoted_string(&r#""foo \" bar""#),
            Ok(("", ParamValue::new(1, r#"foo \" bar"#))),
        );
        assert_eq!(quoted_string(r#""""#), Ok(("", ParamValue::new(0, ""))));
    }

    #[test]
    fn test_challenges() {
        assert_eq!(
            challenges(r#"Scheme foo="blah \" blah""#),
            Ok((
                "",
                vec![ChallengeRef {
                    scheme: "Scheme",
                    params: vec![("foo", ParamValue::new(1, "blah \\\" blah"),)],
                }]
            ))
        );
    }

    #[test]
    fn test_list1() {
        assert_eq!(
            list1_relaxed(token)("foo,bar"),
            Ok(("", vec!["foo", "bar"]))
        );
        assert_eq!(
            list1_relaxed(token)("foo ,bar"),
            Ok(("", vec!["foo", "bar"]))
        );
        assert_eq!(
            list1_relaxed(token)("foo ,bar, charlie   "),
            Ok(("   ", vec!["foo", "bar", "charlie"]))
        );
        assert_eq!(
            list1_relaxed(token)(""),
            Err(Err::Error(Error::new("", ErrorKind::IsA)))
        );
        assert_eq!(
            list1_relaxed(token)(","),
            Err(Err::Error(Error::new("", ErrorKind::IsA)))
        );
        assert_eq!(
            list1_relaxed(token)(",  ,"),
            Err(Err::Error(Error::new("", ErrorKind::IsA)))
        );
    }

    #[test]
    fn test_2level_list1() {
        let foo_bar_list = preceded(tag("foo "), list1_relaxed_inner(tag("bar")));
        assert_eq!(
            list1_relaxed(foo_bar_list)(", foo bar,bar, foo bar,"),
            Ok(("", vec![vec!["bar", "bar"], vec!["bar"]]))
        );
    }

    #[test]
    fn test_list0() {
        assert_eq!(
            list0_relaxed(token)("foo,bar"),
            Ok(("", vec!["foo", "bar"]))
        );
        assert_eq!(
            list0_relaxed(token)("foo ,bar"),
            Ok(("", vec!["foo", "bar"]))
        );
        assert_eq!(
            list0_relaxed(token)("foo ,bar, charlie   "),
            Ok(("   ", vec!["foo", "bar", "charlie"]))
        );
        assert_eq!(list0_relaxed(token)(""), Ok(("", vec![])));
        assert_eq!(list0_relaxed(token)(","), Ok(("", vec![])));
        assert_eq!(list0_relaxed(token)(",  ,"), Ok(("", vec![])));
    }
}
