// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `Bearer` challenges and credentials against RFC 6750 and RFC 9728.

#![cfg(feature = "server")]

use http_auth::bearer::{ChallengeBuilder, Credentials, ErrorCode};

fn params(header: &str) -> Vec<(String, String)> {
    let c = http_auth::parse_challenges(header).unwrap();
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].scheme(), "Bearer");
    match c[0].body() {
        http_auth::AuthBodyRef::Params(p) => p
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_unescaped().into_owned()))
            .collect(),
        http_auth::AuthBodyRef::Token68(_) => panic!("token68 body"),
    }
}

#[test]
fn rfc6750_examples() {
    let c = ChallengeBuilder::new().realm("example").build().unwrap();
    assert_eq!(c.as_str(), r#"Bearer realm="example""#);
    let c = ChallengeBuilder::new()
        .realm("example")
        .error(ErrorCode::InvalidToken)
        .error_description("The access token expired")
        .build()
        .unwrap();
    assert_eq!(
        c.as_str(),
        r#"Bearer realm="example", error="invalid_token", error_description="The access token expired""#
    );
}

#[test]
fn rfc9728_example() {
    let c = ChallengeBuilder::new()
        .resource_metadata("https://resource.example.com/.well-known/oauth-protected-resource")
        .build()
        .unwrap();
    assert_eq!(
        c.as_str(),
        r#"Bearer resource_metadata="https://resource.example.com/.well-known/oauth-protected-resource""#
    );
}

#[test]
fn round_trip() {
    let c = ChallengeBuilder::new()
        .realm("zen \"ith\" \\")
        .scope("live:read vod:read")
        .error(ErrorCode::InsufficientScope)
        .error_description("need vod:read")
        .error_uri("https://example.com/e")
        .resource_metadata("https://example.com/.well-known/oauth-protected-resource")
        .build()
        .unwrap();
    assert_eq!(
        params(c.as_str()),
        vec![
            ("realm".to_owned(), "zen \"ith\" \\".to_owned()),
            ("scope".to_owned(), "live:read vod:read".to_owned()),
            ("error".to_owned(), "insufficient_scope".to_owned()),
            ("error_description".to_owned(), "need vod:read".to_owned()),
            ("error_uri".to_owned(), "https://example.com/e".to_owned()),
            (
                "resource_metadata".to_owned(),
                "https://example.com/.well-known/oauth-protected-resource".to_owned()
            ),
        ]
    );
    let c = ChallengeBuilder::new()
        .error(ErrorCode::InvalidRequest)
        .build()
        .unwrap();
    assert_eq!(
        params(c.as_str()),
        vec![("error".to_owned(), "invalid_request".to_owned())]
    );
    assert_eq!(ChallengeBuilder::new().build().unwrap().as_str(), "Bearer");
}

#[test]
fn rejects_invalid_values() {
    assert!(ChallengeBuilder::new().realm("a\nb").build().is_err());
    assert!(ChallengeBuilder::new()
        .error_description("say \"hi\"")
        .build()
        .is_err());
    assert!(ChallengeBuilder::new()
        .error_description("back\\slash")
        .build()
        .is_err());
    assert!(ChallengeBuilder::new()
        .error_description("tab\there")
        .build()
        .is_err());
    assert!(ChallengeBuilder::new().error_uri("a\"b").build().is_err());
    assert!(ChallengeBuilder::new().scope("a  b").build().is_err());
    assert!(ChallengeBuilder::new().scope(" a").build().is_err());
    assert!(ChallengeBuilder::new().scope("a ").build().is_err());
    assert!(ChallengeBuilder::new().scope("").build().is_err());
    assert!(ChallengeBuilder::new().scope("a\"b").build().is_err());
    assert!(ChallengeBuilder::new().scope("caf\u{e9}").build().is_err());
    assert!(ChallengeBuilder::new()
        .resource_metadata("x\"y")
        .build()
        .is_err());
    assert!(ChallengeBuilder::new().scope("a b").build().is_ok());
}

#[test]
fn error_status() {
    assert_eq!(ErrorCode::InvalidRequest.status(), 400);
    assert_eq!(ErrorCode::InvalidToken.status(), 401);
    assert_eq!(ErrorCode::InsufficientScope.status(), 403);
}

#[test]
fn credentials() {
    let c = Credentials::parse("Bearer mF_9.B5f-4.1JqM")
        .unwrap()
        .unwrap();
    assert_eq!(c.token(), "mF_9.B5f-4.1JqM");
    let c = Credentials::parse("bearer abc+/=").unwrap().unwrap();
    assert_eq!(c.token(), "abc+/=");
    let parsed = http_auth::parse_credentials("Bearer xyz").unwrap();
    assert_eq!(Credentials::parse(&parsed).unwrap().unwrap().token(), "xyz");

    assert!(Credentials::parse("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==").is_none());
    assert!(matches!(
        Credentials::parse("Bearer a=\"b\""),
        Some(Err(http_auth::ServerError::Malformed(_)))
    ));
    assert!(matches!(
        Credentials::parse("Bearer"),
        Some(Err(http_auth::ServerError::Malformed(_)))
    ));
    assert!(matches!(
        Credentials::parse("Bearer a b"),
        Some(Err(http_auth::ServerError::Malformed(_)))
    ));
}
