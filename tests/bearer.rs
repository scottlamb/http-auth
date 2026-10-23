// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `Bearer` challenges and credentials against RFC 6750 and RFC 9728.

use std::convert::TryFrom as _;

use http_auth::bearer::{self, Client};
#[cfg(feature = "server")]
use http_auth::bearer::{ChallengeBuilder, Credentials, ErrorCode};

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
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
}

#[cfg(feature = "server")]
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
    assert!(ChallengeBuilder::new().build().is_err());
    assert!(ChallengeBuilder::new()
        .error_description("")
        .build()
        .is_err());
    assert!(ChallengeBuilder::new().error_uri("a\"b").build().is_err());
    assert!(ChallengeBuilder::new()
        .error_uri("https://example.com/a b")
        .build()
        .is_err());
    assert!(ChallengeBuilder::new()
        .error_uri("/relative")
        .build()
        .is_err());
    assert!(ChallengeBuilder::new()
        .error_uri("https://example.com/%zz")
        .build()
        .is_err());
    assert!(ChallengeBuilder::new()
        .error_uri("https://[::1/")
        .build()
        .is_err());
    for ok in [
        "https://example.com/errors#invalid_token",
        "urn:example:error",
        "http://[2001:db8::1]:8080/e?x=1",
    ] {
        assert!(
            ChallengeBuilder::new().error_uri(ok).build().is_ok(),
            "{}",
            ok
        );
    }
    assert!(ChallengeBuilder::new().scope("a  b").build().is_err());
    assert!(ChallengeBuilder::new().scope(" a").build().is_err());
    assert!(ChallengeBuilder::new().scope("a ").build().is_err());
    assert!(ChallengeBuilder::new().scope("").build().is_err());
    assert!(ChallengeBuilder::new().scope("a\"b").build().is_err());
    assert!(ChallengeBuilder::new().scope("caf\u{e9}").build().is_err());
    for bad in [
        "x\"y",
        "http://example.com/.well-known/oauth-protected-resource",
        "https://example.com/.well-known/oauth-protected-resource#f",
        "https:///no-host",
        "/.well-known/oauth-protected-resource",
    ] {
        assert!(
            ChallengeBuilder::new()
                .resource_metadata(bad)
                .build()
                .is_err(),
            "{}",
            bad
        );
    }
    for ok in [
        "https://example.com/.well-known/oauth-protected-resource",
        "HTTPS://[::1]:8443/.well-known/oauth-protected-resource/api?x=1",
    ] {
        assert!(
            ChallengeBuilder::new()
                .resource_metadata(ok)
                .build()
                .is_ok(),
            "{}",
            ok
        );
    }
    assert!(ChallengeBuilder::new().scope("a b").build().is_ok());
}

#[cfg(feature = "server")]
#[test]
fn error_status() {
    assert_eq!(ErrorCode::InvalidRequest.status(), 400);
    assert_eq!(ErrorCode::InvalidToken.status(), 401);
    assert_eq!(ErrorCode::InsufficientScope.status(), 403);
}

#[cfg(feature = "server")]
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

fn client(header: &str) -> Client {
    let c = http_auth::parse_challenges(header).unwrap();
    assert_eq!(c.len(), 1);
    Client::try_from(&c[0]).unwrap()
}

#[test]
fn client_rfc6750_example() {
    let c = client(
        r#"Bearer realm="example", error="invalid_token", error_description="The access token expired""#,
    );
    assert_eq!(c.realm(), Some("example"));
    assert_eq!(c.error(), Some("invalid_token"));
    assert_eq!(c.error_description(), Some("The access token expired"));
    assert_eq!(c.scope(), None);
    assert_eq!(c.error_uri(), None);
    assert_eq!(c.resource_metadata(), None);
}

#[test]
fn client_rfc9728_example() {
    let c = client(
        r#"Bearer resource_metadata="https://resource.example.com/.well-known/oauth-protected-resource""#,
    );
    assert_eq!(
        c.resource_metadata(),
        Some("https://resource.example.com/.well-known/oauth-protected-resource")
    );
    assert_eq!(c.realm(), None);
}

#[test]
fn client_parsing() {
    let c = client(r#"Bearer REALM="a\"b", Scope=x, error=use_dpop_nonce, other="ignored""#);
    assert_eq!(c.realm(), Some("a\"b"));
    assert_eq!(c.scope(), Some("x"));
    assert_eq!(c.error(), Some("use_dpop_nonce"));

    let wrong = http_auth::parse_challenges(r#"Basic realm="x""#).unwrap();
    assert!(Client::try_from(&wrong[0]).is_err());
    for bad in [
        "Bearer",
        "Bearer abc=",
        r#"Bearer realm="a", realm="b""#,
        r#"Bearer scope="a", Scope="b""#,
        r#"Bearer error="a", error="b""#,
        r#"Bearer error_description="a", error_description="b""#,
        r#"Bearer error_uri="https://a/", error_uri="https://b/""#,
        r#"Bearer resource_metadata="https://a/", resource_metadata="https://b/""#,
        r#"Bearer scope="a  b""#,
        r#"Bearer error="""#,
        r#"Bearer error_description="""#,
        r#"Bearer error="\\x""#,
        r#"Bearer error_uri="relative""#,
        r#"Bearer resource_metadata="http://example.com/m""#,
    ] {
        let c = http_auth::parse_challenges(bad).unwrap();
        assert!(Client::try_from(&c[0]).is_err(), "{}", bad);
    }
}

#[test]
fn client_respond() {
    let c = client(r#"Bearer realm="example""#);
    assert_eq!(
        c.respond("mF_9.B5f-4.1JqM").unwrap(),
        "Bearer mF_9.B5f-4.1JqM"
    );
    assert_eq!(
        bearer::encode_credentials("abc+/==").unwrap(),
        "Bearer abc+/=="
    );
    for bad in ["", "a b", "a\r\nX: y", "=abc", "a=b", "caf\u{e9}", "a\"b"] {
        assert!(bearer::encode_credentials(bad).is_err(), "{:?}", bad);
        assert!(c.respond(bad).is_err(), "{:?}", bad);
    }
}

#[cfg(feature = "server")]
#[test]
fn client_server_round_trip() {
    let header = ChallengeBuilder::new()
        .realm("zen \"ith\" \\")
        .scope("live:read vod:read")
        .error(ErrorCode::InsufficientScope)
        .error_description("need vod:read")
        .error_uri("https://example.com/e")
        .resource_metadata("https://example.com/.well-known/oauth-protected-resource")
        .build()
        .unwrap();
    let c = client(header.as_str());
    assert_eq!(c.realm(), Some("zen \"ith\" \\"));
    assert_eq!(c.scope(), Some("live:read vod:read"));
    assert_eq!(c.error(), Some(ErrorCode::InsufficientScope.as_str()));
    assert_eq!(c.error_description(), Some("need vod:read"));
    assert_eq!(c.error_uri(), Some("https://example.com/e"));
    assert_eq!(
        c.resource_metadata(),
        Some("https://example.com/.well-known/oauth-protected-resource")
    );

    for token in ["mF_9.B5f-4.1JqM", "abc+/==", "x"] {
        let header = c.respond(token).unwrap();
        let creds = Credentials::parse(header.as_str()).unwrap().unwrap();
        assert_eq!(creds.token(), token);
    }
}
