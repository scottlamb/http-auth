// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A hyper server protecting `/basic` with `Basic`, `/digest` with `Digest`,
//! and `/both` with either.
//!
//! ```text
//! cargo run --example server --features server,http10
//! curl --basic   -u aladdin:"open sesame" http://127.0.0.1:8080/basic
//! curl --digest  -u mufasa:"Circle of Life" http://127.0.0.1:8080/digest
//! curl --anyauth -u mufasa:"Circle of Life" http://127.0.0.1:8080/both
//! ```

use std::convert::Infallible;
use std::sync::Arc;
use std::time::SystemTime;

use http_auth::digest::{Algorithm, Secret};
use http_auth::{basic, digest, ServerError};
use http_body_util::Empty;
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderValue, AUTHORIZATION, WWW_AUTHENTICATE};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;

const BIND: &str = "127.0.0.1:8080";

struct Servers {
    /// Built once; cloning a `HeaderValue` is cheap.
    basic: HeaderValue,
    digest: digest::Server,
}

fn main() {
    let servers = Arc::new(Servers {
        basic: basic::ChallengeBuilder::new("WallyWorld")
            .build()
            .unwrap()
            .into(),
        digest: digest::Server::builder(
            "http-auth@example.org",
            &[Algorithm::Sha256, Algorithm::Md5],
        )
        .build()
        .unwrap(),
    });
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(BIND).await.unwrap();
        println!("listening on http://{}/", BIND);
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let servers = servers.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req| {
                    let resp = handle(&servers, req);
                    async move { Ok::<_, Infallible>(resp) }
                });
                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    eprintln!("connection error: {}", e);
                }
            });
        }
    });
}

fn handle(servers: &Servers, req: Request<Incoming>) -> Response<Empty<Bytes>> {
    let authorization = req.headers().get(AUTHORIZATION);
    let (status, challenges) = match req.uri().path() {
        "/basic" => verify_basic(&servers.basic, authorization),
        "/digest" => verify_digest(&servers.digest, authorization, &req),
        "/both" => verify_both(servers, authorization, &req),
        _ => (StatusCode::NOT_FOUND, vec![]),
    };
    let mut resp = Response::builder().status(status);
    for c in challenges {
        resp = resp.header(WWW_AUTHENTICATE, c);
    }
    resp.body(Empty::new()).unwrap()
}

fn to_header_values(challenges: Vec<http_auth::Challenge>) -> Vec<HeaderValue> {
    challenges.into_iter().map(HeaderValue::from).collect()
}

/// Looks up a user's password; `None` if there's no such user.
fn password(username: &str) -> Option<&'static str> {
    match username {
        "aladdin" => Some("open sesame"),
        "mufasa" => Some("Circle of Life"),
        _ => None,
    }
}

fn check_basic(c: &basic::Credentials) -> Result<(), ServerError> {
    match password(c.username()) {
        Some(p) if c.verify_password(p) => Ok(()),
        _ => Err(ServerError::BadCredentials),
    }
}

fn check_digest(
    server: &digest::Server,
    c: digest::CredentialsRef<'_>,
    req: &Request<Incoming>,
    now: SystemTime,
) -> Result<(), ServerError> {
    let c = server.check_nonce(c, now)?;
    let secret = match c.username() {
        digest::Username::Plain(username) => {
            password(username).map(|password| Secret::Password { username, password })
        }
        _ => None,
    };
    server.verify(&c, req.into(), secret)
}

// Each `verify_*` gets an `outcome` of `None` if there are no credentials of
// an accepted scheme, `Some(Err(_))` if they're rejected.

fn verify_basic(
    challenge: &HeaderValue,
    authorization: Option<&HeaderValue>,
) -> (StatusCode, Vec<HeaderValue>) {
    let outcome = authorization
        .and_then(basic::Credentials::parse)
        .map(|c| check_basic(&c?));
    let status = match outcome {
        Some(Ok(())) => return (StatusCode::OK, vec![]),
        Some(Err(e)) => e.status_code(),
        None => StatusCode::UNAUTHORIZED,
    };
    (status, vec![challenge.clone()])
}

fn verify_digest(
    server: &digest::Server,
    authorization: Option<&HeaderValue>,
    req: &Request<Incoming>,
) -> (StatusCode, Vec<HeaderValue>) {
    let now = SystemTime::now();
    let outcome = authorization
        .and_then(digest::CredentialsRef::parse)
        .map(|c| check_digest(server, c?, req, now));
    let (status, stale) = match outcome {
        Some(Ok(())) => return (StatusCode::OK, vec![]),
        Some(Err(e)) => (e.status_code(), e == ServerError::Stale),
        None => (StatusCode::UNAUTHORIZED, false),
    };
    (status, to_header_values(server.challenges(stale, now)))
}

/// Accepts either scheme, parsing the header once and dispatching on the
/// scheme the client chose.
fn verify_both(
    servers: &Servers,
    authorization: Option<&HeaderValue>,
    req: &Request<Incoming>,
) -> (StatusCode, Vec<HeaderValue>) {
    let now = SystemTime::now();
    let outcome = match authorization.map(HeaderValue::to_str) {
        None => None,
        Some(Err(_)) => Some(Err(ServerError::Malformed("invalid credentials syntax"))),
        Some(Ok(a)) => match http_auth::parse_credentials(a) {
            Err(e) => Some(Err(e.into())),
            Ok(c) => basic::Credentials::parse(&c)
                .map(|b| check_basic(&b?))
                .or_else(|| {
                    digest::CredentialsRef::parse(&c)
                        .map(|d| check_digest(&servers.digest, d?, req, now))
                }),
        },
    };
    let (status, stale) = match outcome {
        Some(Ok(())) => return (StatusCode::OK, vec![]),
        Some(Err(e)) => (e.status_code(), e == ServerError::Stale),
        None => (StatusCode::UNAUTHORIZED, false),
    };
    // Offer both schemes; clients pick the strongest they support.
    let mut challenges = to_header_values(servers.digest.challenges(stale, now));
    challenges.push(servers.basic.clone());
    (status, challenges)
}
