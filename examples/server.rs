// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A hyper server protecting `/basic` with `Basic` and `/digest` with
//! `Digest`.
//!
//! ```text
//! cargo run --example server --features server,http10
//! curl --basic  -u aladdin:"open sesame" http://127.0.0.1:8080/basic
//! curl --digest -u mufasa:"Circle of Life" http://127.0.0.1:8080/digest
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
    let authorization = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let (status, challenges) = match (req.uri().path(), authorization) {
        ("/basic", Some(a)) => verify_basic(&servers.basic, a),
        ("/basic", None) => (StatusCode::UNAUTHORIZED, vec![servers.basic.clone()]),
        ("/digest", Some(a)) => verify_digest(&servers.digest, a, &req),
        ("/digest", None) => (
            StatusCode::UNAUTHORIZED,
            to_header_values(servers.digest.challenges(false, SystemTime::now())),
        ),
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

fn verify_basic(challenge: &HeaderValue, header: &str) -> (StatusCode, Vec<HeaderValue>) {
    let outcome = basic::Credentials::parse(header).and_then(|c| {
        if c.username() == "aladdin" && c.verify_password("open sesame") {
            Ok(())
        } else {
            Err(ServerError::BadCredentials)
        }
    });
    match outcome {
        Ok(()) => (StatusCode::OK, vec![]),
        Err(e) => (e.status_code(), vec![challenge.clone()]),
    }
}

/// Looks up a user's secret; `None` if there's no such user.
fn lookup(username: digest::Username<'_>) -> Option<Secret<'static>> {
    match username {
        digest::Username::Plain("mufasa") => Some(Secret::Password {
            username: "mufasa",
            password: "Circle of Life",
        }),
        _ => None,
    }
}

fn verify_digest(
    server: &digest::Server,
    header: &str,
    req: &Request<Incoming>,
) -> (StatusCode, Vec<HeaderValue>) {
    let now = SystemTime::now();
    let outcome = digest::CredentialsRef::parse(header).and_then(|r| {
        let r = server.check_nonce(r, now)?;
        server.verify(&r, req.into(), lookup(r.username()))
    });
    match outcome {
        Ok(()) => (StatusCode::OK, vec![]),
        Err(ServerError::Stale) => (
            StatusCode::UNAUTHORIZED,
            to_header_values(server.challenges(true, now)),
        ),
        Err(e) => (
            e.status_code(),
            to_header_values(server.challenges(false, now)),
        ),
    }
}
