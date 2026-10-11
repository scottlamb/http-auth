// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A hyper server protecting `/basic` with `Basic` and `/digest` with
//! `Digest`.
//!
//! ```text
//! cargo run --example server --features server
//! curl --basic  -u aladdin:"open sesame" http://127.0.0.1:8080/basic
//! curl --digest -u mufasa:"Circle of Life" http://127.0.0.1:8080/digest
//! ```

use std::convert::Infallible;
use std::sync::Arc;
use std::time::SystemTime;

use http_auth::basic::{BasicCredentials, BasicServer};
use http_auth::digest::{Algorithm, DigestResponse, DigestServer, Secret};
use http_auth::server::{Challenge, ServerError};
use http_body_util::Empty;
use hyper::body::{Bytes, Incoming};
use hyper::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;

const BIND: &str = "127.0.0.1:8080";

struct Servers {
    basic: BasicServer,
    digest: DigestServer,
}

fn main() {
    let servers = Arc::new(Servers {
        basic: BasicServer::new("WallyWorld").unwrap(),
        digest: DigestServer::builder("http-auth@example.org")
            .algorithms(&[Algorithm::Sha256, Algorithm::Md5])
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
    let uri = req.uri().path_and_query().map_or("/", |p| p.as_str());
    let (status, challenges) = match (req.uri().path(), authorization) {
        ("/basic", Some(a)) => verify_basic(&servers.basic, a),
        ("/basic", None) => (401, vec![servers.basic.challenge()]),
        ("/digest", Some(a)) => verify_digest(&servers.digest, a, req.method().as_str(), uri),
        ("/digest", None) => (401, servers.digest.challenges(false, SystemTime::now())),
        _ => (404, vec![]),
    };
    let mut resp = Response::builder().status(status);
    for c in &challenges {
        resp = resp.header(WWW_AUTHENTICATE, c.as_str());
    }
    resp.body(Empty::new()).unwrap()
}

fn verify_basic(server: &BasicServer, header: &str) -> (u16, Vec<Challenge>) {
    let outcome = BasicCredentials::parse(header).and_then(|c| {
        if c.username() == "aladdin" && c.verify_password("open sesame") {
            Ok(())
        } else {
            Err(ServerError::BadCredentials)
        }
    });
    match outcome {
        Ok(()) => (200, vec![]),
        Err(e) => (e.status(), vec![server.challenge()]),
    }
}

fn verify_digest(
    server: &DigestServer,
    header: &str,
    method: &str,
    uri: &str,
) -> (u16, Vec<Challenge>) {
    let now = SystemTime::now();
    let outcome = DigestResponse::parse(header).and_then(|r| {
        let r = server.check_nonce(r, now)?;
        server.verify(
            &r,
            http_auth::digest::Request {
                method,
                uri,
                body: None,
            },
            Secret::Password {
                username: "mufasa",
                password: "Circle of Life",
            },
        )
    });
    match outcome {
        Ok(()) => (200, vec![]),
        Err(ServerError::Stale) => (401, server.challenges(true, now)),
        Err(e) => (e.status(), server.challenges(false, now)),
    }
}
