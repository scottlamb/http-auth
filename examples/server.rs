// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A `std::net` server protecting `/basic` with `Basic` and `/digest` with
//! `Digest`.
//!
//! ```text
//! cargo run --example server --features server
//! curl --basic  -u aladdin:"open sesame" http://127.0.0.1:8080/basic
//! curl --digest -u mufasa:"Circle of Life" http://127.0.0.1:8080/digest
//! ```

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::SystemTime;

use http_auth::basic::{BasicCredentials, BasicServer};
use http_auth::digest::{Algorithm, DigestResponse, DigestServer, Request, Secret};
use http_auth::server::{Challenge, ServerError};

const BIND: &str = "127.0.0.1:8080";

fn main() {
    let basic = BasicServer::new("WallyWorld").unwrap();
    let digest = DigestServer::builder("http-auth@example.org")
        .algorithms(&[Algorithm::Sha256, Algorithm::Md5])
        .build()
        .unwrap();
    let listener = TcpListener::bind(BIND).unwrap();
    println!("listening on http://{}/", BIND);
    for stream in listener.incoming().flatten() {
        if let Err(e) = handle(stream, &basic, &digest) {
            eprintln!("connection error: {}", e);
        }
    }
}

fn handle(
    mut stream: TcpStream,
    basic: &BasicServer,
    digest: &DigestServer,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_owned();
    let uri = parts.next().unwrap_or("/").to_owned();
    let mut authorization = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("authorization") {
                authorization = Some(value.trim().to_owned());
            }
        }
    }

    let (status, challenges) = match (uri.as_str(), authorization.as_deref()) {
        ("/basic", Some(a)) => verify_basic(basic, a),
        ("/basic", None) => (401, vec![basic.challenge()]),
        ("/digest", Some(a)) => verify_digest(digest, a, &method, &uri),
        ("/digest", None) => (401, digest.challenges(false, SystemTime::now())),
        _ => (404, vec![]),
    };

    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    let mut out = format!("HTTP/1.1 {} {}\r\n", status, reason);
    for c in &challenges {
        out.push_str(&format!("WWW-Authenticate: {}\r\n", c));
    }
    out.push_str("Content-Length: 0\r\n\r\n");
    stream.write_all(out.as_bytes())
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
            Request {
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
