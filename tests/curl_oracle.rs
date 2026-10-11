// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Uses `curl` as an independent client against this crate's servers over
//! HTTP and RTSP. Skipped if `curl` is missing, unless
//! `HTTP_AUTH_REQUIRE_CURL` is set.
//!
//! curl hashes an empty body for `auth-int`, so `auth-int` is tested with
//! empty bodies only.

#![cfg(all(
    feature = "server",
    feature = "digest-scheme",
    feature = "basic-scheme"
))]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use http_auth::basic::{BasicCredentials, BasicServer};
use http_auth::digest::{
    Algorithm, DigestResponse, DigestServer, DigestServerBuilder, Qop, Request, Secret, Username,
};
use http_auth::server::{Challenge, ServerError};

const REALM: &str = "http-auth@example.org";

enum Scheme {
    Digest(DigestServer),
    Basic(BasicServer),
}

struct Config {
    scheme: Scheme,
    username: &'static str,
    password: &'static str,
    use_ha1: bool,
    issue_stale_first: bool,
}

impl Config {
    fn digest(server: DigestServer) -> Self {
        Config {
            scheme: Scheme::Digest(server),
            username: "Mufasa",
            password: "Circle of Life",
            use_ha1: false,
            issue_stale_first: false,
        }
    }
}

#[derive(Debug, Default)]
struct Log {
    requests: usize,
    outcomes: Vec<Result<(), ServerError>>,
    algorithms: Vec<Algorithm>,
    sessions: Vec<bool>,
    userhashes: Vec<bool>,
    qops: Vec<Qop>,
    uris: Vec<String>,
}

fn spawn(config: Config) -> (u16, Arc<Mutex<Log>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Log::default()));
    let thread_log = Arc::clone(&log);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            handle(stream, &config, &thread_log);
        }
    });
    (port, log)
}

#[rustfmt::skip]
fn handle(stream: TcpStream, config: &Config, log: &Mutex<Log>) {
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut stream = stream;
    loop {
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).unwrap_or(0) == 0 { return; }
        let mut parts = request_line.trim_end().splitn(3, ' ');
        let method = parts.next().unwrap_or("").to_owned();
        let uri = parts.next().unwrap_or("").to_owned();
        let proto = if parts.next().unwrap_or("").starts_with("RTSP") { "RTSP/1.0" } else { "HTTP/1.1" };
        let (mut authorization, mut cseq, mut content_length) = (None, None, 0usize);
        loop {
            let mut raw = Vec::new();
            if reader.read_until(b'\n', &mut raw).unwrap_or(0) == 0 || raw == b"\r\n" { break; }
            let line = String::from_utf8_lossy(&raw).trim_end().to_owned();
            if let Some((name, value)) = line.split_once(':') {
                let value = value.trim().to_owned();
                match name.to_ascii_lowercase().as_str() {
                    "authorization" => authorization = Some(value),
                    "cseq" => cseq = Some(value),
                    "content-length" => content_length = value.parse().unwrap_or(0),
                    _ => {}
                }
            }
        }
        let mut body = vec![0; content_length];
        if reader.read_exact(&mut body).is_err() { return; }
        let (status, challenges) = respond(config, log, &method, &uri, authorization.as_deref(), &body);
        let reason = match status { 200 => "OK", 400 => "Bad Request", 401 => "Unauthorized", _ => "Internal Server Error" };
        let mut out = format!("{} {} {}\r\n", proto, status, reason);
        if let Some(c) = &cseq { out += &format!("CSeq: {}\r\n", c); }
        for c in challenges { out += &format!("WWW-Authenticate: {}\r\n", c); }
        out += "Content-Length: 0\r\n\r\n";
        if stream.write_all(out.as_bytes()).is_err() { return; }
    }
}

#[rustfmt::skip]
fn respond(config: &Config, log: &Mutex<Log>, method: &str, uri: &str, authorization: Option<&str>, body: &[u8]) -> (u16, Vec<Challenge>) {
    let mut log = log.lock().unwrap();
    log.requests += 1;
    let now = SystemTime::now();
    match &config.scheme {
        Scheme::Basic(server) => {
            let a = match authorization {
                Some(a) => a,
                None => return (401, vec![server.challenge()]),
            };
            let outcome = BasicCredentials::parse(a).and_then(|c| {
                if c.username() == config.username && c.verify_password(config.password) { Ok(()) } else { Err(ServerError::BadCredentials) }
            });
            log.outcomes.push(outcome);
            match outcome {
                Ok(()) => (200, vec![]),
                Err(e) => (e.status(), vec![server.challenge()]),
            }
        }
        Scheme::Digest(server) => {
            let a = match authorization {
                Some(a) => a,
                None => {
                    let issued = if config.issue_stale_first && log.requests == 1 { now - Duration::from_secs(3600) } else { now };
                    return (401, server.challenges(false, issued));
                }
            };
            let outcome = DigestResponse::parse(a).and_then(|r| {
                log.algorithms.push(r.algorithm());
                log.sessions.push(r.session());
                log.userhashes.push(matches!(r.username(), Username::Hashed(_)));
                log.qops.push(r.qop());
                log.uris.push(r.uri().to_owned());
                let r = server.check_nonce(r, now)?;
                let ha1 = r.algorithm().ha1(config.username, REALM, config.password);
                let secret = if config.use_ha1 { Secret::Ha1(&ha1) } else { Secret::Password { username: config.username, password: config.password } };
                server.verify(&r, Request { method, uri, body: Some(body) }, secret)
            });
            log.outcomes.push(outcome);
            match outcome {
                Ok(()) => (200, vec![]),
                Err(ServerError::Stale) => (401, server.challenges(true, now)),
                Err(e) => (e.status(), server.challenges(false, now)),
            }
        }
    }
}

fn curl_version() -> Option<(u32, u32)> {
    let out = Command::new("curl").arg("--version").output().ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut parts = stdout.split_whitespace().nth(1)?.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

fn curl_version_or_skip() -> Option<(u32, u32)> {
    let version = curl_version();
    if version.is_none() {
        if std::env::var_os("HTTP_AUTH_REQUIRE_CURL").is_some() {
            panic!("HTTP_AUTH_REQUIRE_CURL is set but curl was not found");
        }
        eprintln!("skipping: curl not found");
    }
    version
}
fn curl(args: &[&str]) -> u16 {
    let out = Command::new("curl")
        .args(["-q", "-s", "-o", "/dev/null", "-w", "%{response_code}"])
        .args(["--noproxy", "*", "--max-time", "10"])
        .args(args)
        .output()
        .unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn run_digest(config: Config, user_pass: &str) -> (u16, Arc<Mutex<Log>>) {
    let (port, log) = spawn(config);
    let url = format!("http://127.0.0.1:{}/dir/index.html?x=1", port);
    (curl(&["--digest", "-u", user_pass, &url]), log)
}

fn server(algorithms: &[Algorithm]) -> DigestServerBuilder {
    DigestServer::builder(REALM)
        .algorithms(algorithms)
        .opaque("opaque-value")
}

#[rustfmt::skip]
#[test]
fn digest_algorithms() {
    let Some(version) = curl_version_or_skip() else { return; };
    // curl before 8.7.0 computed SHA-512-256 digests with SHA-256 (fixed in curl commit e3461bbd0).
    let mut algorithms = vec![Algorithm::Md5, Algorithm::Sha256];
    if version >= (8, 7) { algorithms.push(Algorithm::Sha512Trunc256); }
    for algorithm in &algorithms {
        for session in [false, true] {
            let s = server(&[*algorithm]).session(session).build().unwrap();
            let (status, log) = run_digest(Config::digest(s), "Mufasa:Circle of Life");
            let log = log.lock().unwrap();
            assert_eq!(status, 200, "{:?} session={}: {:?}", algorithm, session, log);
            assert_eq!(log.algorithms, vec![*algorithm]);
            assert_eq!(log.sessions, vec![session]);
        }
    }
    for order in [&[Algorithm::Sha256, Algorithm::Md5][..], &[Algorithm::Md5, Algorithm::Sha256][..]] {
        let (status, log) = run_digest(Config::digest(server(order).build().unwrap()), "Mufasa:Circle of Life");
        assert_eq!(status, 200);
        assert_eq!(log.lock().unwrap().algorithms, vec![order[0]]);
    }
}

#[test]
fn digest_options() {
    let Some(_) = curl_version_or_skip() else {
        return;
    };
    fn bad_credentials(log: &Log) {
        assert_eq!(log.outcomes, vec![Err(ServerError::BadCredentials)]);
    }
    fn userhash(log: &Log) {
        assert_eq!(log.userhashes, vec![true]);
    }
    fn auth_int(log: &Log) {
        assert_eq!(log.qops, vec![Qop::AuthInt]);
    }
    #[rustfmt::skip]
    type Case = (DigestServerBuilder, &'static str, bool, u16, Option<fn(&Log)>);
    #[rustfmt::skip]
    let cases: [Case; 5] = [
        (server(&[Algorithm::Sha256]), "Mufasa:nope", false, 401, Some(bad_credentials)),
        (server(&[Algorithm::Sha256]), "Mufasa:Circle of Life", true, 200, None),
        (server(&[Algorithm::Sha256]).userhash(true), "Mufasa:Circle of Life", false, 200, Some(userhash)),
        (server(&[Algorithm::Md5]).qop(Qop::AuthInt.into()), "Mufasa:Circle of Life", false, 200, Some(auth_int)),
        (DigestServer::builder(r#"a "quoted" \ realm"#), "Mufasa:Circle of Life", false, 200, None),
    ];
    for (builder, user_pass, use_ha1, expected_status, check) in cases {
        let mut config = Config::digest(builder.build().unwrap());
        config.use_ha1 = use_ha1;
        let (status, log) = run_digest(config, user_pass);
        assert_eq!(status, expected_status, "{}", user_pass);
        if let Some(check) = check {
            check(&log.lock().unwrap());
        }
    }
}

#[test]
fn digest_stale_retry() {
    let Some(_) = curl_version_or_skip() else {
        return;
    };
    let mut config = Config::digest(server(&[Algorithm::Sha256]).build().unwrap());
    config.issue_stale_first = true;
    let (status, log) = run_digest(config, "Mufasa:Circle of Life");
    let log = log.lock().unwrap();
    assert_eq!(status, 200, "{:?}", log);
    assert_eq!(log.requests, 3);
    assert_eq!(log.outcomes, vec![Err(ServerError::Stale), Ok(())]);
}

#[test]
fn digest_raw_non_ascii_username_rejected() {
    let Some(_) = curl_version_or_skip() else {
        return;
    };
    let (status, log) = run_digest(
        Config::digest(server(&[Algorithm::Md5]).build().unwrap()),
        "J\u{e4}s\u{f8}n:pw",
    );
    assert_eq!(status, 400);
    #[rustfmt::skip]
    assert_eq!(log.lock().unwrap().outcomes, vec![Err(ServerError::Malformed("invalid credentials syntax"))]);
}

#[test]
fn rtsp_digest() {
    let Some(_) = curl_version_or_skip() else {
        return;
    };
    let (port, log) = spawn(Config::digest(server(&[Algorithm::Md5]).build().unwrap()));
    let status = curl(&[
        "--digest",
        "-u",
        "Mufasa:Circle of Life",
        &format!("rtsp://127.0.0.1:{}/cam", port),
    ]);
    let log = log.lock().unwrap();
    assert_eq!(status, 200, "{:?}", log);
    assert_eq!(log.uris, vec!["*".to_owned()]);
}

#[rustfmt::skip]
#[test]
fn basic() {
    let Some(_) = curl_version_or_skip() else { return; };
    for (user_pass, username, password, expected) in [
        ("Aladdin:open sesame", "Aladdin", "open sesame", 200),
        ("Aladdin:wrong", "Aladdin", "open sesame", 401),
        ("test:123\u{a3}", "test", "123\u{a3}", 200),
    ] {
        let (port, _log) = spawn(Config { scheme: Scheme::Basic(BasicServer::new("WallyWorld").unwrap().charset_utf8(true)), username, password, use_ha1: false, issue_stale_first: false });
        let url = format!("http://127.0.0.1:{}/", port);
        assert_eq!(curl(&["--basic", "-u", user_pass, &url]), expected, "{}", user_pass);
    }
}
