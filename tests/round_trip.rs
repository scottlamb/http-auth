// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every Digest option combination, and Basic, through this crate's client
//! and server.

#![cfg(all(
    feature = "server",
    feature = "digest-scheme",
    feature = "basic-scheme"
))]

use std::convert::TryFrom;
use std::time::SystemTime;

use http_auth::basic::{BasicClient, BasicCredentials, BasicServer};
use http_auth::digest::{
    Algorithm, DigestClient, DigestResponse, DigestServer, Qop, QopSet, Request, Secret,
};
use http_auth::server::ServerError;
use http_auth::{parse_challenges, PasswordParams};

/// xorshift64*.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn word(&mut self, pieces: &[&str]) -> String {
        let n = 1 + self.next() % 8;
        (0..n)
            .map(|_| pieces[(self.next() % pieces.len() as u64) as usize])
            .collect()
    }
}

const ASCII: &[&str] = &["a", "Z", "0", " ", "\"", "\\", ":", "@", "%", "'", ","];
const ANY: &[&str] = &[
    "a", "Z", "0", " ", "\"", "\\", ":", "@", "%", "'", "ä", "α", "😀",
];

#[rustfmt::skip]
fn check(rng: &mut Rng, algorithm: Algorithm, session: bool, qop: QopSet, userhash: bool, body: Option<&[u8]>) {
    let now = SystemTime::now();
    let realm = rng.word(ASCII);
    let username = rng.word(ANY);
    let password = rng.word(ANY);
    let ctx = format!("{:?} s={} q={:?} uh={} body={:?}", algorithm, session, qop, userhash, body);
    let server = DigestServer::builder(realm.clone())
        .algorithms(&[algorithm]).session(session).qop(qop).userhash(userhash).opaque("op").build().unwrap();
    let challenge = server.challenges(false, now)[0].as_str().to_owned();
    assert_eq!(challenge.contains("userhash=true"), userhash, "{}", ctx);
    let mut client = DigestClient::try_from(&parse_challenges(&challenge).unwrap()[0]).unwrap();
    let header = client.respond(&PasswordParams { username: &username, password: &password, uri: "/x?y=1", method: "POST", body }).unwrap();
    assert_eq!(header.contains("userhash=true"), userhash, "{}", ctx);
    if !userhash && !username.is_ascii() {
        assert!(header.contains("username*="), "{} {:?}", ctx, header);
    }
    let request = Request { method: "POST", uri: "/x?y=1", body };
    let response = server.check_nonce(DigestResponse::parse(&header).expect(&ctx), now).expect(&ctx);
    let pw = Secret::Password { username: &username, password: &password };
    assert_eq!(server.verify(&response, request, pw), Ok(()), "{}", ctx);
    assert_eq!(server.verify(&response, request, Secret::Ha1(&algorithm.ha1(&username, &realm, &password))), Ok(()), "{}", ctx);
    for (request, secret) in [
        (request, Secret::Password { username: &username, password: "wrong" }),
        (request, Secret::Password { username: "wrong", password: &password }),
        (Request { method: "PUT", uri: "/x?y=1", body }, pw),
    ] {
        assert_eq!(server.verify(&response, request, secret), Err(ServerError::BadCredentials), "{}", ctx);
    }
    if response.qop() == Qop::AuthInt {
        let tampered = Request { method: "POST", uri: "/x?y=1", body: Some(&b"tampered"[..]) };
        assert_eq!(server.verify(&response, tampered, pw), Err(ServerError::BadCredentials), "{}", ctx);
    }
}

#[test]
fn digest_matrix() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for algorithm in [Algorithm::Md5, Algorithm::Sha256, Algorithm::Sha512Trunc256] {
        for session in [false, true] {
            for qop in [
                QopSet::from(Qop::Auth),
                QopSet::from(Qop::AuthInt),
                Qop::Auth | Qop::AuthInt,
            ] {
                for userhash in [false, true] {
                    for body in [None, Some(&b"hello"[..])] {
                        if body.is_none() && qop == QopSet::from(Qop::AuthInt) {
                            continue;
                        }
                        for _ in 0..4 {
                            check(&mut rng, algorithm, session, qop, userhash, body);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn basic_round_trip() {
    let mut rng = Rng(42);
    for _ in 0..200 {
        let username = rng.word(&["a", "Z", "0", " ", "\"", "@", "\u{e4}", "\u{1f600}"]); // no ':'
        let password = rng.word(ANY);
        let server = BasicServer::new(rng.word(ASCII))
            .unwrap()
            .charset_utf8(true);
        let challenge = server.challenge();
        let parsed = parse_challenges(challenge.as_str()).unwrap();
        let client = BasicClient::try_from(&parsed[0]).unwrap();
        let creds = BasicCredentials::parse(&client.respond(&username, &password)).unwrap();
        assert_eq!(
            (creds.username(), creds.password()),
            (&username[..], &password[..])
        );
    }
}
