// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

// Feeds arbitrary input through Digest response parsing and verification;
// must never panic:
// $ cargo +nightly fuzz run digest_response

#![no_main]
use libfuzzer_sys::fuzz_target;

use http_auth::digest::{self, Algorithm, Ha1, Qop, Request, Secret};

fuzz_target!(|data: &str| {
    let Ok(r) = digest::CredentialsRef::parse(data) else {
        return;
    };
    let server = digest::Server::builder("r", &[Algorithm::Md5, Algorithm::Sha256])
        .qop(Qop::Auth | Qop::AuthInt)
        .userhash(true)
        .nonce_key([0; 32])
        .build()
        .unwrap();
    let _ = server.check_nonce(r, std::time::SystemTime::now());
    let Ok(r) = digest::CredentialsRef::parse(data) else {
        return;
    };
    let r = r.nonce_checked_externally();
    let req = Request {
        method: "GET",
        uri: r.uri(),
        body: Some(b""),
    };
    let _ = server.verify(
        &r,
        req,
        Secret::Password {
            username: "u",
            password: "p",
        },
    );
    let ha1 = Ha1::from_hex(Algorithm::Md5, "00000000000000000000000000000000").unwrap();
    let _ = server.verify(&r, req, Secret::Ha1(&ha1));
});
