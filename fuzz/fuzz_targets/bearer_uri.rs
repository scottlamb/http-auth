// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

// Differential: http-auth's URI validator vs iri-string (RFC 3986 `URI`):
// $ cargo +nightly fuzz run bearer_uri

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = env_logger::builder().try_init();
    let ours = http_auth::bearer::ChallengeBuilder::new()
        .error_uri(data)
        .build()
        .is_ok();
    let oracle = iri_string::types::UriStr::new(data).is_ok();
    if ours != oracle {
        panic!("MISMATCH {:?} ours={} oracle={}", data, ours, oracle);
    }
});
