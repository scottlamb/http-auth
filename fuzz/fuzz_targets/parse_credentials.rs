// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

// Compares the hand-written credentials parser with the nom reference:
// $ cargo +nightly fuzz run parse_credentials

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = env_logger::builder().try_init();
    let hand = http_auth::parse_credentials(data);
    let nom = http_auth_fuzz::credentials(data).ok().map(|(_, c)| c);
    match (hand, nom) {
        (Ok(h), Some(n)) => assert_eq!(h, n),
        (Err(e), Some(n)) => panic!(
            "hand parsing failed with {}; nom succeeded with {:#?}",
            e, n
        ),
        (Ok(h), None) => panic!("nom parsing failed; hand succeeded with {:#?}", h),
        (Err(_), None) => {}
    }
});
