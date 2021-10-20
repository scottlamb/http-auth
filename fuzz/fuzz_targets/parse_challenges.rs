// Copyright (C) 2021 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

// Runs both the state machine-based challenge parser and a nom-based challenge
// parser, failing if their outputs differ or if either panics. Run via:
//
// ```console
// $ cd .../http-auth/fuzz
// $ cargo +nightly test
// $ RUST_LOG=http_auth=trace cargo +nightly fuzz run parse_challenges

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = env_logger::builder().try_init();
    let hand_parsed = http_auth::parse_challenges(data);
    let nom_parsed = http_auth_fuzz::challenges(data);
    match (hand_parsed, nom_parsed) {
        (Ok(hand_challenges), Ok((_, nom_challenges))) => {
            assert_eq!(hand_challenges, nom_challenges)
        }
        (Err(hand_e), Ok((_, nom_challenges))) => {
            panic!(
                "hand parsing failed with {}; nom parsing succeeded with {:#?}",
                hand_e, nom_challenges
            );
        }
        (Ok(hand_challenges), Err(nom_e)) => {
            panic!(
                "nom parsing failed with {}; hand parsing succeeded with {:#?}",
                nom_e, hand_challenges
            );
        }
        (Err(_hand_e), Err(_nom_e)) => {} // messages don't need to match.
    }
});
