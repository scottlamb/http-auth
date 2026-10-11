// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

// Checks that Display for ChallengeRef round-trips through the parser:
// $ cargo +nightly fuzz run render_challenges

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    if let Ok(challenges) = http_auth::parse_challenges(data) {
        let rendered: Vec<String> = challenges.iter().map(|c| c.to_string()).collect();
        let joined = rendered.join(", ");
        let reparsed = http_auth::parse_challenges(&joined)
            .unwrap_or_else(|e| panic!("rendered {:?} failed to parse: {}", rendered, e));
        assert_eq!(challenges, reparsed);
    }
});
