// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stateless nonces:
//! `hex(issued_at:u64be || salt:[u8; 8] || HMAC-SHA256(key, issued_at || salt || realm)[..16])`.

use std::convert::TryInto as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::server::ServerError;

/// A 32-byte nonce HMAC key whose `Debug` output is redacted.
#[derive(Clone, Copy)]
pub(crate) struct NonceKey(pub [u8; 32]);

impl std::fmt::Debug for NonceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

const TAG_LEN: usize = 16;
const RAW_LEN: usize = 8 + 8 + TAG_LEN;

/// Allowed clock skew for future issued-at times.
const MAX_FUTURE_SKEW: Duration = Duration::from_secs(60);

fn secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs()
}

fn mac(key: &[u8; 32], prefix: &[u8], realm: &str) -> Hmac<Sha256> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(prefix);
    m.update(realm.as_bytes());
    m
}

pub(crate) fn issue(key: &[u8; 32], realm: &str, now: SystemTime, salt: [u8; 8]) -> String {
    let mut raw = [0u8; RAW_LEN];
    raw[..8].copy_from_slice(&secs(now).to_be_bytes());
    raw[8..16].copy_from_slice(&salt);
    let tag = mac(key, &raw[..16], realm).finalize().into_bytes();
    raw[16..].copy_from_slice(&tag[..TAG_LEN]);
    hex::encode(raw)
}

/// Whether an authentic nonce is within its lifetime.
pub(crate) enum Validity {
    Fresh,
    Stale,
}

/// Verifies the nonce's HMAC and age.
pub(crate) fn check(
    key: &[u8; 32],
    realm: &str,
    nonce: &str,
    now: SystemTime,
    lifetime: Duration,
) -> Result<Validity, ServerError> {
    let mut raw = [0u8; RAW_LEN];
    hex::decode_to_slice(nonce, &mut raw).map_err(|_| ServerError::BadNonce)?;
    mac(key, &raw[..16], realm)
        .verify_truncated_left(&raw[16..])
        .map_err(|_| ServerError::BadNonce)?;
    let issued = u64::from_be_bytes(raw[..8].try_into().expect("8 bytes"));
    let now = secs(now);
    if issued > now.saturating_add(MAX_FUTURE_SKEW.as_secs())
        || now.saturating_sub(issued) > lifetime.as_secs()
    {
        return Ok(Validity::Stale);
    }
    Ok(Validity::Fresh)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];
    const LIFE: Duration = Duration::from_secs(300);

    fn t(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn format_and_uniqueness() {
        let a = issue(&KEY, "realm", t(1_000_000), [1; 8]);
        let b = issue(&KEY, "realm", t(1_000_000), [2; 8]);
        assert_eq!(a.len(), 64);
        assert!(a
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_ne!(a, b);
    }

    #[test]
    fn lifetime() {
        let n = issue(&KEY, "realm", t(1_000_000), [1; 8]);
        let stale =
            |secs: u64| matches!(check(&KEY, "realm", &n, t(secs), LIFE), Ok(Validity::Stale));
        for (t, expected) in [
            (1_000_000, false),
            (1_000_300, false),
            (1_000_301, true),
            (999_970, false),
            (999_940, false),
            (999_939, true),
            (999_900, true),
        ] {
            assert_eq!(stale(t), expected, "t={}", t);
        }
    }

    #[test]
    fn forgeries() {
        let n = issue(&KEY, "realm", t(1_000_000), [1; 8]);
        let mut tampered = n.clone().into_bytes();
        tampered[15] = if tampered[15] == b'0' { b'1' } else { b'0' }; // change the timestamp
        let tampered = String::from_utf8(tampered).unwrap();
        // Wrong key or realm.
        assert!(check(&[8; 32], "realm", &n, t(1_000_000), LIFE).is_err());
        assert!(check(&KEY, "other", &n, t(1_000_000), LIFE).is_err());
        // Garbled nonces.
        for bad in ["", "abc", &n[..62], &format!("{}00", n), &tampered] {
            assert!(matches!(
                check(&KEY, "realm", bad, t(1_000_000), LIFE),
                Err(ServerError::BadNonce)
            ));
        }
    }
}
