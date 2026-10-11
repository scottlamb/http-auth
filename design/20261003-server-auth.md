# Server-side `Basic` and `Digest` authentication

Date: 2026-10-03

Tracking issue: [#5](https://github.com/scottlamb/http-auth/issues/5).

# Problem statement

`http-auth` implements only the client side. Servers (HTTP origins, RTSP
servers, ONVIF devices, proxies) issue `WWW-Authenticate` /
`Proxy-Authenticate` challenges, parse `Authorization` / `Proxy-Authorization`
credentials, and verify them against a stored secret.

Goals: server side of RFC 7616 (Digest), RFC 7617 (Basic) and RFC 9110 §11
(the framework); sound by construction (nonce check can't be skipped, no CR/LF
in rendered headers, constant-time comparisons); no I/O in the crate.

Non-goals: server-side RFC 2069 (qop-less) responses; `Authentication-Info` /
`rspauth` / `nextnonce` (RFC 7616 §3.5); built-in stateful replay tracking;
Unicode normalization (NFC, RFC 7613).

# Considered options

1.  **A parse function and a `verify` function, with no enforced nonce check.**
2.  **A three-stage pipeline enforced by types:** parse, check nonce, verify.

# Decision outcome

Option 2: parse, then `DigestServer::check_nonce` (built-in stateless check, or
`DigestResponse::nonce_checked_externally` with a caller's store), then
`verify(&resp, Request { method, uri, body }, secret)`; only a
`DigestResponse<NonceChecked>` reaches `verify`. `DigestServer::builder(realm)`
builds a `Send + Sync` server; `challenges(stale, now)` returns one validated
`Challenge` per offered algorithm. The secret is `Secret::Ha1(&str)` or
`Secret::Password { username, password }`. `BasicServer::new(realm)` validates
the realm; `challenge()`, `BasicCredentials::parse` and `verify_password`
complete the `Basic` server.

The nonce is `hex(issued_at_secs:u64be || salt:[u8; 8] || HMAC-SHA256(key,
issued_at_secs || salt || realm)[..16])`, keyed by `nonce_key` with lifetime
`nonce_lifetime`. The built-in check keeps no `nc` record; callers track the
highest `nc` per `(nonce, cnonce)` for RFC 7616 §5.5.

## Validation rules

| Rule | Error |
|---|---|
| Parse: scheme `Digest` (case-insensitive) | `WrongScheme` |
| Parse: `response`, `nonce`, `uri`, `realm`, `cnonce`, `nc`, `qop` present; no `token68`; no repeated parameter | `Malformed` |
| Parse: exactly one of `username` and `username*`; `userhash` usernames hex, lower-cased | `Malformed` |
| Parse: `username*` valid RFC 8187 `ext-value`, not with `userhash=true` | `Malformed` |
| Parse: `nc` 8 hex digits; `qop` `auth`/`auth-int`; `algorithm` known; `response` hex of the algorithm's length | `Malformed` |
| Parse: non-ASCII bytes | `Malformed` |
| `check_nonce`: nonce decodes, HMAC tag verifies (constant-time); authentic-but-expired is marked stale, not an error | `BadNonce` |
| `verify`: `realm` or `opaque` differ | `WrongRealm` / `WrongOpaque` |
| `verify`: `algorithm` (default `MD5`) and `-sess` not offered; `qop` not offered | `UnofferedAlgorithm` / `UnofferedQop` |
| `verify`: `userhash=true` not offered | `UnofferedUserhash` |
| `verify`: `uri` differs from the request-target (RFC 7616 §3.4.6) | `UriMismatch` (400) |
| `verify`: `qop=auth-int` without `body: Some(_)` | `BodyRequired` |
| `verify`: `Secret::Ha1` wrong hex length | `SecretMismatch` |
| `verify`: username or computed `response` (constant-time) mismatch | `BadCredentials` |
| `verify`: nonce authentic but expired, everything else valid | `Stale` |
| `BasicCredentials::parse` (RFC 7617 §2): scheme, token68 base64, `:` split, CTLs, UTF-8 | `Malformed` / `WrongScheme` |

Builders return `ServerError::InvalidConfig`.

# Errors

`ServerError::status()` gives the HTTP status to respond with; re-challenge
with `stale=true` on `ServerError::Stale`. Failure details go to logs only.

## Features and compatibility

`server` gates server code; needs `basic-scheme` and/or `digest-scheme`; adds
`hmac`, `subtle`. Every feature combination and `--no-default-features`
builds; MSRV stays 1.70. 0.2 changes are in [CHANGELOG](../CHANGELOG.md).

# Security notes

*   `Digest` requires a password-equivalent secret (HA1); a leaked, unsalted HA1 database authenticates to this server and is cheap to brute-force.
*   Offering `MD5` alongside `SHA-256` permits downgrade (RFC 7616 §5.6, §5.8).
*   The nonce lifetime bounds the replay window; use an external `nc` check for unsafe methods (RFC 7616 §5.5).
*   Raw non-ASCII usernames are rejected; send `username*` (RFC 8187).
*   `-sess` uses `H(HA1 ":" nonce ":" cnonce)` (erratum 1649), unlike the RFC 2617 sample code.

# Testing

*   RFC worked examples: RFC 2617 §3.5; RFC 7616 §3.9.1 and §3.9.2 (erratum 4897 values); RFC 7617 §2.
*   One negative test per validation rule, asserting the error variant.
*   Client/server round-trips across algorithm × `-sess` × qop × userhash.
*   `curl` oracle (`tests/curl_oracle.rs`), skipped when curl is absent.
*   Fuzzing: `parse_credentials` (differential), `DigestResponse::parse`, rendering round-trip.
