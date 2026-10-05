## Unreleased (0.2.0)

### Breaking

*   `ChallengeRef` gains a `token68` field; `ChallengeParser` accepts `token68`
    challenges and `1*SP` between the scheme and body ([RFC 9110 section
    11.2](https://datatracker.ietf.org/doc/html/rfc9110#section-11.2)).
*   `ParamValue::to_unescaped` now returns `std::borrow::Cow<str>` instead of
    `String`.

### Added

*   server support behind the `server` feature: `basic::BasicServer`,
    `digest::DigestServer`, `server::Challenge`, `server::ServerError`.
*   `parse_credentials` for `Authorization` / `Proxy-Authorization` values.
*   `impl Display for ChallengeRef`.
*   `digest::Algorithm::ha1`.
*   `digest::Qop` now implements `PartialEq` and `Eq`.
*   `digest::QopSet` constructors: `From<Qop>`, `BitOr`, `contains`,
    `is_empty`.

### Changed

*   fix: `qop=auth-int` hashes `H(entity-body)`, not the raw body.
*   algorithm names in challenges are now matched case-insensitively.
*   the client rejects a repeated `stale` or `algorithm` in a challenge.

## `v0.1.10` (2024-08-31)

*   update `base64` to version 0.22.
*   update minimum Rust version to 1.70.

## `v0.1.9` (2023-12-28)

*   support conversion from `http` crate version 1.0 types.

## `v0.1.8` (2023-01-30)

*   upgrade `base64` dependency from 0.20 to 0.21.

## `v0.1.7` (2023-01-05)

*   bump minimum Rust version to 1.57.
*   upgrade `base64` dependency from 0.13 to 0.20.

## `v0.1.6` (2022-05-02)

*   upgrade `digest`, `md5`, and `sha2` dependencies.

## `v0.1.5` (2021-11-30)

*   add `http_auth::basic::encode_credentials` for preemptively sending `Basic`
    credentials.

## `v0.1.4` (2021-11-18)

*   more thorough documentation
*   shrink `DigestClient`
*   support `userhash` in `DigestClient`
*   support `-sess` algorithm variants in `DigestClient`

## `v0.1.3` (2021-10-20)

*   fix `docs.rs`

## `v0.1.2` (2021-10-20)

*   add RFC 2069 compatibility mode.

## `v0.1.1` (2021-10-20)

*   allow `Digest`'s `qop` parameter to be omitted.

## `v0.1.0` (2021-10-20)

*   initial version
