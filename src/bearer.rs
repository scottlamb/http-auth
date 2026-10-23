// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `Bearer` authentication scheme, as in
//! [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750).

#[cfg(feature = "server")]
mod server;

#[cfg(feature = "server")]
#[cfg_attr(docsrs, doc(cfg(feature = "server")))]
pub use self::server::{ChallengeBuilder, Credentials, ErrorCode};
