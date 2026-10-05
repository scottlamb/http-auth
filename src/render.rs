// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Writes `scheme k=v, k="v", k*=UTF-8''v` header values.

use crate::is_token;
#[cfg(feature = "digest-scheme")]
use crate::table::C_ATTR;
use crate::table::{char_classes, C_ESCAPABLE, C_QDTEXT};

/// Returns true if `s` can be sent as a quoted-string.
pub(crate) fn is_quotable(s: &str) -> bool {
    s.bytes()
        .all(|b| (char_classes(b) & (C_QDTEXT | C_ESCAPABLE)) != 0)
}

/// Writes a challenge or credentials header value. Callers validate values.
pub(crate) struct HeaderWriter(String);

impl HeaderWriter {
    pub(crate) fn new(scheme: &str) -> Self {
        debug_assert!(is_token(scheme));
        Self(scheme.to_owned())
    }

    fn key(&mut self, key: &str) {
        debug_assert!(is_token(key));
        self.0
            .push_str(if self.0.contains(' ') { ", " } else { " " });
        self.0.push_str(key);
    }

    /// Appends `key=value`; `value` must be a token.
    #[cfg(feature = "digest-scheme")]
    pub(crate) fn token(&mut self, key: &str, value: &str) {
        debug_assert!(is_token(value));
        self.key(key);
        self.0.push('=');
        self.0.push_str(value);
    }

    /// Appends `key="value"`, escaping `"` and `\`; `value` must be quotable.
    pub(crate) fn quoted(&mut self, key: &str, value: &str) {
        debug_assert!(is_quotable(value));
        self.key(key);
        self.0.push_str("=\"");
        for c in value.chars() {
            if c == '"' || c == '\\' {
                self.0.push('\\');
            }
            self.0.push(c);
        }
        self.0.push('"');
    }

    /// Appends `key*=UTF-8''value`, percent-encoding bytes outside `attr-char`
    /// ([RFC 8187](https://datatracker.ietf.org/doc/html/rfc8187)).
    #[cfg(feature = "digest-scheme")]
    pub(crate) fn ext(&mut self, key: &str, value: &str) {
        use std::fmt::Write as _;
        self.key(key);
        self.0.push_str("*=UTF-8''");
        for &b in value.as_bytes() {
            if (char_classes(b) & C_ATTR) != 0 {
                self.0.push(char::from(b));
            } else {
                let _ = write!(self.0, "%{:02X}", b);
            }
        }
    }

    pub(crate) fn finish(self) -> String {
        self.0
    }
}
