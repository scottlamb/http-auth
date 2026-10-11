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
pub(crate) struct HeaderWriter {
    out: String,
    has_params: bool,
}

impl HeaderWriter {
    pub(crate) fn new(scheme: &str) -> Self {
        debug_assert!(is_token(scheme));
        Self {
            out: scheme.to_owned(),
            has_params: false,
        }
    }

    fn key(&mut self, key: &str) {
        debug_assert!(is_token(key));
        self.out.push_str(if self.has_params { ", " } else { " " });
        self.has_params = true;
        self.out.push_str(key);
    }

    /// Appends `key=value`; `value` must be a token.
    #[cfg(feature = "digest-scheme")]
    pub(crate) fn token(&mut self, key: &str, value: &str) {
        debug_assert!(is_token(value));
        self.key(key);
        self.out.push('=');
        self.out.push_str(value);
    }

    /// Appends `key="value"`, escaping `"` and `\`; `value` must be quotable.
    pub(crate) fn quoted(&mut self, key: &str, value: &str) {
        debug_assert!(is_quotable(value));
        self.key(key);
        self.out.push_str("=\"");
        for c in value.chars() {
            if c == '"' || c == '\\' {
                self.out.push('\\');
            }
            self.out.push(c);
        }
        self.out.push('"');
    }

    /// Appends `key*=UTF-8''value`, percent-encoding bytes outside `attr-char`
    /// ([RFC 8187](https://datatracker.ietf.org/doc/html/rfc8187)).
    #[cfg(feature = "digest-scheme")]
    pub(crate) fn ext(&mut self, key: &str, value: &str) {
        use std::fmt::Write as _;
        self.key(key);
        self.out.push_str("*=UTF-8''");
        for &b in value.as_bytes() {
            if (char_classes(b) & C_ATTR) != 0 {
                self.out.push(char::from(b));
            } else {
                let _ = write!(self.out, "%{:02X}", b);
            }
        }
    }

    pub(crate) fn finish(self) -> String {
        self.out
    }
}
