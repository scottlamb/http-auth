// Copyright (C) 2026 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

pub(crate) struct Uri<'a> {
    pub(crate) scheme: &'a str,
    pub(crate) host: Option<&'a str>,
    pub(crate) fragment: Option<&'a str>,
}

pub(crate) fn parse(input: &str) -> Option<Uri<'_>> {
    let bytes = input.as_bytes();
    (!bytes.is_empty() && bytes[0].is_ascii_alphabetic()).then_some(())?;
    let mut position = 1 + bytes[1..]
        .iter()
        .take_while(|&&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        .count();
    let scheme_end = position;
    (position < bytes.len() && bytes[position] == b':').then_some(())?;
    position += 1;
    let mut host_range = None;
    if position + 1 < bytes.len() && bytes[position] == b'/' && bytes[position + 1] == b'/' {
        position += 2;
        let authority_end = memchr::memchr3(b'/', b'?', b'#', &bytes[position..])
            .map(|i| position + i)
            .unwrap_or(bytes.len());
        if let Some(at) = bytes[position..authority_end]
            .iter()
            .position(|&c| c == b'@')
        {
            scan(&bytes[position..position + at], userinfo_byte).then_some(())?;
            position += at + 1;
        }
        let host_start = position;
        if position < authority_end && bytes[position] == b'[' {
            let inner_start = position + 1;
            let close = inner_start + memchr::memchr(b']', &bytes[inner_start..authority_end])?;
            (is_ipv6(&bytes[inner_start..close]) || is_ipvfuture(&bytes[inner_start..close]))
                .then_some(())?;
            position = close + 1;
        } else {
            let cursor = ipv4(bytes, position);
            let boundary = cursor.is_some_and(|value| {
                value == authority_end
                    || matches!(bytes.get(value), Some(b':' | b'/' | b'?' | b'#'))
            });
            if boundary {
                position = cursor.unwrap();
            } else {
                let mut local = 0;
                skip(&bytes[position..authority_end], &mut local, |b| {
                    pchar_byte(b) && b != b':' && b != b'@'
                });
                position += local;
            }
        }
        host_range = Some((host_start, position));
        if position < authority_end && bytes[position] == b':' {
            position += 1;
            position += bytes[position..authority_end]
                .iter()
                .take_while(|&&b| b.is_ascii_digit())
                .count();
        }
        (position == authority_end).then_some(())?;
        path_segments(bytes, &mut position);
    } else if position < bytes.len() && bytes[position] == b'/' {
        position += 1;
        if position < bytes.len() && !matches!(bytes[position], b'?' | b'#' | b'/') {
            segment_nz(bytes, &mut position).then_some(())?;
        }
        path_segments(bytes, &mut position);
    } else if position < bytes.len() && !matches!(bytes[position], b'?' | b'#') {
        segment_nz(bytes, &mut position).then_some(())?;
        path_segments(bytes, &mut position);
    }
    let mut fragment_range = None;
    if position < bytes.len() && bytes[position] == b'?' {
        position += 1;
        skip(bytes, &mut position, query_byte);
    }
    if position < bytes.len() && bytes[position] == b'#' {
        let fragment_start = position + 1;
        position += 1;
        skip(bytes, &mut position, query_byte);
        fragment_range = Some((fragment_start, position));
    }
    (position == bytes.len()).then_some(())?;
    Some(Uri {
        scheme: &input[..scheme_end],
        host: host_range.map(|(a, b)| &input[a..b]),
        fragment: fragment_range.map(|(a, b)| &input[a..b]),
    })
}

fn skip(bytes: &[u8], position: &mut usize, allowed: fn(u8) -> bool) {
    while *position < bytes.len() {
        if allowed(bytes[*position]) {
            *position += 1;
        } else if bytes[*position] == b'%'
            && *position + 2 < bytes.len()
            && bytes[*position + 1].is_ascii_hexdigit()
            && bytes[*position + 2].is_ascii_hexdigit()
        {
            *position += 3;
        } else {
            break;
        }
    }
}

fn scan(bytes: &[u8], allowed: fn(u8) -> bool) -> bool {
    let mut position = 0;
    skip(bytes, &mut position, allowed);
    position == bytes.len()
}

fn segment_nz(bytes: &[u8], position: &mut usize) -> bool {
    let start = *position;
    skip(bytes, position, pchar_byte);
    *position > start
}

fn path_segments(bytes: &[u8], position: &mut usize) {
    while *position < bytes.len() && bytes[*position] == b'/' {
        *position += 1;
        skip(bytes, position, pchar_byte);
    }
}

fn ipv4(bytes: &[u8], position: usize) -> Option<usize> {
    let mut pos = position;
    for i in 0..4 {
        if i > 0 {
            (pos < bytes.len() && bytes[pos] == b'.').then_some(())?;
            pos += 1;
        }
        let start = pos;
        pos += bytes[pos..]
            .iter()
            .take_while(|&&b| b.is_ascii_digit())
            .count();
        (pos > start && valid_dec_octet(&bytes[start..pos])).then_some(())?;
    }
    Some(pos)
}

fn is_ipv6(bytes: &[u8]) -> bool {
    let double_colon = bytes.windows(2).position(|window| *window == *b"::");
    if let Some(position) = double_colon {
        if bytes[position + 2..]
            .windows(2)
            .any(|window| *window == *b"::")
        {
            return false;
        }
    }
    let (left, right) = double_colon
        .map(|position| (&bytes[..position], &bytes[position + 2..]))
        .unwrap_or((bytes, &bytes[0..0]));
    let Some(left_count) = validate_groups(left, double_colon.is_none()) else {
        return false;
    };
    let Some(right_count) = validate_groups(right, true) else {
        return false;
    };
    if double_colon.is_some() {
        left_count + right_count <= 7
    } else {
        left_count == 8
    }
}

fn validate_groups(bytes: &[u8], allow_ipv4_last: bool) -> Option<usize> {
    let mut position = 0;
    let mut count = 0;
    while position < bytes.len() {
        let start = position;
        while position < bytes.len() && bytes[position] != b':' {
            position += 1;
        }
        let group = &bytes[start..position];
        (!group.is_empty()).then_some(())?;
        if allow_ipv4_last && position == bytes.len() && group.contains(&b'.') {
            (ipv4(group, 0)? == group.len()).then_some(())?;
            count += 2;
        } else {
            (group.len() <= 4 && group.iter().all(|b| b.is_ascii_hexdigit())).then_some(())?;
            count += 1;
        }
        if position < bytes.len() {
            (bytes[position] == b':').then_some(())?;
            position += 1;
            (position < bytes.len() && bytes[position] != b':').then_some(())?;
        }
    }
    Some(count)
}

fn is_ipvfuture(bytes: &[u8]) -> bool {
    if bytes.is_empty() || !(bytes[0] == b'v' || bytes[0] == b'V') {
        return false;
    }
    let hex_len = bytes[1..]
        .iter()
        .take_while(|&&b| b.is_ascii_hexdigit())
        .count();
    if hex_len == 0
        || hex_len + 1 >= bytes.len()
        || bytes[hex_len + 1] != b'.'
        || hex_len + 2 >= bytes.len()
    {
        return false;
    }
    bytes[hex_len + 2..].iter().all(|&b| userinfo_byte(b))
}

fn valid_dec_octet(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.len() <= 3
        && (bytes.len() == 1 || bytes[0] != b'0')
        && bytes.iter().all(u8::is_ascii_digit)
        && bytes.iter().fold(0u16, |v, &b| v * 10 + (b - b'0') as u16) <= 255
}

fn pchar_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || b"-._~".contains(&b)
        || b"!$&'()*+,;=".contains(&b)
        || b == b':'
        || b == b'@'
}
fn userinfo_byte(b: u8) -> bool {
    pchar_byte(b) && b != b'@'
}
fn query_byte(b: u8) -> bool {
    pchar_byte(b) || b == b'/' || b == b'?'
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn rfc3986_examples() {
        for value in [
            "https://www.example.com/foo/bar?x=1#frag",
            "ftp://ftp.is.co.za/rfc/rfc1808.txt",
            "http://www.ietf.org/rfc/rfc2396.txt#header1",
            "ldap://[2001:db8::7]/c=GB?objectClass?one",
            "mailto:John.Doe@example.com",
            "news:comp.infosystems.www.servers.unix",
            "tel:+1-816-555-1212",
            "telnet://192.0.2.16:80/",
            "urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
        ] {
            assert!(parse(value).is_some(), "{}", value);
        }
    }

    #[test]
    fn invalid_ipv6() {
        for value in [
            "http://[::1",
            "http://[::1/",
            "http://[2001:db8::g]/",
            "http://[1.2.3.4]/",
        ] {
            assert!(parse(value).is_none(), "{}", value);
        }
    }

    #[test]
    fn uri_forms() {
        assert!(parse("http://example.com").is_some());
        assert!(parse("http://example.com/").is_some());
        assert!(parse("http://example.com/a/b").is_some());
        assert!(parse("http://example.com/a/b?c=d&e=f").is_some());
        assert!(parse("http://example.com/a/b#c").is_some());
        assert!(parse("scheme:foo").is_some());
        assert!(parse("scheme:").is_some());
        assert!(parse("").is_none());
        assert!(parse("http://").is_some());
        assert!(parse("http:///host").is_some());
        assert!(parse("http://[::1]:8080/x").is_some());
        assert!(parse("http://[v1.fe80::a]/").is_some());
        assert!(parse("http://user:pass@example.com:80/x").is_some());
        assert!(parse("http://example.com/%zz").is_none());
        assert!(parse("http://example.com/%20").is_some());
    }

    #[test]
    fn ipv6_alternatives() {
        for value in [
            "http://[1:2:3:4:5:6:7:8]/",
            "http://[::1:2:3:4:5:6:7]/",
            "http://[1::2:3:4:5:6:7]/",
            "http://[1:2::3:4:5:6:7]/",
            "http://[1::2:3:4:5]/",
            "http://[1::2:3:4]/",
            "http://[1::2:3]/",
            "http://[1::2]/",
            "http://[1::]/",
            "http://[::1]/",
            "http://[::ffff:192.0.2.1]/",
        ] {
            assert!(parse(value).is_some(), "{}", value);
        }
    }

    #[test]
    fn ipv6_invalid() {
        for value in [
            "http://[:::]/",
            "http://[1:2:3:4:5:6:7:8:9]/",
            "http://[1::2::3]/",
            "http://[12345::]/",
            "http://[::1.2.3]/",
            "http://[1.2.3.4::]/",
            "http://[::ffff:1.2.3.256]/",
        ] {
            assert!(parse(value).is_none(), "{}", value);
        }
    }

    #[test]
    fn host_fallback() {
        for value in [
            "https://1.2.3.4abc/",
            "https://1.2.3.4.5/",
            "https://999.1.1.1/",
        ] {
            assert!(parse(value).is_some(), "{}", value);
        }
    }

    #[test]
    fn ipv6_trailing_colon() {
        for value in [
            "http://[1:2:3:4:5:6:7:8:]/",
            "http://[::1:]:80/",
            "http://[1::3:4:5:6:7:]/",
        ] {
            assert!(parse(value).is_none(), "{}", value);
        }
    }

    #[test]
    fn ipvfuture_pct_encoded() {
        assert!(parse("http://[v7.x%97:y]/").is_none());
    }
}
