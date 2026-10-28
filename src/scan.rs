//! Byte classes and scanners for the RFC 9110 / RFC 9112 grammar.
//!
//! Every call site in the crate reaches the grammar through this one module.
//! The generic RFC 9110 field grammar comes from `parse-net` (spec section
//! 7.9, OD-1): `tchar` and tokens, OWS and its trimming, the field-value
//! check, `qdtext`, `1*DIGIT`, and hex digits. Each is a thin wrapper or a
//! re-export, so the behaviour is parse-net's, and the tests at the end of
//! this file hold it to the 0.7 local implementation byte for byte.
//!
//! What stays here is HTTP/1.1 wire framing, or grammar whose parse-net
//! counterpart answers differently (decisions D-59 and D-60): the
//! request-target and `Host` checks, the reason phrase, the printable-run
//! and byte-search scanners of the head's hot path, the infallible `#list`
//! walker, and the number writers.

use parse_net::{
    ErrorKind,
    class::{self, Class},
    num,
};
pub(crate) use parse_net::{
    class::{hex_value, is_qdtext, is_tchar},
    text::{is_ows, is_token, trim_ows},
};

use crate::{error::HttpError, write::Output};

/// RFC 3986 characters allowed in a request target (`%` is checked apart):
/// `unreserved / sub-delims / ":" / "@" / "/" / "?"` and the `%` that
/// introduces a `pct-encoded` triple.
const fn build_target() -> [bool; 256] {
    let mut t = [false; 256];
    let mut b = 0usize;
    while b < 256 {
        let c = b as u8;
        t[b] = c.is_ascii_alphanumeric()
            || matches!(
                c,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
                    | b'/'
                    | b'?'
                    | b'%'
            );
        b += 1;
    }
    t
}

static TARGET: [bool; 256] = build_target();

#[inline]
fn is_target_char(b: u8) -> bool {
    TARGET[b as usize]
}

/// The length of the run of printable ASCII (`0x20` to `0x7e`) at the start
/// of `s`, eight bytes at a time: where the first control byte, DEL, or
/// byte of `0x80` and above sits, or `s.len()`.
#[inline]
pub(crate) fn printable_run(s: &[u8]) -> usize {
    let mut chunks = s.chunks_exact(8);
    let mut base = 0usize;
    for chunk in &mut chunks {
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        let w = u64::from_le_bytes(word);
        // The masks of the SWAR field-value check: below 0x20, DEL, high
        // bit. A marker can be false only above a true one, so the lowest is
        // exact.
        let low = w.wrapping_sub(0x2020_2020_2020_2020) & !w & 0x8080_8080_8080_8080;
        let del = {
            let x = w ^ 0x7f7f_7f7f_7f7f_7f7f;
            x.wrapping_sub(0x0101_0101_0101_0101) & !x & 0x8080_8080_8080_8080
        };
        let marks = low | del | (w & 0x8080_8080_8080_8080);
        if marks != 0 {
            return base + (marks.trailing_zeros() / 8) as usize;
        }
        base += 8;
    }
    let rest = chunks.remainder();
    base + rest
        .iter()
        .position(|b| !(0x20..0x7f).contains(b))
        .unwrap_or(rest.len())
}

/// Validates a field value (already trimmed of OWS), with parse-net's SWAR
/// check.
///
/// A CR is reported as [`HttpError::BareCr`] because that is the smuggling
/// vector it represents; every other control byte (parse-net's `LineFeed`,
/// `Nul`, and `Control` kinds) is [`HttpError::InvalidHeaderValue`].
#[inline]
pub(crate) fn check_field_value(value: &[u8]) -> Result<(), HttpError> {
    parse_net::scan::check_field_value(value).map_err(|e| match e.kind() {
        ErrorKind::BareCr => HttpError::BareCr,
        _ => HttpError::InvalidHeaderValue,
    })
}

/// Validates a reason phrase: `*( HTAB / SP / VCHAR / obs-text )`.
#[inline]
pub(crate) fn is_reason(s: &[u8]) -> bool {
    class::all(s, Class::FIELD_TEXT)
}

/// Validates the characters of a request target: RFC 3986 characters only,
/// and every `%` followed by two hex digits.
pub(crate) fn is_target_chars(s: &[u8]) -> bool {
    let mut i = 0;
    while i < s.len() {
        let b = s[i];
        if !is_target_char(b) {
            return false;
        }
        if b == b'%' {
            match (s.get(i + 1), s.get(i + 2)) {
                (Some(&h1), Some(&h2)) if class::is_hexdig(h1) && class::is_hexdig(h2) => i += 3,
                _ => return false,
            }
        } else {
            i += 1;
        }
    }
    true
}

/// Validates a `Host` field value: `uri-host [ ":" port ]`, possibly empty.
pub(crate) fn is_host_value(s: &[u8]) -> bool {
    if s.is_empty() {
        // RFC 9112 section 3.2: an empty Host is how a client says the target
        // URI has no authority.
        return true;
    }
    let (host, port) = if s[0] == b'[' {
        // IP-literal: "[" ... "]" [ ":" port ]
        match s.iter().position(|&b| b == b']') {
            Some(close) => {
                let inner = &s[1..close];
                if inner.is_empty()
                    || !inner
                        .iter()
                        .all(|&b| b.is_ascii_hexdigit() || matches!(b, b':' | b'.' | b'v' | b'V'))
                {
                    return false;
                }
                let rest = &s[close + 1..];
                match rest {
                    [] => (&s[..0], None),
                    [b':', port @ ..] => (&s[..0], Some(port)),
                    _ => return false,
                }
            }
            None => return false,
        }
    } else {
        match s.iter().rposition(|&b| b == b':') {
            // A port needs a host: `:80` names no authority at all.
            Some(0) => return false,
            Some(colon) => (&s[..colon], Some(&s[colon + 1..])),
            None => (s, None),
        }
    };
    // reg-name allows pct-encoded triples only: `%` and two hex digits.
    if !host_pct_ok(host) {
        return false;
    }
    let host_ok = host.iter().all(|&b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b'%'
            )
    });
    let port_ok = port.is_none_or(|p| p.iter().all(u8::is_ascii_digit));
    host_ok && port_ok
}

/// Whether every `%` in `host` starts a `%XX` triple.
fn host_pct_ok(host: &[u8]) -> bool {
    let mut i = 0;
    while let Some(off) = host.get(i..).and_then(|rest| find_byte(b'%', rest)) {
        let at = i + off;
        match (host.get(at + 1), host.get(at + 2)) {
            (Some(&h1), Some(&h2)) if class::is_hexdig(h1) && class::is_hexdig(h2) => i = at + 3,
            _ => return false,
        }
    }
    true
}

/// Validates an upgrade protocol: `protocol-name ["/" protocol-version]`,
/// both tokens (RFC 9110 section 7.8).
pub(crate) fn is_protocol(s: &[u8]) -> bool {
    match find_byte(b'/', s) {
        Some(i) => is_token(&s[..i]) && is_token(&s[i + 1..]),
        None => is_token(s),
    }
}

/// Parses `1*DIGIT` into a `u64`, refusing signs, spaces, and overflow
/// (parse-net's `parse_u64`, whose every error is `None` here).
#[inline]
pub(crate) fn parse_decimal(s: &[u8]) -> Option<u64> {
    num::parse_u64(s).ok()
}

/// Iterates the elements of a comma-separated list value, trimmed of OWS,
/// skipping empty elements (RFC 9110 section 5.6.1.2).
///
/// A comma inside a quoted string does not end an element: `a="x,y", b` is
/// two elements, `a="x,y"` and `b` (a backslash escapes the next byte
/// inside the quotes). An unterminated quote runs to the end of the value.
///
/// This stays local although parse-net has a list walker (decision
/// D-60): parse-net's `list` validates as it splits and refuses inputs this
/// walker accepts (an unterminated quote, an unbalanced `)`, more than 16
/// empty elements or 1024 members), and it treats `(...)` as a comment, so
/// `(a, b)` is one element there and two here. Moving would change which
/// requests http-net accepts.
pub(crate) fn list_elements(value: &[u8]) -> ListSplit<'_> {
    ListSplit {
        rest: value,
        // Almost every list value has no quoted string; those are split
        // with the word-at-a-time comma search instead of the byte walk.
        quoted: find_byte(b'"', value).is_some(),
    }
}

/// The iterator behind [`list_elements`].
#[derive(Clone, Debug)]
pub(crate) struct ListSplit<'a> {
    rest: &'a [u8],
    quoted: bool,
}

impl<'a> Iterator for ListSplit<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        while !self.rest.is_empty() {
            let end = if self.quoted {
                element_end(self.rest)
            } else {
                find_byte(b',', self.rest).unwrap_or(self.rest.len())
            };
            let element = trim_ows(&self.rest[..end]);
            self.rest = self.rest.get(end + 1..).unwrap_or(&[]);
            if !element.is_empty() {
                return Some(element);
            }
        }
        None
    }
}

/// The index of the comma that ends the first element of `s` (or `s.len()`),
/// skipping commas inside quoted strings.
fn element_end(s: &[u8]) -> usize {
    let mut i = 0;
    let mut quoted = false;
    while i < s.len() {
        match s[i] {
            b'"' => quoted = !quoted,
            b'\\' if quoted => i += 1,
            b',' if !quoted => return i,
            _ => {}
        }
        i += 1;
    }
    s.len()
}

/// Finds the first occurrence of `needle` in `hay`, eight bytes at a time.
#[inline]
pub(crate) fn find_byte(needle: u8, hay: &[u8]) -> Option<usize> {
    let pattern = u64::from_le_bytes([needle; 8]);
    let marks = |chunk: &[u8]| {
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        let x = u64::from_le_bytes(word) ^ pattern;
        x.wrapping_sub(0x0101_0101_0101_0101) & !x & 0x8080_8080_8080_8080
    };
    // Eight bytes per step. Sixteen (two words, one branch) measured about
    // 12% slower on the head benchmarks: field lines are short (decision
    // D-45).
    let mut base = 0usize;
    let mut chunks = hay.chunks_exact(8);
    for chunk in &mut chunks {
        let found = marks(chunk);
        if found != 0 {
            // The lowest set marker belongs to the first matching byte; the
            // borrow trick can only produce false markers above a true one.
            return Some(base + (found.trailing_zeros() / 8) as usize);
        }
        base += 8;
    }
    chunks
        .remainder()
        .iter()
        .position(|&b| b == needle)
        .map(|i| base + i)
}

/// Writes `n` in lowercase hexadecimal.
pub(crate) fn push_hex<O: Output + ?Sized>(out: &mut O, n: u64) {
    let mut digits = [0u8; 16];
    let mut i = digits.len();
    let mut v = n;
    loop {
        i -= 1;
        digits[i] = b"0123456789abcdef"[(v & 0xf) as usize];
        v >>= 4;
        if v == 0 {
            break;
        }
    }
    out.put(&digits[i..]);
}

/// Writes `n` in decimal.
pub(crate) fn push_decimal<O: Output + ?Sized>(out: &mut O, n: u64) {
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    let mut v = n;
    loop {
        i -= 1;
        digits[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    out.put(&digits[i..]);
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;

    #[test]
    fn test_token_classes_match_rfc() {
        for b in 0u8..=255 {
            let expected = b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
            assert_eq!(is_tchar(b), expected, "byte {b:#x}");
        }
        assert!(!is_token(b""));
        assert!(is_token(b"GET"));
        assert!(!is_token(b"GE T"));
    }

    #[test]
    fn test_field_value_rejects_controls_and_reports_cr() {
        assert!(check_field_value(b"text/html; q=0.9\tx").is_ok());
        assert!(check_field_value(b"caf\xc3\xa9 \x80\xff").is_ok());
        assert_eq!(check_field_value(b"a\rb"), Err(HttpError::BareCr));
        assert_eq!(
            check_field_value(b"abcdefgh\x00ijk"),
            Err(HttpError::InvalidHeaderValue)
        );
        assert_eq!(
            check_field_value(b"abcdefghijklmno\x7f"),
            Err(HttpError::InvalidHeaderValue)
        );
        assert_eq!(
            check_field_value(b"abcdefg\nhij"),
            Err(HttpError::InvalidHeaderValue)
        );
    }

    #[test]
    fn test_trim_ows_only_strips_space_and_tab() {
        assert_eq!(trim_ows(b" \t a b \t"), b"a b");
        assert_eq!(trim_ows(b"\x0ba\x0c"), b"\x0ba\x0c");
        assert_eq!(trim_ows(b"   "), b"");
    }

    #[test]
    fn test_target_chars_check_percent_encoding() {
        assert!(is_target_chars(b"/a/b?c=d&e=%20"));
        assert!(!is_target_chars(b"/a%2"));
        assert!(!is_target_chars(b"/a%zz"));
        assert!(!is_target_chars(b"/a b"));
        assert!(!is_target_chars(b"/a#frag"));
        assert!(!is_target_chars(b"/a\x7f"));
    }

    #[test]
    fn test_host_value_forms() {
        assert!(is_host_value(b""));
        assert!(is_host_value(b"example.com"));
        assert!(is_host_value(b"127.0.0.1:8080"));
        assert!(is_host_value(b"[::1]:80"));
        assert!(is_host_value(b"[::1]"));
        assert!(!is_host_value(b"a b"));
        assert!(!is_host_value(b"host:8x"));
        assert!(!is_host_value(b"[::1"));
        assert!(!is_host_value(b"a/b"));
    }

    #[test]
    fn test_host_value_empty_host_with_port_is_refused() {
        assert!(!is_host_value(b":80"));
        assert!(!is_host_value(b":"));
        // An empty port is allowed by RFC 3986 (`port = *DIGIT`), and the
        // port is not bounded by the grammar.
        assert!(is_host_value(b"example.com:"));
        assert!(is_host_value(b"example.com:99999"));
        assert!(is_host_value(b"[::1]:80"));
        assert!(is_host_value(b"[v1.fe80::a]"));
    }

    #[test]
    fn test_host_value_percent_escapes_need_two_hex_digits() {
        assert!(is_host_value(b"a%41"));
        assert!(is_host_value(b"%41%42:8080"));
        assert!(!is_host_value(b"a%zz"));
        assert!(!is_host_value(b"a%4"));
        assert!(!is_host_value(b"a%"));
        assert!(!is_host_value(b"a%4:80"));
    }

    #[test]
    fn test_protocol_names_and_versions() {
        assert!(is_protocol(b"websocket"));
        assert!(is_protocol(b"foo/2"));
        assert!(!is_protocol(b"foo/"));
        assert!(!is_protocol(b"/2"));
        assert!(!is_protocol(b"a/b/c"));
        assert!(!is_protocol(b"a b"));
        assert!(!is_protocol(b""));
    }

    #[test]
    fn test_parse_decimal_rejects_signs_and_overflow() {
        assert_eq!(parse_decimal(b"0"), Some(0));
        assert_eq!(parse_decimal(b"18446744073709551615"), Some(u64::MAX));
        assert_eq!(parse_decimal(b"18446744073709551616"), None);
        assert_eq!(parse_decimal(b"+1"), None);
        assert_eq!(parse_decimal(b""), None);
        assert_eq!(parse_decimal(b"1 "), None);
    }

    #[test]
    fn test_list_elements_respects_quoted_strings() {
        fn all(v: &[u8]) -> Vec<&[u8]> {
            list_elements(v).collect()
        }
        assert_eq!(all(b"a, b ,,c"), [&b"a"[..], b"b", b"c"]);
        assert_eq!(all(b"a=\"x,y\", b"), [&b"a=\"x,y\""[..], b"b"]);
        assert_eq!(all(b"a=\"x\\\",y\", b"), [&b"a=\"x\\\",y\""[..], b"b"]);
        assert_eq!(all(b"a=\"unterminated, b"), [&b"a=\"unterminated, b"[..]]);
        assert_eq!(all(b""), Vec::<&[u8]>::new());
        assert_eq!(all(b" , ,"), Vec::<&[u8]>::new());
        // A trailing backslash inside quotes cannot read past the end.
        assert_eq!(all(b"\"\\"), [&b"\"\\"[..]]);
    }

    #[test]
    fn test_find_byte_matches_position() {
        let hay: Vec<u8> = (0..64u8).collect();
        for needle in 0..70u8 {
            assert_eq!(
                find_byte(needle, &hay),
                hay.iter().position(|&b| b == needle)
            );
        }
        assert_eq!(find_byte(b'\n', b"\x0b\x0a"), Some(1));
        assert_eq!(find_byte(1, &[0x81, 0x01]), Some(1));
    }

    #[test]
    fn test_find_byte_at_every_position_among_near_misses() {
        // The bytes next to the needle in value (and with the high bit
        // flipped) are the ones the borrow trick could mistake for it.
        for needle in [0u8, 1, b'\n', b':', b';', 0x7f, 0x80, 0xff] {
            let near = [
                needle.wrapping_sub(1),
                needle.wrapping_add(1),
                needle ^ 0x80,
                needle ^ 0x01,
            ];
            for len in 0..=50usize {
                for filler in near {
                    for at in (0..len).map(Some).chain([None]) {
                        let mut hay = vec![filler; len];
                        if let Some(i) = at {
                            hay[i] = needle;
                            // A second match later must not win.
                            if i + 3 < len {
                                hay[i + 3] = needle;
                            }
                        }
                        assert_eq!(
                            find_byte(needle, &hay),
                            hay.iter().position(|&b| b == needle),
                            "needle {needle:#x} filler {filler:#x} len {len} at {at:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_number_formatting() {
        let mut out = Vec::new();
        push_hex(&mut out, 0);
        out.push(b' ');
        push_hex(&mut out, 0xdead_beef);
        out.push(b' ');
        push_decimal(&mut out, 0);
        out.push(b' ');
        push_decimal(&mut out, u64::MAX);
        assert_eq!(out, b"0 deadbeef 0 18446744073709551615");
    }
}

/// The section 7.9 equality tests: every item that now comes from parse-net
/// against a copy of the http-net 0.7 implementation it replaced.
#[cfg(test)]
mod parity_07 {
    use alloc::{vec, vec::Vec};

    use super::*;

    /// The http-net 0.7 grammar, copied verbatim as the reference.
    mod old {
        use crate::error::HttpError;

        pub(super) const TCHAR: u8 = 1;
        pub(super) const FIELD: u8 = 2;
        pub(super) const TARGET: u8 = 4;
        pub(super) const HEX: u8 = 8;
        pub(super) const QDTEXT: u8 = 16;

        const fn build_classes() -> [u8; 256] {
            let mut t = [0u8; 256];
            let mut b = 0usize;
            while b < 256 {
                let c = b as u8;
                let mut class = 0u8;
                let alpha = c.is_ascii_alphabetic();
                let digit = c.is_ascii_digit();
                if alpha
                    || digit
                    || matches!(
                        c,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
                {
                    class |= TCHAR;
                }
                if c == b'\t' || (c >= 0x20 && c != 0x7f) {
                    class |= FIELD;
                }
                if alpha
                    || digit
                    || matches!(
                        c,
                        b'-' | b'.'
                            | b'_'
                            | b'~'
                            | b'!'
                            | b'$'
                            | b'&'
                            | b'\''
                            | b'('
                            | b')'
                            | b'*'
                            | b'+'
                            | b','
                            | b';'
                            | b'='
                            | b':'
                            | b'@'
                            | b'/'
                            | b'?'
                            | b'%'
                    )
                {
                    class |= TARGET;
                }
                if c.is_ascii_hexdigit() {
                    class |= HEX;
                }
                if c == b'\t'
                    || c == b' '
                    || c == 0x21
                    || (c >= 0x23 && c <= 0x5b)
                    || (c >= 0x5d && c <= 0x7e)
                    || c >= 0x80
                {
                    class |= QDTEXT;
                }
                t[b] = class;
                b += 1;
            }
            t
        }

        static CLASSES: [u8; 256] = build_classes();

        pub(super) fn has(b: u8, class: u8) -> bool {
            CLASSES[b as usize] & class != 0
        }

        pub(super) fn is_token(s: &[u8]) -> bool {
            !s.is_empty() && s.iter().all(|&b| has(b, TCHAR))
        }

        pub(super) fn is_ows(b: u8) -> bool {
            b == b' ' || b == b'\t'
        }

        pub(super) fn trim_ows(mut s: &[u8]) -> &[u8] {
            while let [first, rest @ ..] = s {
                if is_ows(*first) {
                    s = rest;
                } else {
                    break;
                }
            }
            while let [rest @ .., last] = s {
                if is_ows(*last) {
                    s = rest;
                } else {
                    break;
                }
            }
            s
        }

        pub(super) fn check_field_value(value: &[u8]) -> Result<(), HttpError> {
            let mut chunks = value.chunks_exact(8);
            for chunk in &mut chunks {
                let mut word = [0u8; 8];
                word.copy_from_slice(chunk);
                let w = u64::from_le_bytes(word);
                let low = w.wrapping_sub(0x2020_2020_2020_2020) & !w & 0x8080_8080_8080_8080;
                let del = {
                    let x = w ^ 0x7f7f_7f7f_7f7f_7f7f;
                    x.wrapping_sub(0x0101_0101_0101_0101) & !x & 0x8080_8080_8080_8080
                };
                let high = w & 0x8080_8080_8080_8080;
                if low | del | high != 0 {
                    check_field_bytes(chunk)?;
                }
            }
            check_field_bytes(chunks.remainder())
        }

        pub(super) fn check_field_bytes(bytes: &[u8]) -> Result<(), HttpError> {
            for &b in bytes {
                if !has(b, FIELD) {
                    return Err(if b == b'\r' {
                        HttpError::BareCr
                    } else {
                        HttpError::InvalidHeaderValue
                    });
                }
            }
            Ok(())
        }

        pub(super) fn is_reason(s: &[u8]) -> bool {
            s.iter().all(|&b| has(b, FIELD))
        }

        pub(super) fn parse_decimal(s: &[u8]) -> Option<u64> {
            if s.is_empty() {
                return None;
            }
            let mut n: u64 = 0;
            for &b in s {
                if !b.is_ascii_digit() {
                    return None;
                }
                n = n.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
            }
            Some(n)
        }

        pub(super) fn hex_value(b: u8) -> Option<u8> {
            match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            }
        }
    }

    /// A small deterministic generator (xorshift64*), so the corpus is the
    /// same on every run and needs no dependency.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    #[test]
    fn test_classifiers_match_07_tables_for_every_byte() {
        for b in 0u8..=255 {
            assert_eq!(is_tchar(b), old::has(b, old::TCHAR), "tchar {b:#04x}");
            assert_eq!(is_qdtext(b), old::has(b, old::QDTEXT), "qdtext {b:#04x}");
            assert_eq!(class::is_hexdig(b), old::has(b, old::HEX), "hex {b:#04x}");
            assert_eq!(
                Class::FIELD_TEXT.contains(b),
                old::has(b, old::FIELD),
                "field {b:#04x}"
            );
            assert_eq!(
                is_target_char(b),
                old::has(b, old::TARGET),
                "target {b:#04x}"
            );
            assert_eq!(is_ows(b), old::is_ows(b), "ows {b:#04x}");
            assert_eq!(hex_value(b), old::hex_value(b), "hex value {b:#04x}");
            assert_eq!(is_reason(&[b]), old::is_reason(&[b]), "reason {b:#04x}");
        }
    }

    #[test]
    fn test_is_token_matches_07_on_every_one_and_two_byte_input() {
        assert_eq!(is_token(b""), old::is_token(b""));
        for a in 0u8..=255 {
            assert_eq!(is_token(&[a]), old::is_token(&[a]), "{a:#04x}");
            for b in 0u8..=255 {
                let s = [a, b];
                assert_eq!(is_token(&s), old::is_token(&s), "{a:#04x} {b:#04x}");
                let s = [b'x', a, b'y', b];
                assert_eq!(is_token(&s), old::is_token(&s), "{a:#04x} {b:#04x}");
            }
        }
    }

    #[test]
    fn test_field_value_check_matches_07_for_every_byte_at_every_position() {
        // Filler bytes that keep the SWAR fast path (a), sit on its edges
        // (SP, `~`), or force the bytewise path (HTAB, obs-text).
        for filler in [b'a', b' ', b'~', b'\t', 0x80, 0xff] {
            for b in 0u8..=255 {
                for pos in 0..17 {
                    let mut v = vec![filler; 17];
                    v[pos] = b;
                    assert_eq!(
                        check_field_value(&v),
                        old::check_field_value(&v),
                        "filler {filler:#04x} byte {b:#04x} at {pos}"
                    );
                    assert_eq!(
                        old::check_field_value(&v),
                        old::check_field_bytes(&v),
                        "reference fast path, byte {b:#04x} at {pos}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_field_value_check_reports_the_first_of_two_bad_bytes_as_07() {
        // CR against every other refused byte, in either order: the error
        // kind depends on which comes first.
        let bad: Vec<u8> = (0u8..=255).filter(|&b| !old::has(b, old::FIELD)).collect();
        for &x in &bad {
            for &y in &bad {
                for i in 0..17 {
                    for j in 0..17 {
                        if i == j {
                            continue;
                        }
                        let mut v = vec![b'a'; 17];
                        v[i] = x;
                        v[j] = y;
                        assert_eq!(
                            check_field_value(&v),
                            old::check_field_value(&v),
                            "{x:#04x} at {i}, {y:#04x} at {j}"
                        );
                    }
                }
            }
        }
        for len in 0..40 {
            let v = vec![b'a'; len];
            assert_eq!(check_field_value(&v), old::check_field_value(&v));
        }
    }

    #[test]
    fn test_trim_ows_matches_07_for_every_byte_pair_at_both_ends() {
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                for s in [
                    &[a, b][..],
                    &[a, b, b'x'],
                    &[b'x', a, b],
                    &[a, b, b'x', a, b],
                    &[a, b, b'x', b'y', b, a],
                ] {
                    assert_eq!(trim_ows(s), old::trim_ows(s), "{s:?}");
                }
            }
        }
        assert_eq!(trim_ows(b""), old::trim_ows(b""));
    }

    #[test]
    fn test_parse_decimal_matches_07_on_edge_cases() {
        let mut cases: Vec<Vec<u8>> = [
            &b""[..],
            b"0",
            b"00",
            b"007",
            b"+1",
            b"-1",
            b" 1",
            b"1 ",
            b"1\t",
            b"1_000",
            b"1,000",
            b"0x10",
            b"1e3",
            b"\xef\xbc\x91",
            b"18446744073709551615",
            b"18446744073709551616",
            b"18446744073709551620",
            b"99999999999999999999",
            b"184467440737095516150",
            b"000000000000000000000000000018446744073709551615",
            b"000000000000000000000000000018446744073709551616",
        ]
        .iter()
        .map(|s| s.to_vec())
        .collect();
        // Every power of ten and its neighbours, to the edge of u64.
        let mut p: u64 = 1;
        loop {
            for n in [p - 1, p, p + 1] {
                cases.push(alloc::format!("{n}").into_bytes());
            }
            match p.checked_mul(10) {
                Some(next) => p = next,
                None => break,
            }
        }
        for d in 0..=9u8 {
            let mut over = b"1844674407370955161".to_vec();
            over.push(b'0' + d);
            cases.push(over);
        }
        for s in &cases {
            assert_eq!(parse_decimal(s), old::parse_decimal(s), "{s:?}");
        }
        for a in 0u8..=255 {
            assert_eq!(parse_decimal(&[a]), old::parse_decimal(&[a]), "{a:#04x}");
            for b in 0u8..=255 {
                let s = [a, b];
                assert_eq!(parse_decimal(&s), old::parse_decimal(&s), "{s:?}");
            }
        }
    }

    #[test]
    fn test_parse_decimal_matches_07_on_a_generated_corpus() {
        // Mostly digits, with the bytes a Content-Length attack uses mixed in.
        const ALPHABET: &[u8] = b"0123456789012345678901234567890123456789+- \t,.x\x00\xff";
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for _ in 0..200_000 {
            let len = rng.below(26);
            let s: Vec<u8> = (0..len)
                .map(|_| ALPHABET[rng.below(ALPHABET.len())])
                .collect();
            assert_eq!(parse_decimal(&s), old::parse_decimal(&s), "{s:?}");
        }
        for _ in 0..200_000 {
            let n = rng.next() >> rng.below(64);
            let s = alloc::format!("{n}").into_bytes();
            assert_eq!(parse_decimal(&s), Some(n));
            assert_eq!(parse_decimal(&s), old::parse_decimal(&s));
        }
    }
}
