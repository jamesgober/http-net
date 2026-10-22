//! Byte classes and small scanners for the RFC 9110 / RFC 9112 grammar.
//!
//! Every classification is a lookup in one 256-entry table, so validating a
//! line costs one load and one mask per byte. The table is built at compile
//! time from the ABNF, which keeps the rules in one reviewable place.

use crate::{error::HttpError, write::Output};

/// `tchar`: the characters allowed in a token (method, field name, coding).
const TCHAR: u8 = 1;
/// `field-vchar / SP / HTAB`: the characters allowed inside a field value.
const FIELD: u8 = 2;
/// RFC 3986 characters allowed in a request target (`%` is checked apart).
const TARGET: u8 = 4;
/// `HEXDIG`.
const HEX: u8 = 8;
/// `qdtext`: characters allowed unescaped inside a quoted string.
const QDTEXT: u8 = 16;

const fn build_classes() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut b = 0usize;
    while b < 256 {
        let c = b as u8;
        let mut class = 0u8;
        let alpha = c.is_ascii_alphabetic();
        let digit = c.is_ascii_digit();
        // tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "."
        //       / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
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
        // field-vchar = VCHAR / obs-text, plus SP and HTAB inside a value.
        if c == b'\t' || (c >= 0x20 && c != 0x7f) {
            class |= FIELD;
        }
        // unreserved / sub-delims / ":" / "@" / "/" / "?" and the "%" that
        // introduces a pct-encoded triple (whose digits are checked apart).
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
        // qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
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

#[inline]
fn has(b: u8, class: u8) -> bool {
    CLASSES[b as usize] & class != 0
}

/// Whether `b` may appear in a token.
#[inline]
pub(crate) fn is_tchar(b: u8) -> bool {
    has(b, TCHAR)
}

/// Whether `s` is a non-empty token.
#[inline]
pub(crate) fn is_token(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(|&b| is_tchar(b))
}

/// Whether `b` is optional whitespace (`SP / HTAB`).
#[inline]
pub(crate) fn is_ows(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Strips `OWS` (spaces and tabs only) from both ends.
///
/// `<[u8]>::trim_ascii` is deliberately not used: it also strips vertical tab
/// and form feed, which are invalid in a field value and must be rejected,
/// not silently removed.
#[inline]
pub(crate) fn trim_ows(mut s: &[u8]) -> &[u8] {
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

/// Validates a field value (already trimmed of OWS).
///
/// A CR is reported as [`HttpError::BareCr`] because that is the smuggling
/// vector it represents; every other control byte is
/// [`HttpError::InvalidHeaderValue`].
#[inline]
pub(crate) fn check_field_value(value: &[u8]) -> Result<(), HttpError> {
    // Fast path: plain printable ASCII, eight bytes at a time.
    let mut chunks = value.chunks_exact(8);
    for chunk in &mut chunks {
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        let w = u64::from_le_bytes(word);
        // A byte is "suspicious" when it is below 0x20, equal to 0x7f, or has
        // the high bit set. Suspicious words drop to the exact per-byte check.
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

#[inline]
fn check_field_bytes(bytes: &[u8]) -> Result<(), HttpError> {
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

/// Validates a reason phrase: `*( HTAB / SP / VCHAR / obs-text )`.
#[inline]
pub(crate) fn is_reason(s: &[u8]) -> bool {
    s.iter().all(|&b| has(b, FIELD))
}

/// Validates the characters of a request target: RFC 3986 characters only,
/// and every `%` followed by two hex digits.
pub(crate) fn is_target_chars(s: &[u8]) -> bool {
    let mut i = 0;
    while i < s.len() {
        let b = s[i];
        if !has(b, TARGET) {
            return false;
        }
        if b == b'%' {
            match (s.get(i + 1), s.get(i + 2)) {
                (Some(&h1), Some(&h2)) if has(h1, HEX) && has(h2, HEX) => i += 3,
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
            (Some(&h1), Some(&h2)) if has(h1, HEX) && has(h2, HEX) => i = at + 3,
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

/// Parses `1*DIGIT` into a `u64`, refusing signs, spaces, and overflow.
pub(crate) fn parse_decimal(s: &[u8]) -> Option<u64> {
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

/// The value of one hex digit, if `b` is one.
#[inline]
pub(crate) fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Whether `b` may appear unescaped inside a quoted string.
#[inline]
pub(crate) fn is_qdtext(b: u8) -> bool {
    has(b, QDTEXT)
}

/// Iterates the elements of a comma-separated list value, trimmed of OWS,
/// skipping empty elements (RFC 9110 section 5.6.1.2).
///
/// A comma inside a quoted string does not end an element: `a="x,y", b` is
/// two elements, `a="x,y"` and `b` (a backslash escapes the next byte
/// inside the quotes). An unterminated quote runs to the end of the value.
/// This is the walker `parse-net` specifies; it stays here until http-net
/// takes that crate as a dependency.
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
    let mut chunks = hay.chunks_exact(8);
    let mut base = 0usize;
    for chunk in &mut chunks {
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        let x = u64::from_le_bytes(word) ^ pattern;
        let found = x.wrapping_sub(0x0101_0101_0101_0101) & !x & 0x8080_8080_8080_8080;
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
    use alloc::vec::Vec;

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
    fn test_field_value_fast_path_agrees_with_bytewise() {
        for b in 0u8..=255 {
            for pos in 0..17 {
                let mut v = alloc::vec![b'a'; 17];
                v[pos] = b;
                let fast = check_field_value(&v).is_ok();
                let slow = check_field_bytes(&v).is_ok();
                assert_eq!(fast, slow, "byte {b:#x} at {pos}");
            }
        }
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
