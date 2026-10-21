//! An independent reference parser for one request, written straight from
//! the RFC 9112 / RFC 9110 ABNF with no incremental state and its own
//! character classes. The differential property test
//! (`tests/prop_reference.rs`) and the `reference_diff` and `chunk_line`
//! fuzz targets all use this one file, so they test one contract; it must
//! follow the crate when the crate's rules change.

use http_net::{Limits, Version};

use super::{Ev, drive_server};

/// A request as the reference reads it.
#[derive(Debug, PartialEq, Eq)]
pub struct RefRequest {
    pub method: Vec<u8>,
    pub target: Vec<u8>,
    pub http11: bool,
    pub fields: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: Vec<u8>,
}

/// The body budget both sides use (the default `Limits::max_body`).
pub const MAX_BODY: usize = 1 << 20;

/// The field-count budget both sides use (the default
/// `Limits::max_headers`), applied to the header section and the trailer
/// section separately. The byte budgets (8 KiB start line, 16 KiB header
/// section and chunk extensions) are not modelled: callers keep inputs
/// shorter than 8 KiB so they cannot be reached.
pub const MAX_FIELDS: usize = 100;

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn is_token(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().copied().all(is_tchar)
}

fn is_vchar_or_obs(b: u8) -> bool {
    (0x21..=0x7e).contains(&b) || b >= 0x80
}

fn is_pchar_like(b: u8) -> bool {
    // unreserved / sub-delims / ":" / "@" / "/" / "?"
    b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?".contains(&b)
}

/// Every `%` followed by two hex digits; other bytes from `allowed`.
fn pct_ok(s: &[u8], allowed: impl Fn(u8) -> bool) -> bool {
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            if !(s.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                && s.get(i + 2).is_some_and(u8::is_ascii_hexdigit))
            {
                return false;
            }
            i += 3;
        } else if allowed(s[i]) {
            i += 1;
        } else {
            return false;
        }
    }
    true
}

/// `reg-name = *( unreserved / pct-encoded / sub-delims )`.
fn reg_name_ok(s: &[u8]) -> bool {
    pct_ok(s, |b| {
        b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&b)
    })
}

fn ip_literal_ok(inner: &[u8]) -> bool {
    !inner.is_empty()
        && inner
            .iter()
            .all(|&b| b.is_ascii_hexdigit() || b":.vV".contains(&b))
}

/// `uri-host [ ":" port ]`; `require_port` for CONNECT's authority-form.
fn authority_ok(s: &[u8], require_port: bool) -> bool {
    let (host_ok, port) = if s.first() == Some(&b'[') {
        let Some(close) = s.iter().position(|&b| b == b']') else {
            return false;
        };
        let rest = &s[close + 1..];
        let port = match rest {
            [] => None,
            [b':', p @ ..] => Some(p),
            _ => return false,
        };
        (ip_literal_ok(&s[1..close]), port)
    } else {
        match s.iter().rposition(|&b| b == b':') {
            Some(c) => (reg_name_ok(&s[..c]), Some(&s[c + 1..])),
            None => (reg_name_ok(s), None),
        }
    };
    let port_ok = match port {
        None => !require_port,
        Some(p) => p.iter().all(u8::is_ascii_digit) && !(require_port && p.is_empty()),
    };
    host_ok && port_ok
}

/// RFC 9110 section 4.2.1: an `http` URI with an empty host is invalid,
/// and a `Host` of `:80` names no host (0.3).
fn host_present(authority: &[u8]) -> bool {
    !authority.is_empty() && authority[0] != b':'
}

fn target_ok(method: &[u8], target: &[u8]) -> bool {
    match target {
        [] => false,
        [b'*'] => method == b"OPTIONS",
        [b'/', ..] => method != b"CONNECT" && pct_ok(target, is_pchar_like),
        _ if method == b"CONNECT" => host_present(target) && authority_ok(target, true),
        _ => {
            // absolute-form, hierarchical with an authority:
            // scheme "://" authority path-abempty [ "?" query ]
            let Some(colon) = target.iter().position(|&b| b == b':') else {
                return false;
            };
            let scheme = &target[..colon];
            let Some(rest) = target[colon + 1..].strip_prefix(b"//") else {
                return false;
            };
            let end = rest
                .iter()
                .position(|&b| b == b'/' || b == b'?')
                .unwrap_or(rest.len());
            let (authority, tail) = rest.split_at(end);
            scheme.first().is_some_and(u8::is_ascii_alphabetic)
                && scheme
                    .iter()
                    .all(|&b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
                // userinfo ('@') is not a reg-name character, so
                // authority_ok refuses it as RFC 9110 section 4.2.4 asks.
                && host_present(authority)
                && authority_ok(authority, false)
                && pct_ok(tail, is_pchar_like)
        }
    }
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = s {
        s = rest;
    }
    s
}

/// Reads one CRLF line starting at `*pos`.
fn line<'a>(input: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let rest = &input[*pos..];
    let lf = rest.iter().position(|&b| b == b'\n')?;
    let with_cr = &rest[..lf];
    let content = with_cr.strip_suffix(b"\r")?;
    *pos += lf + 1;
    Some(content)
}

fn field(l: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let colon = l.iter().position(|&b| b == b':')?;
    let name = &l[..colon];
    let value = trim(&l[colon + 1..]);
    let value_ok = value
        .iter()
        .all(|&b| b == b' ' || b == b'\t' || is_vchar_or_obs(b));
    (is_token(name) && value_ok).then(|| (name.to_vec(), value.to_vec()))
}

fn ws_len(s: &[u8]) -> usize {
    s.iter().take_while(|&&b| b == b' ' || b == b'\t').count()
}

/// One chunk-size line (without its CRLF): the size, if the line is valid.
///
/// `chunk-size [ chunk-ext ]`, `chunk-ext = *( BWS ";" BWS name
/// [ BWS "=" BWS ( token / quoted-string ) ] )`, at most 16 hex digits.
pub fn chunk_size(l: &[u8]) -> Option<u64> {
    let digits = l.iter().take_while(|b| b.is_ascii_hexdigit()).count();
    if digits == 0 || digits > 16 {
        return None;
    }
    let size = u64::from_str_radix(std::str::from_utf8(&l[..digits]).ok()?, 16).ok()?;
    let mut rest = &l[digits..];
    while !rest.is_empty() {
        rest = rest[ws_len(rest)..].strip_prefix(b";")?;
        rest = &rest[ws_len(rest)..];
        let name = rest.iter().take_while(|&&b| is_tchar(b)).count();
        if name == 0 {
            return None;
        }
        rest = &rest[name..];
        let ws = ws_len(rest);
        if rest.get(ws) == Some(&b'=') {
            rest = &rest[ws + 1..];
            rest = &rest[ws_len(rest)..];
            if rest.first() == Some(&b'"') {
                let mut i = 1;
                loop {
                    match rest.get(i)? {
                        b'"' => break,
                        b'\\' => {
                            let next = *rest.get(i + 1)?;
                            if !(next == b'\t' || next == b' ' || is_vchar_or_obs(next)) {
                                return None;
                            }
                            i += 2;
                        }
                        &b if b == b'\t'
                            || b == b' '
                            || b == 0x21
                            || (0x23..=0x5b).contains(&b)
                            || (0x5d..=0x7e).contains(&b)
                            || b >= 0x80 =>
                        {
                            i += 1
                        }
                        _ => return None,
                    }
                }
                rest = &rest[i + 1..];
            } else {
                let tok = rest.iter().take_while(|&&b| is_tchar(b)).count();
                if tok == 0 {
                    return None;
                }
                rest = &rest[tok..];
            }
        }
        // Trailing whitespace must introduce another extension.
        let ws = ws_len(rest);
        if ws == rest.len() && ws > 0 {
            return None;
        }
    }
    Some(size)
}

/// The reference reading of the first request in `input`, or `None` if it
/// is refused or incomplete.
pub fn reference(input: &[u8]) -> Option<RefRequest> {
    let mut pos = 0;
    while input[pos..].starts_with(b"\r\n") {
        pos += 2;
    }
    let start = line(input, &mut pos)?;
    let parts: Vec<&[u8]> = start.split(|&b| b == b' ').collect();
    let [method, target, version] = parts.as_slice() else {
        return None;
    };
    if !is_token(method) || !target_ok(method, target) {
        return None;
    }
    let http11 = match *version {
        [b'H', b'T', b'T', b'P', b'/', b'1', b'.', b'0'] => false,
        [b'H', b'T', b'T', b'P', b'/', b'1', b'.', d] if d.is_ascii_digit() => true,
        _ => return None,
    };

    let mut fields = Vec::new();
    loop {
        let l = line(input, &mut pos)?;
        if l.is_empty() {
            break;
        }
        if fields.len() == MAX_FIELDS {
            return None;
        }
        fields.push(field(l)?);
    }

    let named = |n: &str| -> Vec<&Vec<u8>> {
        fields
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(n.as_bytes()))
            .map(|(_, v)| v)
            .collect()
    };
    let hosts = named("host");
    if hosts.len() > 1 || (http11 && hosts.is_empty()) {
        return None;
    }
    if let Some(h) = hosts.first() {
        // An empty Host is allowed (a target without an authority).
        if !(h.is_empty() || (host_present(h) && authority_ok(h, false))) {
            return None;
        }
    }
    let lengths = named("content-length");
    let codings: Vec<Vec<u8>> = named("transfer-encoding")
        .iter()
        .flat_map(|v| v.split(|&b| b == b','))
        .map(|e| trim(e).to_vec())
        .filter(|e| !e.is_empty())
        .collect();
    let has_te = !named("transfer-encoding").is_empty();
    let body = if has_te {
        let only_chunked = codings.len() == 1 && codings[0].eq_ignore_ascii_case(b"chunked");
        if !http11 || !lengths.is_empty() || !only_chunked {
            return None;
        }
        let mut body = Vec::new();
        loop {
            let size = usize::try_from(chunk_size(line(input, &mut pos)?)?).ok()?;
            if size == 0 {
                break;
            }
            if body.len() + size > MAX_BODY {
                return None;
            }
            let data = input.get(pos..pos + size)?;
            body.extend_from_slice(data);
            pos += size;
            if input.get(pos..pos + 2)? != b"\r\n" {
                return None;
            }
            pos += 2;
        }
        let mut trailers = 0;
        loop {
            let l = line(input, &mut pos)?;
            if l.is_empty() {
                break;
            }
            if trailers == MAX_FIELDS {
                return None;
            }
            field(l)?;
            trailers += 1;
        }
        body
    } else {
        match lengths.as_slice() {
            [] => Vec::new(),
            [one] => {
                if one.is_empty() || !one.iter().all(u8::is_ascii_digit) {
                    return None;
                }
                let n: usize = std::str::from_utf8(one).ok()?.parse().ok()?;
                if n > MAX_BODY {
                    return None;
                }
                input.get(pos..pos + n)?.to_vec()
            }
            _ => return None,
        }
    };
    Some(RefRequest {
        method: method.to_vec(),
        target: target.to_vec(),
        http11,
        fields,
        body,
    })
}

/// The crate's reading of the first request, fed whole with the default
/// limits: `None` if it was refused or incomplete.
pub fn crate_first(input: &[u8]) -> Option<RefRequest> {
    let events = drive_server(&[input], Limits::new());
    let mut iter = events.into_iter();
    let Some(Ev::Head {
        method,
        target,
        version,
        headers,
        ..
    }) = iter.next()
    else {
        return None;
    };
    let mut body = Vec::new();
    for e in iter {
        match e {
            Ev::Body(b) => body.extend_from_slice(&b),
            Ev::End => {
                return Some(RefRequest {
                    method: method.into_bytes(),
                    target: target.into_bytes(),
                    http11: version == Version::Http11,
                    fields: headers
                        .into_iter()
                        .map(|(n, v)| (n.into_bytes(), v))
                        .collect(),
                    body,
                });
            }
            _ => return None,
        }
    }
    None
}
