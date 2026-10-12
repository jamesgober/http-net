//! Differential test against a reference parser.
//!
//! The reference below is written straight from the RFC 9112 / RFC 9110
//! ABNF, independently of the crate's code: it takes a complete message,
//! splits it into lines, and checks each rule in the most obvious way, with
//! no incremental state, no buffer management, and its own character
//! classes. Valid seed requests are mutated (bytes inserted, replaced, or
//! removed, biased towards the bytes that matter to framing) and both
//! parsers must agree on whether the first message is valid and, if it is,
//! on its method, target, version, fields, and body.

mod common;

use common::{Ev, drive_server};
use http_net::Limits;
use proptest::prelude::*;

#[derive(Debug, PartialEq, Eq)]
struct RefRequest {
    method: Vec<u8>,
    target: Vec<u8>,
    http11: bool,
    fields: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
}

const MAX_BODY: usize = 1 << 20;

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

fn pct_ok(s: &[u8], extra: &[u8]) -> bool {
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            if !(s.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                && s.get(i + 2).is_some_and(u8::is_ascii_hexdigit))
            {
                return false;
            }
            i += 3;
        } else if is_pchar_like(s[i]) || extra.contains(&s[i]) {
            i += 1;
        } else {
            return false;
        }
    }
    true
}

fn reg_name_ok(s: &[u8]) -> bool {
    s.iter()
        .all(|&b| b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=%".contains(&b))
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

/// RFC 9110 section 4.2.1: an `http` URI with an empty host is invalid.
fn host_present(authority: &[u8]) -> bool {
    !authority.is_empty() && authority[0] != b':'
}

fn target_ok(method: &[u8], target: &[u8]) -> bool {
    match target {
        [] => false,
        [b'*'] => method == b"OPTIONS",
        [b'/', ..] => method != b"CONNECT" && pct_ok(target, b""),
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
                && pct_ok(tail, b"")
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

fn chunk_size(l: &[u8]) -> Option<usize> {
    let digits = l.iter().take_while(|b| b.is_ascii_hexdigit()).count();
    if digits == 0 || digits > 16 {
        return None;
    }
    let size = u64::from_str_radix(std::str::from_utf8(&l[..digits]).ok()?, 16).ok()?;
    // chunk-ext = *( BWS ";" BWS name [ BWS "=" BWS ( token / quoted-string ) ] )
    let mut rest = &l[digits..];
    while !rest.is_empty() {
        let ws = rest
            .iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count();
        rest = rest[ws..].strip_prefix(b";")?;
        let ws = rest
            .iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count();
        rest = &rest[ws..];
        let name = rest.iter().take_while(|&&b| is_tchar(b)).count();
        if name == 0 {
            return None;
        }
        rest = &rest[name..];
        let ws = rest
            .iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count();
        if rest.get(ws) == Some(&b'=') {
            rest = &rest[ws + 1..];
            let ws = rest
                .iter()
                .take_while(|&&b| b == b' ' || b == b'\t')
                .count();
            rest = &rest[ws..];
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
        let ws = rest
            .iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count();
        if ws == rest.len() && ws > 0 {
            return None;
        }
    }
    usize::try_from(size).ok()
}

fn reference(input: &[u8]) -> Option<RefRequest> {
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
        if !h.is_empty() && !authority_ok(h, false) {
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
            let size = chunk_size(line(input, &mut pos)?)?;
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
        loop {
            let l = line(input, &mut pos)?;
            if l.is_empty() {
                break;
            }
            field(l)?;
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

/// The crate's view of the first message: `None` if it was refused.
fn crate_first(input: &[u8]) -> Option<RefRequest> {
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
                    http11: version == http_net::Version::Http11,
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

const SEEDS: &[&[u8]] = &[
    b"GET /index.html?x=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n",
    b"POST /form HTTP/1.1\r\nHost: a:8080\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello",
    b"POST /up HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n4;x=\"y\"\r\nWiki\r\n5\r\npedia\r\n0\r\nT: v\r\n\r\n",
    b"OPTIONS * HTTP/1.1\r\nHost: [::1]:80\r\n\r\n",
    b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
    b"GET http://example.com/a%20b HTTP/1.1\r\nHost: example.com\r\n\r\n",
    b"GET / HTTP/1.0\r\nUser-Agent: test/1.0\r\n\r\n",
    b"\r\nPUT /x HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\nX-A: 1\r\nX-B: \t2 \r\n\r\n",
];

const INTERESTING: &[u8] = b"\r\n \t:;,=\"\\\x00\x7f\x80\xffaZ09%/?*-";

#[derive(Clone, Debug)]
enum Op {
    Insert(usize, u8),
    Replace(usize, u8),
    Remove(usize),
}

fn op() -> impl Strategy<Value = Op> {
    let byte = prop_oneof![
        3 => proptest::sample::select(INTERESTING),
        1 => any::<u8>(),
    ];
    prop_oneof![
        (any::<usize>(), byte.clone()).prop_map(|(p, b)| Op::Insert(p, b)),
        (any::<usize>(), byte).prop_map(|(p, b)| Op::Replace(p, b)),
        any::<usize>().prop_map(Op::Remove),
    ]
}

fn mutate(seed: &[u8], ops: &[Op]) -> Vec<u8> {
    let mut v = seed.to_vec();
    for op in ops {
        match *op {
            Op::Insert(p, b) => v.insert(p % (v.len() + 1), b),
            Op::Replace(p, b) if !v.is_empty() => {
                let i = p % v.len();
                v[i] = b;
            }
            Op::Remove(p) if !v.is_empty() => {
                let _ = v.remove(p % v.len());
            }
            _ => {}
        }
    }
    v
}

#[test]
fn test_seeds_are_valid_for_both() {
    for seed in SEEDS {
        let r = reference(seed);
        assert!(
            r.is_some(),
            "reference refuses {:?}",
            String::from_utf8_lossy(seed)
        );
        assert_eq!(r, crate_first(seed), "{:?}", String::from_utf8_lossy(seed));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8192))]

    #[test]
    fn prop_agrees_with_reference(
        seed in proptest::sample::select(SEEDS),
        ops in proptest::collection::vec(op(), 1..4),
    ) {
        let input = mutate(seed, &ops);
        prop_assert_eq!(
            reference(&input),
            crate_first(&input),
            "input {:?}",
            String::from_utf8_lossy(&input)
        );
    }
}

#[test]
fn test_every_single_byte_mutation_agrees() {
    // Exhaustive over one mutation: every position of every seed, every
    // interesting byte inserted and substituted, and every byte removed.
    let mut accepted = 0usize;
    let mut refused = 0usize;
    for seed in SEEDS {
        for pos in 0..=seed.len() {
            let mut ops: Vec<Op> = INTERESTING
                .iter()
                .flat_map(|&b| [Op::Insert(pos, b), Op::Replace(pos, b)])
                .collect();
            ops.push(Op::Remove(pos));
            for op in ops {
                if !matches!(op, Op::Insert(..)) && pos == seed.len() {
                    continue;
                }
                let input = mutate(seed, &[op]);
                let expected = reference(&input);
                assert_eq!(
                    expected,
                    crate_first(&input),
                    "input {:?}",
                    String::from_utf8_lossy(&input)
                );
                if expected.is_some() {
                    accepted += 1;
                } else {
                    refused += 1;
                }
            }
        }
    }
    // Both verdicts are well represented, so the comparison is not vacuous.
    assert!(
        accepted > 1000 && refused > 1000,
        "accepted {accepted}, refused {refused}"
    );
}
