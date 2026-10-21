//! Differential check against httparse (default, strict configuration):
//! on every request head http-net accepts, httparse must return a complete
//! head of the same length, method, target, version, and fields. Where the
//! two differ it must be because http-net refused, which never reaches
//! this comparison. One documented exception: http-net processes HTTP/1.2
//! to 1.9 as 1.1 (RFC 9110 section 2.5), which httparse refuses.

#![no_main]

use http_net::{ServerConn, ServerEvent, Version};
use libfuzzer_sys::fuzz_target;

fn trim(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = s {
        s = rest;
    }
    s
}

/// Whether the request line (after any leading empty lines) ends in
/// `HTTP/1.x` with `x` from 2 to 9.
fn minor_above_one(data: &[u8]) -> bool {
    let mut rest = data;
    while let Some(r) = rest.strip_prefix(b"\r\n") {
        rest = r;
    }
    let end = rest.iter().position(|&b| b == b'\r').unwrap_or(rest.len());
    let line = &rest[..end];
    line.len() >= 8
        && line[line.len() - 8..line.len() - 1] == *b"HTTP/1."
        && (b'2'..=b'9').contains(&line[line.len() - 1])
}

fuzz_target!(|data: &[u8]| {
    let mut conn = ServerConn::new();
    if conn.feed(data) != data.len() {
        return;
    }
    let (method, target, version, fields) = match conn.poll() {
        Ok(ServerEvent::Request(req)) => (
            req.method_str().to_string(),
            req.target().to_string(),
            req.version(),
            req.headers()
                .map(|(n, v)| (n.to_string(), v.to_vec()))
                .collect::<Vec<_>>(),
        ),
        _ => return,
    };
    let head_len = data.len() - conn.remaining_input().len();
    if version == Version::Http11 && minor_above_one(data) {
        return;
    }

    let mut storage = [httparse::EMPTY_HEADER; 128];
    let mut parsed = httparse::Request::new(&mut storage);
    let status = match parsed.parse(data) {
        Ok(status) => status,
        Err(e) => panic!(
            "http-net accepted a head httparse refuses ({e:?}): {:?}",
            String::from_utf8_lossy(data)
        ),
    };
    let httparse::Status::Complete(len) = status else {
        panic!(
            "httparse found the head incomplete: {:?}",
            String::from_utf8_lossy(data)
        );
    };
    assert_eq!(len, head_len, "head length differs");
    assert_eq!(parsed.method, Some(method.as_str()), "method differs");
    assert_eq!(parsed.path, Some(target.as_str()), "target differs");
    let expected_version = match version {
        Version::Http10 => 0,
        _ => 1,
    };
    assert_eq!(parsed.version, Some(expected_version), "version differs");
    let theirs: Vec<(String, Vec<u8>)> = parsed
        .headers
        .iter()
        .map(|h| (h.name.to_string(), trim(h.value).to_vec()))
        .collect();
    assert_eq!(theirs, fields, "fields differ");
});
