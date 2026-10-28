//! An HTTP Garden origin built on the http-net sans-IO server.
//!
//! Every request the parser accepts is answered `200 OK` with a JSON body
//! that describes how http-net understood it, in the shape every other
//! Garden origin uses:
//!
//! ```text
//! {"method":"<b64>","version":"<b64>","uri":"<b64>","headers":[["<b64>","<b64>"],...],"body":"<b64>"}
//! ```
//!
//! Each value is standard base64 (RFC 4648 section 4, with padding) of the
//! raw bytes. A request the parser refuses gets the error response that
//! [`Response::from_error`] builds (a 4xx or 5xx status), and the connection
//! closes. The Garden reads any status other than 200 as a rejection.
//!
//! Nothing here interprets the request beyond what [`ServerConn`] reports:
//! no `100 Continue` is sent (the Garden sends each payload whole), no
//! expectation is refused, and trailers are dropped, matching the hyper
//! origin.

use std::io::{self, Read, Write};

use http_net::{HttpError, RequestHead, Response, ServerConn, ServerEvent, Version};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Appends the standard base64 encoding of `input`, with `=` padding.
pub fn push_base64(out: &mut String, input: &[u8]) {
    let mut chunks = input.chunks_exact(3);
    for c in &mut chunks {
        let n = (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
        for shift in [18, 12, 6, 0] {
            out.push(char::from(B64[((n >> shift) & 63) as usize]));
        }
    }
    match *chunks.remainder() {
        [a] => {
            let n = u32::from(a) << 16;
            out.push(char::from(B64[((n >> 18) & 63) as usize]));
            out.push(char::from(B64[((n >> 12) & 63) as usize]));
            out.push_str("==");
        }
        [a, b] => {
            let n = (u32::from(a) << 16) | (u32::from(b) << 8);
            out.push(char::from(B64[((n >> 18) & 63) as usize]));
            out.push(char::from(B64[((n >> 12) & 63) as usize]));
            out.push(char::from(B64[((n >> 6) & 63) as usize]));
            out.push('=');
        }
        _ => {}
    }
}

/// The standard base64 encoding of `input`.
#[must_use]
pub fn base64(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    push_base64(&mut out, input);
    out
}

/// The version text the Garden expects (`1.0` or `1.1`, no `HTTP/`).
fn version_text(version: Version) -> &'static str {
    match version {
        Version::Http10 => "1.0",
        _ => "1.1",
    }
}

/// The JSON fields that come from the request head, up to and including the
/// header list. [`finish_echo`] adds the body.
#[must_use]
pub fn head_echo(head: &RequestHead<'_>) -> String {
    let mut out = String::with_capacity(256);
    out.push_str("{\"method\":\"");
    push_base64(&mut out, head.method_str().as_bytes());
    out.push_str("\",\"version\":\"");
    push_base64(&mut out, version_text(head.version()).as_bytes());
    out.push_str("\",\"uri\":\"");
    push_base64(&mut out, head.target().as_bytes());
    out.push_str("\",\"headers\":[");
    for (i, (name, value)) in head.headers().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("[\"");
        push_base64(&mut out, name.as_bytes());
        out.push_str("\",\"");
        push_base64(&mut out, value);
        out.push_str("\"]");
    }
    out.push(']');
    out
}

/// Completes the JSON object started by [`head_echo`] with the decoded body.
#[must_use]
pub fn finish_echo(mut head_json: String, body: &[u8]) -> String {
    head_json.push_str(",\"body\":\"");
    push_base64(&mut head_json, body);
    head_json.push_str("\"}");
    head_json
}

fn to_io(e: HttpError) -> io::Error {
    io::Error::other(e.to_string())
}

/// Serves one connection until the peer closes it, the parser refuses a
/// request, or a request asks to close. Pipelined requests are answered in
/// order. Pending responses are written before every read, so a client that
/// waits for silence (as the Garden does) sees each answer promptly.
///
/// # Errors
///
/// An I/O error from `stream`. Parse errors are not errors here: they are
/// answered on the wire and end the connection normally.
pub fn serve_connection<S: Read + Write>(stream: &mut S) -> io::Result<()> {
    let mut conn = ServerConn::new();
    let mut out: Vec<u8> = Vec::new();
    let mut body: Vec<u8> = Vec::new();
    let mut head_json: Option<String> = None;
    loop {
        match conn.poll() {
            Ok(ServerEvent::Request(head)) => {
                head_json = Some(head_echo(&head));
                body.clear();
            }
            Ok(ServerEvent::Body(chunk)) => body.extend_from_slice(chunk),
            Ok(ServerEvent::RequestEnd) => {
                let json = finish_echo(head_json.take().unwrap_or_default(), &body);
                body.clear();
                let response = Response::new(200)
                    .header("content-type", "application/json")
                    .body(json.into_bytes());
                conn.respond(&response, &mut out).map_err(to_io)?;
            }
            Ok(ServerEvent::NeedInput) => {
                flush(stream, &mut out)?;
                let spare = conn.read_buf();
                if spare.is_empty() {
                    // Cannot happen while the parser enforces its limits;
                    // never spin on it.
                    return Err(io::Error::other("input buffer full"));
                }
                let n = match stream.read(spare) {
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                };
                if n == 0 {
                    conn.feed_eof();
                } else {
                    conn.commit(n);
                }
            }
            Ok(ServerEvent::Closed | ServerEvent::Upgraded) => {
                return flush(stream, &mut out);
            }
            Ok(ServerEvent::Trailers(_) | ServerEvent::AwaitingResponse) => {
                // Trailers are dropped. AwaitingResponse cannot follow
                // RequestEnd here, since every request is answered there.
            }
            Ok(_) => return flush(stream, &mut out),
            Err(e) => {
                // One error response, then close (HttpError's contract).
                let _ = conn.respond(&Response::from_error(&e), &mut out);
                return flush(stream, &mut out);
            }
        }
    }
}

fn flush<S: Write>(stream: &mut S, out: &mut Vec<u8>) -> io::Result<()> {
    if !out.is_empty() {
        stream.write_all(out)?;
        stream.flush()?;
        out.clear();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_rfc4648_vectors() {
        let cases: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (input, want) in cases {
            assert_eq!(base64(input), want);
        }
        assert_eq!(base64(&[0xff, 0xfe, 0x00]), "//4A");
    }
}
