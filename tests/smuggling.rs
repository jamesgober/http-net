//! Request smuggling vectors. Each one is a message that two HTTP
//! implementations have been known to frame differently (CL.TE, TE.CL,
//! TE.TE obfuscation, line-ending confusion). Every vector must be refused
//! with its specific error, whole or split, and the connection must not
//! produce a second request from the leftover bytes.

mod common;

use common::{Ev, drive_server};
use http_net::{HttpError, Limits, Response, ServerConn, ServerEvent};

const VECTORS: &[(&str, &[u8], HttpError)] = &[
    (
        "CL.TE: both framings present",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGPOST / HTTP/1.1\r\n\r\n",
        HttpError::ConflictingFraming,
    ),
    (
        "TE.CL: both framings present, other order",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n",
        HttpError::ConflictingFraming,
    ),
    (
        "TE.TE: space before colon",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding : chunked\r\n\r\n",
        HttpError::WhitespaceBeforeColon,
    ),
    (
        "TE.TE: obfuscated coding name",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: xchunked\r\n\r\n",
        HttpError::InvalidTransferEncoding,
    ),
    (
        "TE.TE: second header hides chunked",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: cow\r\n\r\n",
        HttpError::InvalidTransferEncoding,
    ),
    (
        "TE.TE: identity after chunked",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, identity\r\n\r\n",
        HttpError::InvalidTransferEncoding,
    ),
    (
        "TE.TE: folded continuation",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding:\r\n chunked\r\n\r\n",
        HttpError::ObsFold,
    ),
    (
        "TE.TE: leading space makes it a fold of the request line",
        b"POST / HTTP/1.1\r\n Transfer-Encoding: chunked\r\nHost: a\r\n\r\n",
        HttpError::ObsFold,
    ),
    (
        "TE.TE: vertical tab before the value",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: \x0bchunked\r\n\r\n",
        HttpError::InvalidHeaderValue,
    ),
    (
        "TE.TE: form feed after the value",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\x0c\r\n\r\n",
        HttpError::InvalidHeaderValue,
    ),
    (
        "TE.TE: NUL inside the field name",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer\x00-Encoding: chunked\r\n\r\n",
        HttpError::InvalidHeaderName,
    ),
    (
        "TE.TE: bare CR inside the value",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chun\rked\r\n\r\n",
        HttpError::BareCr,
    ),
    (
        "bare LF splits a header in two for lenient parsers",
        b"POST / HTTP/1.1\r\nHost: a\r\nX: y\nTransfer-Encoding: chunked\r\n\r\n",
        HttpError::BareLf,
    ),
    (
        "bare CR as a line ending",
        b"POST / HTTP/1.1\r\nHost: a\rContent-Length: 5\r\n\r\n",
        HttpError::BareCr,
    ),
    (
        "duplicate Content-Length with different values",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!",
        HttpError::DuplicateContentLength,
    ),
    (
        "duplicate Content-Length with equal values",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
        HttpError::DuplicateContentLength,
    ),
    (
        "Content-Length as a list",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5, 5\r\n\r\nhello",
        HttpError::InvalidContentLength,
    ),
    (
        "hexadecimal Content-Length",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0x5\r\n\r\nhello",
        HttpError::InvalidContentLength,
    ),
    (
        "Transfer-Encoding in HTTP/1.0",
        b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n",
        HttpError::TransferEncodingInHttp10,
    ),
    (
        "chunk size with a sign",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n+5\r\nhello\r\n0\r\n\r\n",
        HttpError::InvalidChunkSize,
    ),
    (
        "chunk size wrapping past 64 bits",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff1\r\n",
        HttpError::InvalidChunkSize,
    ),
    (
        "chunk size followed by junk instead of an extension",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5 x\r\nhello\r\n0\r\n\r\n",
        HttpError::InvalidChunkExtension,
    ),
    (
        "chunk data longer than declared",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nhello\r\n0\r\n\r\n",
        HttpError::InvalidChunkTerminator,
    ),
    (
        "chunk extension with an unterminated quote swallowing the next chunk",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5;a=\"x\r\nhello\r\n0\r\n\r\n",
        HttpError::InvalidChunkExtension,
    ),
    (
        "two Host fields",
        b"GET / HTTP/1.1\r\nHost: good.example\r\nHost: evil.example\r\n\r\n",
        HttpError::InvalidHost,
    ),
];

#[test]
fn test_smuggling_vectors_are_refused() {
    for (name, input, expected) in VECTORS {
        let whole = drive_server(&[input], Limits::new());
        assert_eq!(whole.last(), Some(&Ev::Err(*expected)), "{name}: {whole:?}");
        // No request is ever reported from a refused message's bytes.
        let heads = whole
            .iter()
            .filter(|e| matches!(e, Ev::Head { .. }))
            .count();
        assert!(heads <= 1, "{name}: {whole:?}");
        for cut in 1..input.len() {
            let split = drive_server(&[&input[..cut], &input[cut..]], Limits::new());
            assert_eq!(whole, split, "{name}: split at {cut} changed the result");
        }
    }
}

#[test]
fn test_connection_is_dead_after_an_error() {
    let mut conn = ServerConn::new();
    let _ = conn.feed(
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx\
          GET /next HTTP/1.1\r\nHost: a\r\n\r\n",
    );
    assert_eq!(conn.poll().unwrap_err(), HttpError::DuplicateContentLength);
    // The pipelined request after the bad one is never parsed.
    assert!(matches!(conn.poll(), Ok(ServerEvent::Closed)));
    assert!(matches!(conn.poll(), Ok(ServerEvent::Closed)));
    let mut out = Vec::new();
    conn.respond(&Response::new(400), &mut out).unwrap();
    assert!(out.windows(17).any(|w| w == b"connection: close"));
    assert!(matches!(conn.poll(), Ok(ServerEvent::Closed)));
}

#[test]
fn test_pipelined_requests_are_framed_by_their_own_lengths() {
    // The body of the first request looks like a request; it must stay body.
    let input = b"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 30\r\n\r\n\
                  GET /smuggled HTTP/1.1\r\nX: y\r\n\
                  GET /b HTTP/1.1\r\nHost: a\r\n\r\n";
    let events = drive_server(&[input], Limits::new());
    let targets: Vec<&str> = events
        .iter()
        .filter_map(|e| match e {
            Ev::Head { target, .. } => Some(target.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(targets, ["/a", "/b"]);
    assert!(events.contains(&Ev::Body(b"GET /smuggled HTTP/1.1\r\nX: y\r\n".to_vec())));
}

#[test]
fn test_outgoing_messages_cannot_inject_framing() {
    let mut conn = ServerConn::new();
    let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
    let mut out = Vec::new();
    for bad in [
        Response::new(200).header("x", "a\r\nContent-Length: 0"),
        Response::new(200).header("x", "a\nb"),
        Response::new(200).header("Transfer-Encoding", "chunked"),
        Response::new(200).header("Content-Length", "1"),
        Response::new(200).header("Connection", "keep-alive"),
        Response::new(200).header("Upgrade", "x"),
        Response::new(200).header("x\r\ny", "1"),
    ] {
        assert!(conn.respond(&bad, &mut out).is_err(), "{bad:?}");
        assert!(out.is_empty(), "nothing is written for a refused response");
    }
    conn.respond(&Response::new(200), &mut out).unwrap();
}
