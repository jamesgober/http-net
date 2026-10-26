//! Adversarial review cases (RFC 9110 / RFC 9112), sans-IO.
//!
//! Each test pins one behaviour a hostile or merely unusual peer can
//! trigger: request-target forms and the authority they name, `Expect:
//! 100-continue`, cumulative chunk-extension budgets, interim-response
//! floods on the client, keep-alive after an early answer to a bodiless
//! request, header-name case, and integer edges. Vectors already covered
//! by `smuggling.rs` and `rfc_cases.rs` are not repeated here.

mod common;

use common::{Ev, drive_client, drive_server, server_error};
use http_net::{
    BodyFraming, ClientConn, ClientEvent, HttpError, Limits, Progress, Request, Response,
    ServerConn, ServerEvent,
};

/// Polls once and expects the request head (the whole head is always fed
/// in one piece by these tests).
fn first_request(conn: &mut ServerConn) -> Result<(), HttpError> {
    match conn.poll()? {
        ServerEvent::Request(_) => Ok(()),
        ServerEvent::NeedInput => Err(HttpError::UnexpectedEof),
        other => panic!("unexpected {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Request-target forms and the Host rules
// ---------------------------------------------------------------------------

#[test]
fn test_absolute_form_authority_overrides_host() {
    // RFC 9112 section 3.2.2: an origin server MUST ignore Host and use the
    // authority of an absolute-form target, so the two can never disagree
    // about which site is being asked for.
    let mut conn = ServerConn::new();
    let _ = conn.feed(b"GET http://example.com:8080/a/b?x=1 HTTP/1.1\r\nHost: other.test\r\n\r\n");
    let ServerEvent::Request(req) = conn.poll().unwrap() else {
        panic!("expected a request");
    };
    assert_eq!(req.target(), "http://example.com:8080/a/b?x=1");
    assert_eq!(req.host(), Some("example.com:8080"));
    assert_eq!(req.header("host"), Some(&b"other.test"[..]));
    assert_eq!(req.path(), "/a/b");
    assert_eq!(req.query(), Some("x=1"));
}

#[test]
fn test_absolute_form_with_empty_path_is_root() {
    let mut conn = ServerConn::new();
    let _ = conn.feed(b"GET http://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n");
    let ServerEvent::Request(req) = conn.poll().unwrap() else {
        panic!("expected a request");
    };
    assert_eq!(req.path(), "/");
    assert_eq!(req.query(), None);
    assert_eq!(req.host(), Some("example.com"));

    let mut conn = ServerConn::new();
    let _ = conn.feed(b"GET http://example.com?q HTTP/1.1\r\nHost: example.com\r\n\r\n");
    let ServerEvent::Request(req) = conn.poll().unwrap() else {
        panic!("expected a request");
    };
    assert_eq!(req.path(), "/");
    assert_eq!(req.query(), Some("q"));
}

#[test]
fn test_absolute_form_shapes_that_name_no_authority_are_refused() {
    for target in [
        // userinfo: RFC 9110 section 4.2.4 says to treat it as an error.
        &b"http://user@example.com/"[..],
        b"http://user:pw@example.com/",
        // no authority at all
        b"http:/x",
        b"http:x",
        b"mailto:a",
        b"http://",
        b"http:///x",
        b"http://?q",
        // an authority that is not host[:port]
        b"http://a:b:c/",
        b"http://[::1/",
        b"http://exa mple/",
    ] {
        let mut input = b"GET ".to_vec();
        input.extend_from_slice(target);
        input.extend_from_slice(b" HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(
            server_error(&input),
            Some(HttpError::InvalidTarget),
            "{}",
            String::from_utf8_lossy(target)
        );
    }
}

#[test]
fn test_absolute_form_still_requires_host_in_http11() {
    // RFC 9112 section 3.2: 400 for an HTTP/1.1 request without Host,
    // whatever the target form.
    assert_eq!(
        server_error(b"GET http://example.com/ HTTP/1.1\r\n\r\n"),
        Some(HttpError::MissingHost)
    );
    assert_eq!(
        server_error(b"GET http://example.com/ HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n"),
        Some(HttpError::InvalidHost)
    );
}

#[test]
fn test_host_name_case_and_duplicates() {
    assert_eq!(
        server_error(b"GET / HTTP/1.1\r\nHOST: a\r\nhost: a\r\n\r\n"),
        Some(HttpError::InvalidHost)
    );
    assert_eq!(
        server_error(b"GET / HTTP/1.1\r\nhOsT: a b\r\n\r\n"),
        Some(HttpError::InvalidHost)
    );
    assert_eq!(server_error(b"GET / HTTP/1.1\r\nhOsT: a\r\n\r\n"), None);
    assert_eq!(
        server_error(
            b"GET / HTTP/1.1\r\nHost: a\r\ncontent-length: 1\r\nCONTENT-LENGTH: 1\r\n\r\nx"
        ),
        Some(HttpError::DuplicateContentLength)
    );
}

#[test]
fn test_request_line_whitespace_and_controls() {
    for (input, err) in [
        (
            &b"GET  / HTTP/1.1\r\nHost: a\r\n\r\n"[..],
            HttpError::InvalidTarget,
        ),
        (
            b"GET / HTTP/1.1 \r\nHost: a\r\n\r\n",
            HttpError::InvalidVersion,
        ),
        (
            b"GET\t/ HTTP/1.1\r\nHost: a\r\n\r\n",
            HttpError::InvalidStartLine,
        ),
        (
            b" GET / HTTP/1.1\r\nHost: a\r\n\r\n",
            HttpError::InvalidMethod,
        ),
        (
            b"G(T / HTTP/1.1\r\nHost: a\r\n\r\n",
            HttpError::InvalidMethod,
        ),
        (
            b"GET /\x00 HTTP/1.1\r\nHost: a\r\n\r\n",
            HttpError::InvalidTarget,
        ),
        (
            b"GET /\x7f HTTP/1.1\r\nHost: a\r\n\r\n",
            HttpError::InvalidTarget,
        ),
        (
            b"GET /\xff HTTP/1.1\r\nHost: a\r\n\r\n",
            HttpError::InvalidTarget,
        ),
        (
            b"GET / HTTP/1.1\r\nHost: a\x00\r\n\r\n",
            HttpError::InvalidHeaderValue,
        ),
        (
            b"GET / HTTP/1.1\r\nHost: a\r\nX\x00: 1\r\n\r\n",
            HttpError::InvalidHeaderName,
        ),
    ] {
        assert_eq!(
            server_error(input),
            Some(err),
            "{}",
            String::from_utf8_lossy(input)
        );
    }
}

// ---------------------------------------------------------------------------
// Expect: 100-continue
// ---------------------------------------------------------------------------

#[test]
fn test_expect_continue_is_detected_only_when_it_applies() {
    let cases: &[(&[u8], bool)] = &[
        (
            b"POST / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n",
            true,
        ),
        (
            b"POST / HTTP/1.1\r\nHost: a\r\nexpect: 100-Continue\r\nTransfer-Encoding: chunked\r\n\r\n",
            true,
        ),
        // No body follows: nothing to continue.
        (
            b"POST / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\n\r\n",
            false,
        ),
        // HTTP/1.0: RFC 9110 section 10.1.1 says to ignore it.
        (
            b"POST / HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n",
            false,
        ),
        // Another expectation.
        (
            b"POST / HTTP/1.1\r\nHost: a\r\nExpect: something\r\nContent-Length: 3\r\n\r\n",
            false,
        ),
    ];
    for (input, expected) in cases {
        let mut conn = ServerConn::new();
        let _ = conn.feed(input);
        let ServerEvent::Request(req) = conn.poll().unwrap() else {
            panic!("expected a request");
        };
        assert_eq!(
            req.expects_continue(),
            *expected,
            "{}",
            String::from_utf8_lossy(input)
        );
    }
}

#[test]
fn test_send_continue_then_body_then_final_response() {
    let mut conn = ServerConn::new();
    let _ = conn
        .feed(b"PUT /f HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n");
    first_request(&mut conn).unwrap();
    let mut out = Vec::new();
    conn.send_continue(&mut out).unwrap();
    assert_eq!(out, b"HTTP/1.1 100 Continue\r\n\r\n");
    // Only once per request.
    assert_eq!(
        conn.send_continue(&mut out),
        Err(HttpError::InterimNotAllowed)
    );
    assert!(matches!(conn.poll().unwrap(), ServerEvent::NeedInput));
    let _ = conn.feed(b"abc");
    assert!(matches!(conn.poll().unwrap(), ServerEvent::Body(b"abc")));
    assert!(matches!(conn.poll().unwrap(), ServerEvent::RequestEnd));
    out.clear();
    conn.respond(&Response::new(204), &mut out).unwrap();
    assert!(out.starts_with(b"HTTP/1.1 204 "));
    assert!(!out.windows(17).any(|w| w == b"connection: close"));
}

#[test]
fn test_send_continue_refused_out_of_place() {
    let mut out = Vec::new();
    // No request yet.
    let mut conn = ServerConn::new();
    assert!(matches!(
        conn.send_continue(&mut out),
        Err(HttpError::InvalidState(_))
    ));
    // HTTP/1.0 clients must never get a 1xx (RFC 9110 section 15.2).
    let _ = conn.feed(b"POST / HTTP/1.0\r\nContent-Length: 1\r\n\r\n");
    first_request(&mut conn).unwrap();
    assert_eq!(
        conn.send_continue(&mut out),
        Err(HttpError::InterimNotAllowed)
    );
    // After the final response has started.
    let mut conn = ServerConn::new();
    let _ = conn.feed(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\n");
    first_request(&mut conn).unwrap();
    conn.respond(&Response::new(413), &mut out).unwrap();
    out.clear();
    assert_eq!(
        conn.send_continue(&mut out),
        Err(HttpError::InterimNotAllowed)
    );
    assert!(out.is_empty());
}

#[test]
fn test_final_response_instead_of_continue_closes() {
    // Refusing the body without reading it: the client may or may not send
    // it, so the connection cannot be reused (RFC 9110 section 10.1.1).
    let mut conn = ServerConn::new();
    let _ = conn
        .feed(b"POST / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 10\r\n\r\n");
    first_request(&mut conn).unwrap();
    let mut out = Vec::new();
    conn.respond(&Response::new(417), &mut out).unwrap();
    assert!(out.windows(17).any(|w| w == b"connection: close"));
    assert!(matches!(conn.poll().unwrap(), ServerEvent::Closed));
}

// ---------------------------------------------------------------------------
// Keep-alive after an answer given at the Request event
// ---------------------------------------------------------------------------

#[test]
fn test_answer_at_request_event_keeps_bodiless_connection_alive() {
    // A GET has no body, so answering it as soon as its head arrives
    // leaves nothing unread: the connection must stay open.
    let mut conn = ServerConn::new();
    let _ = conn.feed(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n");
    first_request(&mut conn).unwrap();
    let mut out = Vec::new();
    conn.respond(&Response::text(200, "a"), &mut out).unwrap();
    assert!(
        !out.windows(17).any(|w| w == b"connection: close"),
        "{}",
        String::from_utf8_lossy(&out)
    );
    assert!(matches!(conn.poll().unwrap(), ServerEvent::RequestEnd));
    let ServerEvent::Request(req) = conn.poll().unwrap() else {
        panic!("the pipelined request must follow");
    };
    assert_eq!(req.path(), "/b");
}

#[test]
fn test_answer_at_request_event_with_unread_body_still_closes() {
    let mut conn = ServerConn::new();
    let _ = conn.feed(b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\n");
    first_request(&mut conn).unwrap();
    let mut out = Vec::new();
    conn.respond(&Response::new(200), &mut out).unwrap();
    assert!(out.windows(17).any(|w| w == b"connection: close"));
    assert!(matches!(conn.poll().unwrap(), ServerEvent::Closed));
}

// ---------------------------------------------------------------------------
// Chunked bodies
// ---------------------------------------------------------------------------

fn chunked_head() -> Vec<u8> {
    b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec()
}

#[test]
fn test_chunk_extensions_are_budgeted_across_the_message() {
    // Each chunk line is under the line limit, but together the extensions
    // would let one 1 MiB body cost gigabytes on the wire (the
    // CVE-2024-22019 pattern). The total is capped at the header budget.
    let mut input = chunked_head();
    let ext = format!(";e={}", "x".repeat(1000));
    for _ in 0..40 {
        input.extend_from_slice(format!("1{ext}\r\nz\r\n").as_bytes());
    }
    input.extend_from_slice(b"0\r\n\r\n");
    assert_eq!(
        server_error(&input),
        Some(HttpError::ChunkExtensionsTooLarge)
    );
    assert_eq!(HttpError::ChunkExtensionsTooLarge.status(), Some(400));

    // Just under the budget is fine.
    let mut input = chunked_head();
    for _ in 0..15 {
        input.extend_from_slice(format!("1{ext}\r\nz\r\n").as_bytes());
    }
    input.extend_from_slice(b"0\r\n\r\n");
    assert_eq!(server_error(&input), None);
}

#[test]
fn test_chunk_size_edges() {
    let cases: &[(&[u8], HttpError)] = &[
        (b"1ffffffffffffffff\r\n", HttpError::InvalidChunkSize),
        (b"ffffffffffffffff\r\n", HttpError::BodyTooLarge),
        (b"-1\r\n", HttpError::InvalidChunkSize),
        (b"\r\n", HttpError::InvalidChunkSize),
        (b" 1\r\nz\r\n0\r\n\r\n", HttpError::InvalidChunkSize),
        (b"1\nz\r\n0\r\n\r\n", HttpError::BareLf),
        (b"1\rz\r\n0\r\n\r\n", HttpError::InvalidChunkSize),
        (b"1\r\nz\n0\r\n\r\n", HttpError::InvalidChunkTerminator),
        (b"1\r\nzz\r\n0\r\n\r\n", HttpError::InvalidChunkTerminator),
        (b"1\r\nz\r\n0\r\nX: 1\n\r\n", HttpError::BareLf),
        (b"1\r\nz\r\n0\r\n folded\r\n\r\n", HttpError::ObsFold),
        (
            b"1\r\nz\r\n0\r\nX\x00: 1\r\n\r\n",
            HttpError::InvalidHeaderName,
        ),
        // Missing the CRLF that ends the trailer section.
        (b"1\r\nz\r\n0\r\n", HttpError::UnexpectedEof),
        (b"1\r\nz\r\n0\r\nX: 1\r\n", HttpError::UnexpectedEof),
        (b"1\r\nz\r\n0", HttpError::UnexpectedEof),
    ];
    for (body, err) in cases {
        let mut input = chunked_head();
        input.extend_from_slice(body);
        assert_eq!(
            server_error(&input),
            Some(*err),
            "{}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn test_trailer_fields_cannot_reframe_the_message() {
    // Framing fields in a trailer are discarded; the next pipelined
    // request is framed by its own head.
    let mut input = chunked_head();
    input.extend_from_slice(
        b"3\r\nabc\r\n0\r\nContent-Length: 50\r\nTransfer-Encoding: chunked\r\n\r\n",
    );
    input.extend_from_slice(b"GET /next HTTP/1.1\r\nHost: a\r\n\r\n");
    let events = drive_server(&[&input], Limits::new());
    let targets: Vec<&str> = events
        .iter()
        .filter_map(|e| match e {
            Ev::Head { target, .. } => Some(target.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(targets, ["/", "/next"]);
    assert!(events.contains(&Ev::Body(b"abc".to_vec())));
}

#[test]
fn test_trailer_count_and_size_are_limited() {
    let limits = Limits::new().with_max_headers(3);
    let mut input = chunked_head();
    input.extend_from_slice(b"0\r\nA: 1\r\nB: 1\r\nC: 1\r\nD: 1\r\n\r\n");
    assert_eq!(
        drive_server(&[&input], limits).last(),
        Some(&Ev::Err(HttpError::TooManyHeaders))
    );
    let limits = Limits::new().with_max_header_bytes(64);
    let mut input = chunked_head();
    input.extend_from_slice(b"0\r\nA: ");
    input.extend_from_slice(&[b'x'; 80]);
    input.extend_from_slice(b"\r\n\r\n");
    assert_eq!(
        drive_server(&[&input], limits).last(),
        Some(&Ev::Err(HttpError::HeadersTooLarge))
    );
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

#[test]
fn test_client_interim_flood_is_budgeted() {
    // T-31: interim responses are budgeted by count (`max_interim`, 16 by
    // default) and together by bytes (the header budget), so a server
    // cannot keep a client busy forever without ever answering.
    let one = b"HTTP/1.1 100 Continue\r\n\r\n";
    let flood = one.repeat(2000);
    let events = drive_client(
        &Request::get("/").header("host", "a"),
        &[&flood],
        Limits::new(),
    );
    assert_eq!(events.last(), Some(&Ev::Err(HttpError::TooManyInterim)));
    let events = drive_client(
        &Request::get("/").header("host", "a"),
        &[&flood],
        Limits::new().with_max_interim(u16::MAX),
    );
    assert_eq!(events.last(), Some(&Ev::Err(HttpError::HeadersTooLarge)));
    // Exactly `max_interim` interim responses are fine; one more is not.
    let mut at = one.repeat(16);
    at.extend_from_slice(b"HTTP/1.1 204 No Content\r\n\r\n");
    let events = drive_client(
        &Request::get("/").header("host", "a"),
        &[&at],
        Limits::new(),
    );
    assert!(events.contains(&Ev::End), "{events:?}");
    let mut over = one.repeat(17);
    over.extend_from_slice(b"HTTP/1.1 204 No Content\r\n\r\n");
    let events = drive_client(
        &Request::get("/").header("host", "a"),
        &[&over],
        Limits::new(),
    );
    assert_eq!(events.last(), Some(&Ev::Err(HttpError::TooManyInterim)));

    // A handful of interim responses is normal (100, 103) and still works.
    let mut ok = one.repeat(3);
    ok.extend_from_slice(b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n");
    ok.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nz");
    let events = drive_client(
        &Request::get("/").header("host", "a"),
        &[&ok],
        Limits::new(),
    );
    assert!(matches!(events[0], Ev::Status { status: 200, .. }));
    assert!(events.contains(&Ev::Body(b"z".to_vec())));
}

#[test]
fn test_client_refuses_response_smuggling_shapes() {
    let get = Request::get("/").header("host", "a");
    for (input, err) in [
        (
            &b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
            HttpError::ConflictingFraming,
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
            HttpError::InvalidTransferEncoding,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\nz",
            HttpError::InvalidContentLength,
        ),
        (
            b"HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n",
            HttpError::BareLf,
        ),
        (b"HTTP/1.1 2000 OK\r\n\r\n", HttpError::InvalidStartLine),
        (b"HTTP/1.1 099 X\r\n\r\n", HttpError::InvalidStatus),
        (b"HTTP/1.1 200 O\x00K\r\n\r\n", HttpError::InvalidStartLine),
    ] {
        let events = drive_client(&get, &[input], Limits::new());
        assert_eq!(
            events.last(),
            Some(&Ev::Err(err)),
            "{}",
            String::from_utf8_lossy(input)
        );
    }
    // Bytes after a complete response, with nothing asked: response
    // splitting is refused rather than queued.
    let mut conn = ClientConn::new();
    conn.send_request(&get, &mut Vec::new()).unwrap();
    let _ = conn.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nzHTTP/1.1 200 OK\r\n\r\n");
    while !matches!(conn.poll().unwrap(), ClientEvent::ResponseEnd) {}
    assert_eq!(conn.poll().unwrap_err(), HttpError::UnexpectedData);
}

// ---------------------------------------------------------------------------
// Integer edges
// ---------------------------------------------------------------------------

#[test]
fn test_content_length_integer_edges() {
    let at = |n: &str| {
        let input = format!("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: {n}\r\n\r\n");
        let limits = Limits::new().with_max_body(u64::MAX);
        let mut conn = ServerConn::with_limits(limits);
        let _ = conn.feed(input.as_bytes());
        conn.poll().map(|e| match e {
            ServerEvent::Request(r) => r.framing(),
            _ => BodyFraming::None,
        })
    };
    assert_eq!(
        at("18446744073709551615"),
        Ok(BodyFraming::Length(u64::MAX))
    );
    assert_eq!(
        at("18446744073709551616"),
        Err(HttpError::InvalidContentLength)
    );
    assert_eq!(
        at("99999999999999999999999"),
        Err(HttpError::InvalidContentLength)
    );
    assert_eq!(at("00000000000000000000001"), Ok(BodyFraming::Length(1)));
    assert_eq!(at("-0"), Err(HttpError::InvalidContentLength));
}

#[test]
fn test_chunk_sizes_cannot_overflow_the_running_total() {
    let limits = Limits::new().with_max_body(u64::MAX);
    let mut input = chunked_head();
    input.extend_from_slice(b"1\r\nz\r\nffffffffffffffff\r\n");
    assert_eq!(
        drive_server(&[&input], limits).last(),
        Some(&Ev::Err(HttpError::BodyTooLarge))
    );
}

// ---------------------------------------------------------------------------
// 0.3 attack vectors: 0.CL, Expect, Host, h2c, offered protocols
// ---------------------------------------------------------------------------

/// Runs `input` whole and split at every byte; all runs must agree.
fn whole_and_split(input: &[u8]) -> Vec<Ev> {
    let whole = drive_server(&[input], Limits::new());
    for cut in 1..input.len() {
        let split = drive_server(&[&input[..cut], &input[cut..]], Limits::new());
        assert_eq!(
            whole,
            split,
            "split at {cut} changed the result for {:?}",
            String::from_utf8_lossy(input)
        );
    }
    whole
}

fn targets(events: &[Ev]) -> Vec<&str> {
    events
        .iter()
        .filter_map(|e| match e {
            Ev::Head { target, .. } => Some(target.as_str()),
            _ => None,
        })
        .collect()
}

/// T-14, 0.CL desync (E-91): a GET with `Content-Length` and a body. A hop
/// that ignores the body on GET would read it as the next request; this
/// crate honours `Content-Length` on every method, so the body stays body
/// and the pipelined request after it is the second request.
#[test]
fn test_get_with_content_length_body_then_pipelined_request_frames_both() {
    let input = b"GET /a HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nGET /GET /b HTTP/1.1\r\nHost: a\r\n\r\n";
    let events = whole_and_split(input);
    assert_eq!(targets(&events), ["/a", "/b"], "{events:?}");
    assert!(events.contains(&Ev::Body(b"GET /".to_vec())), "{events:?}");
    let Ev::Head { framing, .. } = &events[0] else {
        panic!("{events:?}");
    };
    assert_eq!(*framing, BodyFraming::Length(5));
}

/// T-14, 0.CL: answering before the declared body was read closes the
/// connection, so whatever the peer sends as "body" is never parsed as a
/// request.
#[test]
fn test_early_answer_with_unread_body_closes_before_smuggled_request() {
    let mut conn = ServerConn::new();
    let _ = conn.feed(
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 30\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: a\r\n\r\n",
    );
    assert!(matches!(conn.poll(), Ok(ServerEvent::Request(_))));
    let mut out = Vec::new();
    conn.respond(&Response::new(401), &mut out).unwrap();
    assert!(out.windows(17).any(|w| w == b"connection: close"));
    assert!(matches!(conn.poll(), Ok(ServerEvent::Closed)));
    assert!(matches!(conn.poll(), Ok(ServerEvent::Closed)));
}

/// T-15, Expect-based desync: obfuscated `Expect` values make hops disagree
/// on whether a body follows. Here `Expect` never changes framing: each
/// request is framed by its `Content-Length`, the pipelined request after
/// it is parsed as the second request, and `expects_continue()` is true
/// exactly for a `100-continue` list element (case-insensitive, OWS
/// trimmed) on an HTTP/1.1 request with a body.
#[test]
fn test_expect_variants_never_change_framing() {
    let cases: &[(&str, &str, bool)] = &[
        ("leading space", "Expect:  100-continue\r\n", true),
        ("leading tab", "Expect:\t100-continue\r\n", true),
        ("mixed case", "Expect: 100-Continue\r\n", true),
        ("trailing junk", "Expect: 100-continuex\r\n", false),
        ("unknown expectation", "Expect: foo\r\n", false),
        ("in a list", "Expect: foo, 100-continue\r\n", true),
        (
            "duplicate fields",
            "Expect: 100-continue\r\nExpect: 100-continue\r\n",
            true,
        ),
        ("empty", "Expect:\r\n", false),
    ];
    for (name, expect, continues) in cases {
        let input = format!(
            "POST /a HTTP/1.1\r\nHost: a\r\n{expect}Content-Length: 5\r\n\r\nhelloGET /b HTTP/1.1\r\nHost: a\r\n\r\n"
        );
        let events = whole_and_split(input.as_bytes());
        assert_eq!(targets(&events), ["/a", "/b"], "{name}: {events:?}");
        assert!(events.contains(&Ev::Body(b"hello".to_vec())), "{name}");
        let mut conn = ServerConn::new();
        let _ = conn.feed(input.as_bytes());
        let ServerEvent::Request(req) = conn.poll().unwrap() else {
            panic!("{name}");
        };
        assert_eq!(req.framing(), BodyFraming::Length(5), "{name}");
        assert_eq!(req.expects_continue(), *continues, "{name}");
    }

    // On a GET without a body there is nothing to wait for.
    let input =
        b"GET /a HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\n\r\nGET /b HTTP/1.1\r\nHost: a\r\n\r\n";
    let events = whole_and_split(input);
    assert_eq!(targets(&events), ["/a", "/b"]);
    let mut conn = ServerConn::new();
    let _ = conn.feed(input);
    let ServerEvent::Request(req) = conn.poll().unwrap() else {
        panic!();
    };
    assert_eq!(req.framing(), BodyFraming::None);
    assert!(!req.expects_continue());
}

/// T-18, Host attacks (E-67 to E-72): an empty host before a port and a `%`
/// not followed by two hex digits are refused; other RFC 3986 shapes are
/// accepted. The same rules apply to authority-form and absolute-form
/// targets and to an outgoing `host` field.
#[test]
fn test_host_percent_escapes_and_empty_host_with_port() {
    for bad in [":80", "a%zz", "a%4", "a%", "%", "a%g1"] {
        let input = format!("GET / HTTP/1.1\r\nHost: {bad}\r\n\r\n");
        assert_eq!(
            server_error(input.as_bytes()),
            Some(HttpError::InvalidHost),
            "Host: {bad}"
        );
    }
    for good in [
        "a%41",
        "[v1.fe80::a]",
        "example.com:",
        "example.com:99999",
        "",
    ] {
        let input = format!("GET / HTTP/1.1\r\nHost: {good}\r\n\r\n");
        let mut conn = ServerConn::new();
        let _ = conn.feed(input.as_bytes());
        let ServerEvent::Request(req) = conn.poll().unwrap() else {
            panic!("Host: {good} refused");
        };
        assert_eq!(req.host(), Some(good));
    }
    for target in ["a%4:443", "a%zz:443", ":443"] {
        let input = format!("CONNECT {target} HTTP/1.1\r\nHost: a:443\r\n\r\n");
        assert_eq!(
            server_error(input.as_bytes()),
            Some(HttpError::InvalidTarget),
            "CONNECT {target}"
        );
    }
    for target in ["http://a%zz/", "http://a%4/x", "http://:80/"] {
        let input = format!("GET {target} HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(
            server_error(input.as_bytes()),
            Some(HttpError::InvalidTarget),
            "{target}"
        );
    }
    let mut conn = ClientConn::new();
    for bad in [":80", "a%zz"] {
        let request = Request::get("/").header("host", bad);
        assert_eq!(
            conn.send_request(&request, &mut Vec::new()),
            Err(HttpError::InvalidHost),
            "host {bad}"
        );
    }
}

/// T-20, h2c smuggling (E-141): `Upgrade: h2c` with `HTTP2-Settings` is
/// never an upgrade offer; the request is served as plain HTTP/1.1 and the
/// connection stays keep-alive.
#[test]
fn test_h2c_upgrade_is_served_as_http11() {
    let input = b"GET / HTTP/1.1\r\nHost: a\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAoAAA\r\n\r\nGET /next HTTP/1.1\r\nHost: a\r\n\r\n";
    let events = whole_and_split(input);
    assert_eq!(targets(&events), ["/", "/next"], "{events:?}");
    assert!(!events.iter().any(|e| matches!(e, Ev::Upgraded(_))));

    let mut conn = ServerConn::new();
    let _ = conn.feed(input);
    let ServerEvent::Request(req) = conn.poll().unwrap() else {
        panic!();
    };
    assert!(!req.is_upgrade());
    assert!(matches!(conn.poll(), Ok(ServerEvent::RequestEnd)));
    let mut out = Vec::new();
    assert_eq!(
        conn.respond(&Response::switching_protocols("h2c"), &mut out),
        Err(HttpError::UpgradeNotOffered)
    );
    conn.respond(&Response::new(200), &mut out).unwrap();
    assert!(out.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(!out.windows(17).any(|w| w == b"connection: close"));
    assert!(!out.windows(7).any(|w| w.eq_ignore_ascii_case(b"upgrade")));
    assert!(matches!(conn.poll(), Ok(ServerEvent::Request(_))));
}

/// T-20 (E-142): `h2c` beside another protocol: the request is an upgrade
/// offer for the other protocol only.
#[test]
fn test_h2c_beside_websocket_offers_websocket_only() {
    let mut conn = ServerConn::new();
    let _ = conn.feed(
        b"GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: h2c, websocket\r\n\r\n",
    );
    let ServerEvent::Request(req) = conn.poll().unwrap() else {
        panic!();
    };
    assert!(req.is_upgrade());
    assert!(matches!(conn.poll(), Ok(ServerEvent::RequestEnd)));
    let mut out = Vec::new();
    assert_eq!(
        conn.respond(&Response::switching_protocols("h2c"), &mut out),
        Err(HttpError::UpgradeNotOffered)
    );
    assert!(out.is_empty());
    conn.respond(&Response::switching_protocols("websocket"), &mut out)
        .unwrap();
    assert!(conn.is_upgraded());
}

/// T-20: a client never asks for h2c.
#[test]
fn test_client_refuses_to_offer_h2c() {
    let mut conn = ClientConn::new();
    for protocol in ["h2c", "H2C"] {
        let request = Request::get("/").header("host", "a").upgrade(protocol);
        assert_eq!(
            conn.send_request(&request, &mut Vec::new()),
            Err(HttpError::UpgradeNotOffered),
            "{protocol}"
        );
    }
    // The refusal left the connection usable.
    conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())
        .unwrap();
}

/// T-21, upgrade smuggling (E-143): a 101 must name a protocol the request
/// offered (RFC 9110 section 7.8). A refused 101 writes nothing and leaves
/// the connection in HTTP, able to send a normal response.
#[test]
fn test_switching_protocols_must_name_an_offered_protocol() {
    fn answer(offer: &str, protocol: &str) -> (Result<(), HttpError>, ServerConn) {
        let mut conn = ServerConn::new();
        let input =
            format!("GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: {offer}\r\n\r\n");
        let _ = conn.feed(input.as_bytes());
        while !matches!(conn.poll(), Ok(ServerEvent::RequestEnd)) {}
        let mut out = Vec::new();
        let result = conn.respond(&Response::switching_protocols(protocol), &mut out);
        assert_eq!(result.is_ok(), !out.is_empty(), "{offer} / {protocol}");
        (result, conn)
    }

    let (result, mut conn) = answer("websocket", "ftp");
    assert_eq!(result, Err(HttpError::UpgradeNotOffered));
    assert!(!conn.is_upgraded());
    let mut out = Vec::new();
    conn.respond(&Response::new(426), &mut out).unwrap();
    assert!(out.starts_with(b"HTTP/1.1 426 Upgrade Required\r\n"));
    assert!(!conn.is_upgraded());

    for (offer, protocol, ok) in [
        ("WebSocket", "websocket", true),
        ("websocket", "WEBSOCKET", true),
        ("websocket/13", "websocket", true),
        ("foo/2", "foo/2", true),
        ("foo/2", "foo/3", false),
        ("foo/2", "foo", true),
        ("foo", "foo/2", false),
        ("a, b, c", "c", true),
        ("a, b, c", "d", false),
    ] {
        let (result, conn) = answer(offer, protocol);
        assert_eq!(
            result.is_ok(),
            ok,
            "offer {offer:?}, 101 {protocol:?}: {result:?}"
        );
        assert_eq!(conn.is_upgraded(), ok);
        if !ok {
            assert_eq!(result, Err(HttpError::UpgradeNotOffered));
        }
    }
}

// ---------------------------------------------------------------------------
// Audit additions: upgrade answers, chunk lines, unanswered floods, error
// answers
// ---------------------------------------------------------------------------

fn upgrade_request() -> Request {
    Request::get("/").header("host", "a").upgrade("websocket")
}

/// T-21, upgrade smuggling: a client that asked to upgrade and got a final
/// answer other than 101 (a 426, or a plain 200) stays in HTTP. The answer
/// is read as an ordinary response framed by its own `Content-Length`, at
/// every split; the connection never reports `Upgraded`, and `progress()`
/// never says `Upgraded`.
#[test]
fn test_client_upgrade_answered_without_101_stays_http() {
    for (answer, status) in [
        (
            &b"HTTP/1.1 426 Upgrade Required\r\nContent-Length: 2\r\n\r\nno"[..],
            426,
        ),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nno", 200),
    ] {
        let whole = drive_client(&upgrade_request(), &[answer], Limits::new());
        let bytes: Vec<&[u8]> = answer.chunks(1).collect();
        let bytewise = drive_client(&upgrade_request(), &bytes, Limits::new());
        assert_eq!(whole, bytewise, "{status}: split changed the result");
        assert!(
            matches!(&whole[0], Ev::Status { status: s, .. } if *s == status),
            "{whole:?}"
        );
        assert_eq!(whole[1..], [Ev::Body(b"no".to_vec()), Ev::End], "{whole:?}");

        let mut conn = ClientConn::new();
        conn.send_request(&upgrade_request(), &mut Vec::new())
            .unwrap();
        assert_eq!(conn.feed(answer), answer.len());
        let mut seen = Vec::new();
        loop {
            let event = match conn.poll().unwrap() {
                ClientEvent::Response(r) => format!("Response {}", r.status()),
                ClientEvent::Body(b) => format!("Body {}", String::from_utf8_lossy(b)),
                ClientEvent::ResponseEnd => "ResponseEnd".to_string(),
                ClientEvent::Idle => break,
                other => panic!("{status}: unexpected {other:?}"),
            };
            seen.push(event);
            assert!(!conn.is_upgraded(), "{status}: {seen:?}");
            assert_ne!(conn.progress(), Progress::Upgraded, "{status}: {seen:?}");
        }
        assert_eq!(
            seen,
            [
                format!("Response {status}"),
                "Body no".into(),
                "ResponseEnd".into()
            ]
        );
        assert!(!conn.is_upgraded());
        assert_eq!(conn.progress(), Progress::Idle);
    }
}

/// T-21: a 101 with no `Upgrade` field, or an empty one, names no protocol
/// to switch to, so even in answer to a request that asked to upgrade it is
/// refused with `UnexpectedUpgrade` and the connection is closed, never
/// switched.
#[test]
fn test_client_101_without_an_upgrade_protocol_is_unexpected_upgrade() {
    for answer in [
        &b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\n\r\n"[..],
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade:\r\n\r\n",
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: \r\n\r\n",
    ] {
        let shown = String::from_utf8_lossy(answer);
        let events = drive_client(&upgrade_request(), &[answer], Limits::new());
        assert_eq!(events, [Ev::Err(HttpError::UnexpectedUpgrade)], "{shown}");

        let mut conn = ClientConn::new();
        conn.send_request(&upgrade_request(), &mut Vec::new())
            .unwrap();
        let _ = conn.feed(answer);
        assert_eq!(
            conn.poll().unwrap_err(),
            HttpError::UnexpectedUpgrade,
            "{shown}"
        );
        assert!(!conn.is_upgraded(), "{shown}");
        assert_eq!(conn.progress(), Progress::Closed, "{shown}");
        assert!(matches!(conn.poll(), Ok(ClientEvent::Closed)), "{shown}");
    }
}

/// T-21: the server switches only once the upgrade request has been read
/// to its end. A 101 at the `Request` event, while the declared body is
/// still unread, is refused with `InvalidState` and writes nothing (the
/// unread body would otherwise reach the new protocol as its first bytes);
/// once the body is read, the same 101 succeeds.
#[test]
fn test_server_101_before_the_upgrade_request_body_is_read_is_refused() {
    let head = b"POST / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: websocket\r\nContent-Length: 5\r\n\r\n";
    let mut conn = ServerConn::new();
    assert_eq!(conn.feed(head), head.len());
    let ServerEvent::Request(req) = conn.poll().unwrap() else {
        panic!("expected a request");
    };
    assert!(req.is_upgrade());
    let mut out = Vec::new();
    assert!(matches!(
        conn.respond(&Response::switching_protocols("websocket"), &mut out),
        Err(HttpError::InvalidState(_))
    ));
    assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));
    assert!(!conn.is_upgraded());

    assert!(matches!(conn.poll().unwrap(), ServerEvent::NeedInput));
    let _ = conn.feed(b"hello");
    assert!(matches!(conn.poll().unwrap(), ServerEvent::Body(b"hello")));
    assert!(matches!(conn.poll().unwrap(), ServerEvent::RequestEnd));
    conn.respond(&Response::switching_protocols("websocket"), &mut out)
        .unwrap();
    assert!(out.starts_with(b"HTTP/1.1 101 "));
    assert!(conn.is_upgraded());
    assert!(matches!(conn.poll().unwrap(), ServerEvent::Upgraded));
}

/// A chunked request whose first chunk line is `1;e=` followed by `ext`
/// bytes of `x` and CRLF, then one data byte and the last chunk.
fn chunk_line_request(ext: usize) -> Vec<u8> {
    let mut input = chunked_head();
    input.extend_from_slice(b"1;e=");
    input.extend(std::iter::repeat_n(b'x', ext));
    input.extend_from_slice(b"\r\nz\r\n0\r\n\r\n");
    input
}

/// T-11 / T-27: one chunk-size line longer than the line budget
/// (`Limits::max_start_line`, 8 KiB by default) is refused with
/// `ChunkLineTooLong`, whole and split at every byte, before any chunk data
/// is delivered.
#[test]
fn test_chunk_line_over_the_line_budget_is_chunk_line_too_long() {
    let events = whole_and_split(&chunk_line_request(8200));
    assert_eq!(
        events.last(),
        Some(&Ev::Err(HttpError::ChunkLineTooLong)),
        "{:?}",
        events.first()
    );
    assert_eq!(targets(&events), ["/"]);
    assert!(!events.iter().any(|e| matches!(e, Ev::Body(_))));
    assert_eq!(HttpError::ChunkLineTooLong.status(), Some(400));
}

/// T-11 / T-27: the chunk-line budget counts the whole line with its CRLF
/// (`find_line` refuses a line whose LF ends past `max_start_line` bytes,
/// and a partial line once it holds `max_start_line` bytes with no LF). A
/// line of exactly the budget is accepted; one byte more is
/// `ChunkLineTooLong`. Both whole and at every split.
#[test]
fn test_chunk_line_of_exactly_the_budget_is_accepted_one_more_is_refused() {
    let budget = Limits::new().max_start_line();
    // "1;e=" (4 bytes) + ext + CRLF (2 bytes) is the line length.
    let at = whole_and_split(&chunk_line_request(budget - 6));
    assert!(at.contains(&Ev::Body(b"z".to_vec())), "{at:?}");
    assert!(at.contains(&Ev::End), "{at:?}");
    assert!(!at.iter().any(|e| matches!(e, Ev::Err(_))), "{at:?}");

    let over = whole_and_split(&chunk_line_request(budget - 5));
    assert_eq!(
        over.last(),
        Some(&Ev::Err(HttpError::ChunkLineTooLong)),
        "{over:?}"
    );
    assert!(!over.iter().any(|e| matches!(e, Ev::Body(_))));
}

/// T-29, pipelining flood: a peer that pipelines 100,000 requests and never
/// reads a response gets exactly one request parsed. The rest waits in the
/// bounded input buffer: `feed` takes at most `Limits::buffer_capacity()`
/// bytes in all and then returns 0, and `poll` reports `AwaitingResponse`
/// until the response is written. Nothing taken is lost: once answered,
/// the next request is parsed.
#[test]
fn test_unanswered_pipelining_flood_stays_in_the_bounded_buffer() {
    let one: &[u8] = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    let capacity = Limits::new().buffer_capacity();
    let mut conn = ServerConn::new();
    let mut taken = 0usize;
    let mut full = false;
    let mut kinds = Vec::with_capacity(100_000);
    for i in 0..100_000 {
        let n = conn.feed(one);
        if full {
            assert_eq!(n, 0, "offer {i}: feed took bytes after the buffer filled");
        }
        full |= n < one.len();
        taken += n;
        kinds.push(match conn.poll().unwrap() {
            ServerEvent::Request(_) => "Request",
            ServerEvent::RequestEnd => "RequestEnd",
            ServerEvent::AwaitingResponse => "AwaitingResponse",
            other => panic!("offer {i}: unexpected {other:?}"),
        });
    }
    assert!(full, "100,000 requests fit in the buffer");
    assert!(taken <= capacity, "took {taken} bytes, capacity {capacity}");
    assert!(conn.remaining_input().len() <= capacity);
    assert_eq!(kinds[..2], ["Request", "RequestEnd"]);
    assert!(
        kinds[2..].iter().all(|k| *k == "AwaitingResponse"),
        "{:?}",
        kinds.iter().find(|k| **k != "AwaitingResponse")
    );
    assert_eq!(conn.progress(), Progress::AwaitingResponse);

    conn.respond(&Response::new(204), &mut Vec::new()).unwrap();
    assert!(matches!(conn.poll(), Ok(ServerEvent::Request(r)) if r.path() == "/"));
}

/// Every variant of `HttpError`, for the `from_error` checks below. The
/// enum is `#[non_exhaustive]`, so a new variant must be added here by hand.
const ALL_ERRORS: &[HttpError] = &[
    HttpError::InvalidStartLine,
    HttpError::InvalidMethod,
    HttpError::InvalidTarget,
    HttpError::InvalidVersion,
    HttpError::UnsupportedVersion,
    HttpError::Http2Preface,
    HttpError::InvalidStatus,
    HttpError::StartLineTooLong,
    HttpError::HeadersTooLarge,
    HttpError::TooManyHeaders,
    HttpError::FieldLineTooLong,
    HttpError::BareCr,
    HttpError::BareLf,
    HttpError::ObsFold,
    HttpError::InvalidHeaderName,
    HttpError::WhitespaceBeforeColon,
    HttpError::InvalidHeaderValue,
    HttpError::MissingHost,
    HttpError::InvalidHost,
    HttpError::InvalidContentLength,
    HttpError::DuplicateContentLength,
    HttpError::ConflictingFraming,
    HttpError::InvalidTransferEncoding,
    HttpError::UnsupportedTransferEncoding,
    HttpError::TransferEncodingInHttp10,
    HttpError::InvalidChunkSize,
    HttpError::InvalidChunkExtension,
    HttpError::InvalidChunkTerminator,
    HttpError::ChunkLineTooLong,
    HttpError::ChunkExtensionsTooLarge,
    HttpError::BodyTooLarge,
    HttpError::UnexpectedEof,
    HttpError::UnexpectedData,
    HttpError::UnexpectedUpgrade,
    HttpError::TooManyInterim,
    HttpError::ReservedHeader,
    HttpError::BodyNotAllowed,
    HttpError::BodyLengthMismatch,
    HttpError::UpgradeNotOffered,
    HttpError::InterimNotAllowed,
    HttpError::TrailerNotAllowed,
    HttpError::InvalidState("rule"),
];

/// T-37, error text reflecting attacker bytes: for every peer error that
/// has a status, `Response::from_error` answers with exactly that status,
/// the error's static `Display` text as the whole body, and `close`; the
/// errors without a status get 400 the same way.
#[test]
fn test_from_error_uses_the_status_and_static_text_of_every_variant() {
    let mut with_status = 0;
    for e in ALL_ERRORS {
        let r = Response::from_error(e);
        if let Some(status) = e.status() {
            assert!(e.is_peer_error(), "{e:?}");
            with_status += 1;
            assert_eq!(r.status(), status, "{e:?}");
        } else {
            assert_eq!(r.status(), 400, "{e:?}");
        }
        assert_eq!(r.body_bytes(), Some(e.to_string().as_bytes()), "{e:?}");
        assert!(r.closes(), "{e:?}");
    }
    assert_eq!(with_status, 30, "peer errors with a status");
}

/// T-37: the answer to a refused request carries none of the refused
/// bytes, only the static text.
#[test]
fn test_error_answer_never_reflects_the_refused_bytes() {
    for (input, expected) in [
        (
            &b"GET / HTTP/1.1\r\nHost: a\r\nX-ATTACKER\x00: 1\r\n\r\n"[..],
            HttpError::InvalidHeaderName,
        ),
        (
            b"GET /<script>ATTACKER</script> HTTP/1.1\r\nHost: a\r\n\r\n",
            HttpError::InvalidTarget,
        ),
        (
            b"GET / HTTP/1.1\r\nHost: ATTACKER host\r\n\r\n",
            HttpError::InvalidHost,
        ),
    ] {
        let mut conn = ServerConn::new();
        let _ = conn.feed(input);
        let err = conn.poll().unwrap_err();
        assert_eq!(err, expected);
        let mut out = Vec::new();
        conn.respond(&Response::from_error(&err), &mut out).unwrap();
        assert!(out.starts_with(b"HTTP/1.1 400 "));
        assert!(out.ends_with(err.to_string().as_bytes()));
        assert!(
            !out.windows(8).any(|w| w == b"ATTACKER"),
            "{}",
            String::from_utf8_lossy(&out)
        );
    }
}
