//! Trailer sections, both directions (FR-18, FR-19, FR-35; E-109 to E-112,
//! E-178; threat T-13), and quote-aware list splitting (X-7).
//!
//! Incoming trailers are validated with the header rules and their own
//! budgets, never merged into the head and never used for framing; they are
//! reported only when asked for. Outgoing trailers are refused when RFC 9110
//! section 6.5.1 keeps the field out of trailers, or when the body is not
//! chunked, and dropped (after validation) when the peer forced a body that
//! cannot carry them.

mod common;

use common::{Ev, Opts, drive_server_opts, split};
use http_net::{
    BodyFraming, ClientConn, ClientEvent, HttpError, Limits, Request, Response, ServerConn,
    ServerEvent,
};

const REPORT: Opts = Opts {
    report_trailers: true,
    report_informational: false,
};

/// Every name `message.rs` keeps out of outgoing trailers.
const FORBIDDEN: &[&str] = &[
    "content-length",
    "transfer-encoding",
    "host",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "proxy-connection",
    "expect",
    "max-forwards",
    "range",
    "if-match",
    "if-none-match",
    "if-modified-since",
    "if-unmodified-since",
    "if-range",
    "authorization",
    "proxy-authorization",
    "www-authenticate",
    "proxy-authenticate",
    "cookie",
    "set-cookie",
    "content-type",
    "content-encoding",
    "content-range",
    "cache-control",
    "expires",
    "date",
    "location",
    "retry-after",
    "vary",
    "age",
];

fn chunked_request(trailers: &[u8]) -> Vec<u8> {
    let mut v =
        b"POST /up HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\n"
            .to_vec();
    v.extend_from_slice(trailers);
    v.extend_from_slice(b"\r\n");
    v
}

fn whole_and_bytewise(input: &[u8], limits: Limits, opts: Opts) -> Vec<Ev> {
    let whole = drive_server_opts(&[input], limits, opts);
    let bytes: Vec<&[u8]> = input.chunks(1).collect();
    let bytewise = drive_server_opts(&bytes, limits, opts);
    assert_eq!(whole, bytewise, "split changed the result");
    whole
}

/// E-112: with reporting on, the trailer fields arrive as one event just
/// before the end of the request, at every split.
#[test]
fn test_server_trailers_reported_when_on_arrive_before_request_end() {
    let input = chunked_request(b"Digest: sha-256=x\r\nX-Count: 4\r\n");
    let events = whole_and_bytewise(&input, Limits::new(), REPORT);
    let trailers = Ev::Trailers(vec![
        ("Digest".into(), b"sha-256=x".to_vec()),
        ("X-Count".into(), b"4".to_vec()),
    ]);
    let at = events
        .iter()
        .position(|e| *e == trailers)
        .expect("trailers");
    assert_eq!(events[at - 1], Ev::Body(b"Wiki".to_vec()));
    assert_eq!(events[at + 1], Ev::End);
}

/// E-112: with reporting off (the default) they are validated and dropped.
#[test]
fn test_server_trailers_reported_when_off_are_absent() {
    let input = chunked_request(b"Digest: sha-256=x\r\n");
    let events = whole_and_bytewise(&input, Limits::new(), Opts::default());
    assert!(!events.iter().any(|e| matches!(e, Ev::Trailers(_))));
    assert!(events.contains(&Ev::End));
}

/// E-112: an empty trailer section gives no event even with reporting on.
#[test]
fn test_server_trailers_empty_section_with_report_on_gives_no_event() {
    let input = chunked_request(b"");
    let events = whole_and_bytewise(&input, Limits::new(), REPORT);
    assert!(!events.iter().any(|e| matches!(e, Ev::Trailers(_))));
    assert!(events.contains(&Ev::End));
}

/// T-13 / E-109: a framing field in a trailer is reported but frames
/// nothing: the pipelined request after it is parsed normally.
#[test]
fn test_server_trailers_framing_fields_do_not_reframe_the_next_request() {
    let mut input = chunked_request(b"Content-Length: 50\r\nTransfer-Encoding: chunked\r\n");
    input.extend_from_slice(b"GET /next HTTP/1.1\r\nHost: a\r\n\r\n");
    let events = whole_and_bytewise(&input, Limits::new(), REPORT);
    let heads: Vec<&Ev> = events
        .iter()
        .filter(|e| matches!(e, Ev::Head { .. }))
        .collect();
    assert_eq!(heads.len(), 2, "{events:?}");
    let Ev::Head {
        target, framing, ..
    } = heads[1]
    else {
        unreachable!()
    };
    assert_eq!(target, "/next");
    assert_eq!(*framing, BodyFraming::None);
}

/// A response written at the trailers event does not close the
/// connection: the whole request has been read by then.
#[test]
fn test_server_trailers_response_at_trailers_event_keeps_alive() {
    let mut conn = ServerConn::new();
    conn.set_report_trailers(true);
    let _ = conn.feed(&chunked_request(b"X: 1\r\n"));
    let mut out = Vec::new();
    loop {
        match conn.poll().unwrap() {
            ServerEvent::Trailers(_) => conn.respond(&Response::new(204), &mut out).unwrap(),
            ServerEvent::RequestEnd => break,
            _ => {}
        }
    }
    assert!(!out.windows(17).any(|w| w == b"connection: close"));
    assert!(matches!(conn.poll().unwrap(), ServerEvent::NeedInput));
}

/// E-110: the trailer field count has its own budget.
#[test]
fn test_server_trailers_over_count_budget_are_too_many_headers() {
    let limits = Limits::new().with_max_trailer_fields(2);
    let ok = chunked_request(b"A: 1\r\nB: 2\r\n");
    assert!(whole_and_bytewise(&ok, limits, REPORT).contains(&Ev::End));
    let over = chunked_request(b"A: 1\r\nB: 2\r\nC: 3\r\n");
    let events = whole_and_bytewise(&over, limits, REPORT);
    assert_eq!(events.last(), Some(&Ev::Err(HttpError::TooManyHeaders)));
    // The header count is unaffected by the trailer budget.
    let many_headers =
        b"POST / HTTP/1.1\r\nHost: a\r\nA: 1\r\nB: 2\r\nC: 3\r\nContent-Length: 0\r\n\r\n";
    assert!(whole_and_bytewise(many_headers, limits, REPORT).contains(&Ev::End));
}

/// E-110: the trailer section has its own byte budget; at the budget it
/// passes, one byte over it does not.
#[test]
fn test_server_trailers_over_byte_budget_are_headers_too_large() {
    // "X: vvvv\r\n" (9 bytes) plus the blank line: an 11-byte section.
    let limits = Limits::new().with_max_trailer_bytes(11);
    let at = chunked_request(b"X: vvvv\r\n");
    assert!(whole_and_bytewise(&at, limits, REPORT).contains(&Ev::End));
    let over = chunked_request(b"X: vvvvv\r\n");
    let events = whole_and_bytewise(&over, limits, REPORT);
    assert_eq!(events.last(), Some(&Ev::Err(HttpError::HeadersTooLarge)));
}

/// E-46 for trailers: one trailer line over `max_field_line` is refused.
#[test]
fn test_server_trailers_long_field_line_is_field_line_too_long() {
    // 32 bytes leaves room for the head's own lines (the longest is
    // "Transfer-Encoding: chunked\r\n", 28 bytes).
    let limits = Limits::new().with_max_field_line(32);
    // "X: " + 27 bytes + CRLF is 32 bytes.
    let at = chunked_request(b"X: 0123456789abcdefghijklmnopq\r\n");
    assert!(whole_and_bytewise(&at, limits, REPORT).contains(&Ev::End));
    let over = chunked_request(b"X: 0123456789abcdefghijklmnopqr\r\n");
    let events = whole_and_bytewise(&over, limits, REPORT);
    assert_eq!(events.last(), Some(&Ev::Err(HttpError::FieldLineTooLong)));
}

/// E-111: trailer lines follow the header rules.
#[test]
fn test_server_trailers_bad_lines_are_refused_like_headers() {
    for (trailer, err) in [
        (&b" folded\r\n"[..], HttpError::ObsFold),
        (b"X : 1\r\n", HttpError::WhitespaceBeforeColon),
        (b"X: a\x00b\r\n", HttpError::InvalidHeaderValue),
        (b"no-colon\r\n", HttpError::InvalidHeaderName),
    ] {
        let events = whole_and_bytewise(&chunked_request(trailer), Limits::new(), REPORT);
        assert_eq!(events.last(), Some(&Ev::Err(err)), "{trailer:?}");
    }
}

/// The client reports response trailers the same way.
#[test]
fn test_client_trailers_reported_when_on_and_absent_when_off() {
    let response =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nServer-Timing: db;dur=5\r\n\r\n";
    let request = Request::get("/").header("host", "a");
    for (opts, expect) in [(REPORT, true), (Opts::default(), false)] {
        let whole = common::drive_client_opts(&request, &[response], Limits::new(), opts);
        let bytes: Vec<&[u8]> = response.chunks(1).collect();
        let bytewise = common::drive_client_opts(&request, &bytes, Limits::new(), opts);
        assert_eq!(whole, bytewise);
        let reported = whole.contains(&Ev::Trailers(vec![(
            "Server-Timing".into(),
            b"db;dur=5".to_vec(),
        )]));
        assert_eq!(reported, expect, "{whole:?}");
        assert!(whole.contains(&Ev::End));
    }
}

/// T-13 on the client: trailer fields cannot reframe a pipelined response
/// stream. With two GETs in flight, a `Content-Length: 50` in the first
/// response's trailers is not applied to anything: the second response is
/// framed by its own head, so the bodies are `z` then `ok`, with trailer
/// reporting on or off and the input split at every byte.
#[test]
fn test_client_trailers_cannot_reframe_the_next_pipelined_response() {
    let wire: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nz\r\n0\r\nContent-Length: 50\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let get = || Request::get("/").header("host", "a");
    for report in [false, true] {
        for cut in 0..wire.len() {
            let mut conn = ClientConn::with_limits(Limits::new().with_pipeline_depth(2));
            conn.set_report_trailers(report);
            let mut out = Vec::new();
            conn.send_request(&get(), &mut out).unwrap();
            conn.send_request(&get(), &mut out).unwrap();
            let mut pieces = split(wire, &[cut]).into_iter();
            let (mut bodies, mut body, mut trailers) = (Vec::new(), Vec::new(), Vec::new());
            loop {
                match conn.poll().unwrap() {
                    ClientEvent::Response(_) => body.clear(),
                    ClientEvent::Body(b) => body.extend_from_slice(b),
                    ClientEvent::Trailers(t) => {
                        trailers.extend(t.map(|(n, v)| (n.to_string(), v.to_vec())));
                    }
                    ClientEvent::ResponseEnd => {
                        bodies.push(String::from_utf8_lossy(&body).into_owned());
                    }
                    ClientEvent::NeedInput => {
                        let piece = pieces.next().expect("input ran out before two responses");
                        assert_eq!(conn.feed(piece), piece.len());
                    }
                    ClientEvent::Idle => break,
                    other => panic!("unexpected {other:?}"),
                }
            }
            assert_eq!(bodies, ["z", "ok"], "report {report}, cut {cut}");
            let expected: Vec<(String, Vec<u8>)> = if report {
                vec![("Content-Length".into(), b"50".to_vec())]
            } else {
                Vec::new()
            };
            assert_eq!(trailers, expected, "report {report}, cut {cut}");
            assert_eq!(conn.outstanding(), 0);
        }
    }
}

fn streaming_server(request: &[u8]) -> (ServerConn, Vec<u8>) {
    let mut conn = ServerConn::new();
    let _ = conn.feed(request);
    while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
    (conn, Vec::new())
}

/// E-178: every forbidden field, in any case, is refused and nothing is
/// written; a valid call afterwards still finishes the body.
#[test]
fn test_server_trailers_forbidden_fields_are_refused_and_write_nothing() {
    for &name in FORBIDDEN {
        for spelled in [name.to_string(), name.to_ascii_uppercase()] {
            let (mut conn, mut out) = streaming_server(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
            conn.respond(&Response::new(200).chunked(), &mut out)
                .unwrap();
            conn.send_body(b"x", &mut out).unwrap();
            let before = out.len();
            assert_eq!(
                conn.end_body_with_trailers(&[("x-ok", b"1"), (&spelled, b"v")], &mut out),
                Err(HttpError::TrailerNotAllowed),
                "{spelled}"
            );
            assert_eq!(out.len(), before, "{spelled}: bytes written on refusal");
            conn.end_body_with_trailers(&[("x-ok", b"1")], &mut out)
                .unwrap();
            assert!(out.ends_with(b"0\r\nx-ok: 1\r\n\r\n"));
        }
    }
}

/// E-178 on the client: forbidden request trailers are refused too.
#[test]
fn test_client_trailers_forbidden_fields_are_refused() {
    for &name in FORBIDDEN {
        let mut conn = ClientConn::new();
        let mut out = Vec::new();
        conn.send_request(&Request::post("/").header("host", "a").chunked(), &mut out)
            .unwrap();
        let before = out.len();
        assert_eq!(
            conn.end_body_with_trailers(&[(name, b"v")], &mut out),
            Err(HttpError::TrailerNotAllowed),
            "{name}"
        );
        assert_eq!(out.len(), before);
    }
}

/// Trailer fields must still be valid fields.
#[test]
fn test_server_trailers_invalid_fields_are_refused() {
    for (name, value, err) in [
        ("bad name", &b"v"[..], HttpError::InvalidHeaderName),
        ("x", b"a\r\nInjected: 1", HttpError::BareCr),
        ("x", b" padded", HttpError::InvalidHeaderValue),
        ("x", b"nul\x00", HttpError::InvalidHeaderValue),
    ] {
        let (mut conn, mut out) = streaming_server(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        conn.respond(&Response::new(200).chunked(), &mut out)
            .unwrap();
        assert_eq!(
            conn.end_body_with_trailers(&[(name, value)], &mut out),
            Err(err),
            "{name:?} {value:?}"
        );
    }
}

/// E-178: trailers on a `content_length` body are refused (on both sides);
/// an empty trailer list is the same as `end_body`.
#[test]
fn test_trailers_on_content_length_body_are_refused() {
    let (mut conn, mut out) = streaming_server(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    conn.respond(&Response::new(200).content_length(2), &mut out)
        .unwrap();
    conn.send_body(b"ok", &mut out).unwrap();
    assert_eq!(
        conn.end_body_with_trailers(&[("x", b"1")], &mut out),
        Err(HttpError::TrailerNotAllowed)
    );
    conn.end_body_with_trailers(&[], &mut out).unwrap();
    assert_eq!(conn.requests_served(), 1);

    let mut client = ClientConn::new();
    let mut out = Vec::new();
    client
        .send_request(
            &Request::post("/").header("host", "a").content_length(1),
            &mut out,
        )
        .unwrap();
    client.send_body(b"z", &mut out).unwrap();
    assert_eq!(
        client.end_body_with_trailers(&[("x", b"1")], &mut out),
        Err(HttpError::TrailerNotAllowed)
    );
    client.end_body(&mut out).unwrap();
}

/// FR-35: trailers are dropped with the body for an HTTP/1.0 client (close
/// delimited) and for `HEAD`, but are still validated, so the same call
/// fails the same way whatever framing the client forced.
#[test]
fn test_server_trailers_dropped_for_http10_and_head_but_validated() {
    for request in [
        &b"GET / HTTP/1.0\r\n\r\n"[..],
        b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n",
    ] {
        let (mut conn, mut out) = streaming_server(request);
        conn.respond(&Response::new(200).chunked(), &mut out)
            .unwrap();
        let head_len = out.len();
        conn.send_body(b"data", &mut out).unwrap();
        assert_eq!(
            conn.end_body_with_trailers(&[("set-cookie", b"a=1")], &mut out),
            Err(HttpError::TrailerNotAllowed)
        );
        conn.end_body_with_trailers(&[("x-sum", b"9")], &mut out)
            .unwrap();
        assert!(!out.windows(5).any(|w| w == b"x-sum"), "{request:?}");
        // Nothing chunk-shaped follows the head.
        assert!(!out[head_len..].windows(3).any(|w| w == b"0\r\n"));
    }
}

/// Outgoing trailers parse back on the other side, any split.
#[test]
fn test_trailers_written_by_client_parse_on_server() {
    let mut client = ClientConn::new();
    let mut wire = Vec::new();
    client
        .send_request(&Request::put("/f").header("host", "a").chunked(), &mut wire)
        .unwrap();
    client.send_body(b"part one,", &mut wire).unwrap();
    client.send_body(b" part two", &mut wire).unwrap();
    client
        .end_body_with_trailers(
            &[("content-digest", b"sha-256=:abc:"), ("x-rows", b"2")],
            &mut wire,
        )
        .unwrap();
    for cuts in [vec![], vec![3, 40, 77], (0..wire.len()).collect()] {
        let events = drive_server_opts(&split(&wire, &cuts), Limits::new(), REPORT);
        assert!(events.contains(&Ev::Body(b"part one, part two".to_vec())));
        assert!(events.contains(&Ev::Trailers(vec![
            ("content-digest".into(), b"sha-256=:abc:".to_vec()),
            ("x-rows".into(), b"2".to_vec()),
        ])));
    }
}

/// X-7: a list field is split on commas outside quoted strings only, across
/// every line with that name.
#[test]
fn test_header_list_quoted_commas_do_not_split_elements() {
    let mut conn = ServerConn::new();
    let _ = conn.feed(
        b"GET / HTTP/1.1\r\nHost: a\r\nX-L: a=\"1,2\", b\r\nX-L: , c=\"q\\\",x\"\r\nX-L:\r\n\r\n",
    );
    let ServerEvent::Request(req) = conn.poll().unwrap() else {
        panic!()
    };
    let list: Vec<&[u8]> = req.header_list("x-l").collect();
    assert_eq!(list, [&b"a=\"1,2\""[..], b"b", b"c=\"q\\\",x\""]);
    assert_eq!(req.header_list("missing").count(), 0);
    // `Debug` of the list names its elements.
    assert!(format!("{:?}", req.header_list("x-l")).contains("b"));
}

/// X-7: a quoted comma inside a `chunked` parameter keeps it one element,
/// which is still refused (parameters on `chunked` are invalid), so no
/// message the 0.3 splitter accepted is accepted now.
#[test]
fn test_transfer_encoding_quoted_parameter_still_refused() {
    let input = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked;x=\"a,b\"\r\n\r\n";
    assert_eq!(
        common::server_error(input),
        Some(HttpError::InvalidTransferEncoding)
    );
    let input = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip;q=\"1,chunked\"\r\n\r\n";
    assert!(common::server_error(input).is_some());
}

/// `ClientEvent::Trailers` carries the same redaction as every other view.
#[test]
fn test_client_trailers_debug_redacts_credentials() {
    let mut conn = ClientConn::new();
    conn.set_report_trailers(true);
    conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())
        .unwrap();
    let _ = conn.feed(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nSet-Cookie: sid=s3cr3t\r\n\r\n",
    );
    loop {
        match conn.poll().unwrap() {
            ClientEvent::Trailers(t) => {
                let shown = format!("{t:?}");
                assert!(!shown.contains("s3cr3t"), "{shown}");
                assert!(shown.contains("<redacted 10 bytes>"), "{shown}");
            }
            ClientEvent::ResponseEnd => break,
            _ => {}
        }
    }
}
