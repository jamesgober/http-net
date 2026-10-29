//! What a driver controls and observes on a live connection (FR-26,
//! FR-27, FR-36, FR-49, FR-50; E-46, E-122, E-128, E-142, E-177), the
//! per-line field budget, and the 0.4 reserved field names.

mod common;

use common::{Ev, drive_server};
use http_net::{
    ClientConn, ClientEvent, DateCache, HttpDate, HttpError, Limits, Method, Progress, Request,
    Response, ServerConn, ServerEvent, status_allows_body,
};

fn at_request_end(conn: &mut ServerConn) {
    while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
}

fn closes(out: &[u8]) -> bool {
    out.windows(17).any(|w| w == b"connection: close")
}

/// E-122: `set_keep_alive(false)` before responding writes
/// `connection: close` and ends the connection after the response, with a
/// pipelined request left unparsed.
#[test]
fn test_server_set_keep_alive_false_before_respond_closes_after_it() {
    let mut conn = ServerConn::new();
    let _ = conn.feed(b"GET /a HTTP/1.1\r\nHost: a\r\n\r\nGET /b HTTP/1.1\r\nHost: a\r\n\r\n");
    at_request_end(&mut conn);
    assert!(conn.keep_alive());
    conn.set_keep_alive(false);
    assert!(!conn.keep_alive());
    let mut out = Vec::new();
    conn.respond(&Response::new(204), &mut out).unwrap();
    assert!(closes(&out));
    assert!(matches!(conn.poll().unwrap(), ServerEvent::Closed));
}

/// E-122: called while a streamed response is already being written, the
/// connection still ends after that response (its head said keep-alive).
#[test]
fn test_server_set_keep_alive_false_mid_stream_ends_after_the_response() {
    let mut conn = ServerConn::new();
    let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\nGET /next HTTP/1.1\r\nHost: a\r\n\r\n");
    at_request_end(&mut conn);
    let mut out = Vec::new();
    conn.respond(&Response::new(200).chunked(), &mut out)
        .unwrap();
    assert!(!closes(&out));
    conn.set_keep_alive(false);
    conn.send_body(b"x", &mut out).unwrap();
    conn.end_body(&mut out).unwrap();
    assert!(matches!(conn.poll().unwrap(), ServerEvent::Closed));
}

/// `set_keep_alive(false)` before any request applies to the first one;
/// `true` cannot override a close the client asked for.
#[test]
fn test_server_set_keep_alive_applies_early_and_cannot_force_open() {
    let mut conn = ServerConn::new();
    conn.set_keep_alive(false);
    let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    at_request_end(&mut conn);
    let mut out = Vec::new();
    conn.respond(&Response::new(204), &mut out).unwrap();
    assert!(closes(&out));

    let mut conn = ServerConn::new();
    let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
    at_request_end(&mut conn);
    conn.set_keep_alive(true);
    assert!(!conn.keep_alive());
    let mut out = Vec::new();
    conn.respond(&Response::new(204), &mut out).unwrap();
    assert!(closes(&out));
    assert!(matches!(conn.poll().unwrap(), ServerEvent::Closed));
}

/// FR-49: responses are counted when complete: full bodies when written,
/// streamed ones at `end_body`, error answers too.
#[test]
fn test_server_requests_served_counts_completed_responses() {
    let mut conn = ServerConn::new();
    let _ = conn.feed(
        b"GET /1 HTTP/1.1\r\nHost: a\r\n\r\nGET /2 HTTP/1.1\r\nHost: a\r\n\r\nGET /3 HTTP/1.1\r\n\r\n",
    );
    let mut out = Vec::new();
    at_request_end(&mut conn);
    conn.respond(&Response::new(204), &mut out).unwrap();
    assert_eq!(conn.requests_served(), 1);
    at_request_end(&mut conn);
    conn.respond(&Response::new(200).content_length(1), &mut out)
        .unwrap();
    assert_eq!(conn.requests_served(), 1);
    conn.send_body(b"x", &mut out).unwrap();
    conn.end_body(&mut out).unwrap();
    assert_eq!(conn.requests_served(), 2);
    let err = conn.poll().unwrap_err();
    assert_eq!(err, HttpError::MissingHost);
    conn.respond(&Response::from_error(&err), &mut out).unwrap();
    assert_eq!(conn.requests_served(), 3);
    // Interim responses are not completed responses.
    let mut conn = ServerConn::new();
    let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    at_request_end(&mut conn);
    conn.send_informational(&Response::new(103), &mut out)
        .unwrap();
    assert_eq!(conn.requests_served(), 0);
}

/// FR-50: the server's progress at every step of an exchange.
#[test]
fn test_server_progress_follows_each_phase() {
    let mut conn = ServerConn::new();
    let mut out = Vec::new();
    assert_eq!(conn.progress(), Progress::Idle);
    let _ = conn.feed(b"POST / HTTP/1.1\r\n");
    assert!(matches!(conn.poll().unwrap(), ServerEvent::NeedInput));
    assert_eq!(conn.progress(), Progress::Head);
    let _ = conn.feed(b"Host: a\r\nContent-Length: 4\r\n\r\nab");
    assert!(matches!(conn.poll().unwrap(), ServerEvent::Request(_)));
    assert_eq!(conn.progress(), Progress::Body);
    assert!(matches!(conn.poll().unwrap(), ServerEvent::Body(_)));
    assert_eq!(conn.progress(), Progress::Body);
    let _ = conn.feed(b"cd");
    at_request_end(&mut conn);
    assert_eq!(conn.progress(), Progress::AwaitingResponse);
    assert!(matches!(
        conn.poll().unwrap(),
        ServerEvent::AwaitingResponse
    ));
    conn.respond(&Response::new(200).chunked(), &mut out)
        .unwrap();
    assert_eq!(conn.progress(), Progress::WritingBody);
    conn.end_body(&mut out).unwrap();
    assert_eq!(conn.progress(), Progress::Idle);
    // Idle keep-alive time is not a request.
    assert!(matches!(conn.poll().unwrap(), ServerEvent::NeedInput));
    assert_eq!(conn.progress(), Progress::Idle);
    // An early answer with unread body bytes ends the connection.
    let _ = conn.feed(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 9\r\n\r\n");
    assert!(matches!(conn.poll().unwrap(), ServerEvent::Request(_)));
    conn.respond(&Response::new(413), &mut out).unwrap();
    assert_eq!(conn.progress(), Progress::Closed);
    // After a parse error one answer is still expected, then it is over.
    let mut conn = ServerConn::new();
    let _ = conn.feed(b"GET / HTTP/1.1\r\n\r\n");
    assert!(conn.poll().is_err());
    assert_eq!(conn.progress(), Progress::AwaitingResponse);
    conn.respond(&Response::new(400), &mut out).unwrap();
    assert_eq!(conn.progress(), Progress::Closed);
    // An upgrade.
    let mut conn = ServerConn::new();
    let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: ws\r\n\r\n");
    at_request_end(&mut conn);
    conn.respond(&Response::switching_protocols("ws"), &mut out)
        .unwrap();
    assert_eq!(conn.progress(), Progress::Upgraded);
}

/// FR-50: a request with no body answered at `ServerEvent::Request`, before
/// `RequestEnd` is polled, leaves a keep-alive connection `Idle`, not
/// `Closed` (fixed in 0.9.0: a driver that closes on `Closed` dropped a
/// healthy connection). A `close` answer still reports `Closed`.
#[test]
fn test_server_progress_answered_at_request_event_stays_idle() {
    let mut out = Vec::new();
    for (request, response, expected) in [
        (
            &b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"[..],
            Response::new(204),
            Progress::Idle,
        ),
        (
            &b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n"[..],
            Response::new(200),
            Progress::Idle,
        ),
        (
            &b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"[..],
            Response::new(204).close(),
            Progress::Closed,
        ),
        (
            &b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"[..],
            Response::new(204),
            Progress::Closed,
        ),
    ] {
        let mut conn = ServerConn::new();
        let _ = conn.feed(request);
        assert!(matches!(conn.poll().unwrap(), ServerEvent::Request(_)));
        conn.respond(&response, &mut out).unwrap();
        assert_eq!(
            conn.progress(),
            expected,
            "{}",
            String::from_utf8_lossy(request)
        );
        assert!(matches!(conn.poll().unwrap(), ServerEvent::RequestEnd));
        assert_eq!(conn.progress(), expected);
        if expected == Progress::Idle {
            assert!(matches!(conn.poll().unwrap(), ServerEvent::NeedInput));
            let _ = conn.feed(b"GET /next HTTP/1.1\r\nHost: a\r\n\r\n");
            assert!(matches!(conn.poll().unwrap(), ServerEvent::Request(_)));
        }
    }
}

/// FR-50: the client's progress at every step.
#[test]
fn test_client_progress_follows_each_phase() {
    let mut conn = ClientConn::new();
    let mut out = Vec::new();
    assert_eq!(conn.progress(), Progress::Idle);
    conn.send_request(&Request::post("/").header("host", "a").chunked(), &mut out)
        .unwrap();
    assert_eq!(conn.progress(), Progress::WritingBody);
    conn.end_body(&mut out).unwrap();
    assert_eq!(conn.progress(), Progress::AwaitingResponse);
    let _ = conn.feed(b"HTTP/1.1 200 OK\r\n");
    assert!(matches!(conn.poll().unwrap(), ClientEvent::NeedInput));
    assert_eq!(conn.progress(), Progress::Head);
    let _ = conn.feed(b"Content-Length: 2\r\n\r\no");
    assert!(matches!(conn.poll().unwrap(), ClientEvent::Response(_)));
    assert_eq!(conn.progress(), Progress::Body);
    assert!(matches!(conn.poll().unwrap(), ClientEvent::Body(_)));
    let _ = conn.feed(b"k");
    assert!(matches!(conn.poll().unwrap(), ClientEvent::Body(_)));
    assert!(matches!(conn.poll().unwrap(), ClientEvent::ResponseEnd));
    assert_eq!(conn.progress(), Progress::Idle);
    assert!(matches!(conn.poll().unwrap(), ClientEvent::Idle));
    assert_eq!(conn.progress(), Progress::Idle);
    // A response that closes.
    conn.send_request(&Request::get("/").header("host", "a").close(), &mut out)
        .unwrap();
    let _ = conn.feed(b"HTTP/1.1 204 No Content\r\n\r\n");
    while !matches!(conn.poll().unwrap(), ClientEvent::ResponseEnd) {}
    assert_eq!(conn.progress(), Progress::Closed);
    // An upgrade.
    let mut conn = ClientConn::new();
    conn.send_request(
        &Request::get("/").header("host", "a").upgrade("ws"),
        &mut out,
    )
    .unwrap();
    let _ = conn
        .feed(b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: ws\r\n\r\n");
    assert!(matches!(conn.poll().unwrap(), ClientEvent::Response(_)));
    assert_eq!(conn.progress(), Progress::Upgraded);
}

/// `is_reusable` on the client: false while a request is outstanding, with
/// unsolicited bytes buffered, and after EOF.
#[test]
fn test_client_is_reusable_rules() {
    let mut conn = ClientConn::new();
    assert!(conn.is_reusable());
    let _ = conn.feed(b"x");
    assert!(!conn.is_reusable());
    let mut conn = ClientConn::new();
    conn.feed_eof();
    assert!(!conn.is_reusable());
    let mut conn = ClientConn::new();
    conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())
        .unwrap();
    let _ = conn.feed(b"HTTP/1.0 200 OK\r\n\r\nbody");
    while !matches!(conn.poll().unwrap(), ClientEvent::NeedInput) {}
    conn.feed_eof();
    while !matches!(conn.poll().unwrap(), ClientEvent::ResponseEnd) {}
    assert!(
        !conn.is_reusable(),
        "a read-until-close response is never reusable"
    );
}

/// FR-36 / E-177: `respond_with_date` adds the date, a caller-set `date`
/// wins, and the cache returns the formatted value.
#[test]
fn test_server_respond_with_date_and_caller_date_wins() {
    let mut cache = DateCache::new();
    let date = *cache.update(1_000_000_000);
    assert_eq!(date, HttpDate::from_unix_seconds(1_000_000_000));
    let mut conn = ServerConn::new();
    let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n");
    at_request_end(&mut conn);
    let mut out = Vec::new();
    conn.respond_with_date(&Response::new(204), &date, &mut out)
        .unwrap();
    let line = format!("date: {date}\r\n");
    assert!(String::from_utf8_lossy(&out).contains(&line));
    at_request_end(&mut conn);
    let mut out = Vec::new();
    let own = Response::new(204).header("date", "Tue, 15 Nov 1994 08:12:31 GMT");
    conn.respond_with_date(&own, &date, &mut out).unwrap();
    let text = String::from_utf8_lossy(&out);
    assert_eq!(text.matches("date: ").count(), 1, "{text}");
    assert!(text.contains("date: Tue, 15 Nov 1994 08:12:31 GMT"));
}

/// FR-26 / E-128: unknown expectations are reported for any version and
/// never change framing.
#[test]
fn test_has_unknown_expectation_reported_never_frames() {
    for (input, continue_, unknown) in [
        (
            &b"PUT / HTTP/1.1\r\nHost: a\r\nExpect: 100-continuex\r\nContent-Length: 1\r\n\r\nz"[..],
            false,
            true,
        ),
        (
            b"PUT / HTTP/1.1\r\nHost: a\r\nExpect: foo\r\nContent-Length: 1\r\n\r\nz",
            false,
            true,
        ),
        (
            b"PUT / HTTP/1.0\r\nExpect: foo\r\nContent-Length: 1\r\n\r\nz",
            false,
            true,
        ),
        (
            b"PUT / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue, foo\r\nContent-Length: 1\r\n\r\nz",
            true,
            true,
        ),
        (
            b"PUT / HTTP/1.1\r\nHost: a\r\nExpect: 100-Continue\r\nContent-Length: 1\r\n\r\nz",
            true,
            false,
        ),
        (
            b"PUT / HTTP/1.1\r\nHost: a\r\nExpect:\r\nContent-Length: 1\r\n\r\nz",
            false,
            false,
        ),
        (
            b"PUT / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\nz",
            false,
            false,
        ),
    ] {
        let mut conn = ServerConn::new();
        let _ = conn.feed(input);
        let ServerEvent::Request(req) = conn.poll().unwrap() else {
            panic!()
        };
        assert_eq!(req.expects_continue(), continue_, "{input:?}");
        assert_eq!(req.has_unknown_expectation(), unknown, "{input:?}");
        // The one body byte is framed by Content-Length whatever Expect says.
        let events = drive_server(&[input], Limits::new());
        assert!(events.contains(&Ev::Body(b"z".to_vec())), "{input:?}");
    }
}

/// FR-27 / E-142: the offered protocols, `h2c` left out; empty when the
/// request is not an upgrade.
#[test]
fn test_upgrade_protocols_omit_h2c_and_need_an_upgrade() {
    let protocols = |input: &[u8]| -> Vec<Vec<u8>> {
        let mut conn = ServerConn::new();
        let _ = conn.feed(input);
        let ServerEvent::Request(req) = conn.poll().unwrap() else {
            panic!()
        };
        req.upgrade_protocols().map(<[u8]>::to_vec).collect()
    };
    assert_eq!(
        protocols(
            b"GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: h2c, websocket\r\n\r\n"
        ),
        [b"websocket".to_vec()]
    );
    assert_eq!(
        protocols(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: foo/2\r\nUpgrade: H2C, bar\r\n\r\n"),
        [b"foo/2".to_vec(), b"bar".to_vec()]
    );
    assert!(protocols(b"GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n\r\n").is_empty());
    assert!(
        protocols(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: h2c\r\n\r\n")
            .is_empty()
    );
    assert!(
        protocols(b"GET / HTTP/1.0\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n")
            .is_empty()
    );
}

/// The 0.4 reserved names, any case: `trailer`, `keep-alive`, and
/// `proxy-connection` on both builders, `te` on responses only.
#[test]
fn test_reserved_names_0_4_are_refused_in_any_case() {
    for name in ["trailer", "keep-alive", "proxy-connection", "te"] {
        for spelled in [name.to_string(), name.to_ascii_uppercase()] {
            let mut conn = ServerConn::new();
            let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
            at_request_end(&mut conn);
            assert_eq!(
                conn.respond(&Response::new(200).header(&spelled, "x"), &mut Vec::new()),
                Err(HttpError::ReservedHeader),
                "response {spelled}"
            );
            let request = Request::get("/")
                .header("host", "a")
                .header(&spelled, "trailers");
            let sent = ClientConn::new().send_request(&request, &mut Vec::new());
            if name == "te" {
                assert_eq!(sent, Ok(()), "a request may carry TE");
            } else {
                assert_eq!(sent, Err(HttpError::ReservedHeader), "request {spelled}");
            }
        }
    }
}

fn with_field_line(len: usize) -> Vec<u8> {
    // "X: " + value + CRLF is `len` bytes.
    let mut v = b"GET / HTTP/1.1\r\nHost: a\r\nX: ".to_vec();
    v.extend(std::iter::repeat_n(b'v', len - 5));
    v.extend_from_slice(b"\r\n\r\n");
    v
}

/// E-46: a field line of exactly `max_field_line` passes, one byte more is
/// `FieldLineTooLong` (431), whole and byte by byte, with the default 8 KiB
/// budget and a small one.
#[test]
fn test_field_line_at_budget_passes_one_more_is_field_line_too_long() {
    for limits in [Limits::new(), Limits::new().with_max_field_line(64)] {
        let n = limits.max_field_line();
        for (input, ok) in [(with_field_line(n), true), (with_field_line(n + 1), false)] {
            let whole = drive_server(&[&input], limits);
            let bytes: Vec<&[u8]> = input.chunks(1).collect();
            assert_eq!(whole, drive_server(&bytes, limits));
            if ok {
                assert!(whole.contains(&Ev::End), "{n}");
            } else {
                assert_eq!(
                    whole.last(),
                    Some(&Ev::Err(HttpError::FieldLineTooLong)),
                    "{n}"
                );
            }
        }
    }
    assert_eq!(HttpError::FieldLineTooLong.status(), Some(431));
}

/// E-46: the line is refused as soon as it is too long, before its end
/// arrives.
#[test]
fn test_field_line_refused_before_the_line_completes() {
    let limits = Limits::new().with_max_field_line(64);
    let mut conn = ServerConn::with_limits(limits);
    let mut partial = b"GET / HTTP/1.1\r\nHost: a\r\nX: ".to_vec();
    partial.extend(std::iter::repeat_n(b'v', 100));
    let _ = conn.feed(&partial);
    assert_eq!(conn.poll().unwrap_err(), HttpError::FieldLineTooLong);
}

/// The section budget still decides when it is the smaller one.
#[test]
fn test_field_line_section_budget_smaller_is_headers_too_large() {
    let limits = Limits::new()
        .with_max_header_bytes(40)
        .with_max_field_line(1024);
    let events = drive_server(&[&with_field_line(60)], limits);
    assert_eq!(events.last(), Some(&Ev::Err(HttpError::HeadersTooLarge)));
}

/// `status_allows_body` against RFC 9112 section 6.3 rules 1 and 2.
#[test]
fn test_status_allows_body_table() {
    let rows: &[(u16, Method, bool)] = &[
        (100, Method::Get, false),
        (103, Method::Post, false),
        (199, Method::Get, false),
        (200, Method::Get, true),
        (200, Method::Head, false),
        (404, Method::Head, false),
        (200, Method::Connect, false),
        (299, Method::Connect, false),
        (407, Method::Connect, true),
        (204, Method::Post, false),
        (205, Method::Post, true),
        (304, Method::Get, false),
        (500, Method::Other, true),
    ];
    for &(status, method, allows) in rows {
        assert_eq!(
            status_allows_body(status, method),
            allows,
            "{status} {method:?}"
        );
    }
}
