//! Interim (1xx) responses and `Expect: 100-continue`, both sides (FR-25,
//! FR-34, FR-39, FR-40; E-129 to E-136; threat T-31).

mod common;

use common::{Ev, Opts, drive_client_opts};
use http_net::{
    ClientConn, ClientEvent, HttpError, Limits, Request, Response, ServerConn, ServerEvent,
};

const INFORMATIONAL: Opts = Opts {
    report_trailers: false,
    report_informational: true,
};

fn server_at_request_end(input: &[u8]) -> ServerConn {
    let mut conn = ServerConn::new();
    let _ = conn.feed(input);
    while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
    conn
}

/// E-131: a 103 and then the final response are written in order, and the
/// interim response leaves the exchange untouched.
#[test]
fn test_server_send_informational_then_final_are_written_in_order() {
    let mut conn = server_at_request_end(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    let mut out = Vec::new();
    let hints = Response::new(103).header("link", "</a.css>; rel=preload");
    conn.send_informational(&hints, &mut out).unwrap();
    conn.send_informational(&Response::new(103), &mut out)
        .unwrap();
    conn.respond(&Response::text(200, "ok"), &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    let first = text.find("HTTP/1.1 103 Early Hints\r\nlink: </a.css>; rel=preload\r\n\r\n");
    let second = text.rfind("HTTP/1.1 103 Early Hints\r\n\r\n");
    let fin = text.find("HTTP/1.1 200 OK\r\n");
    assert!(
        first.unwrap() < second.unwrap() && second.unwrap() < fin.unwrap(),
        "{text}"
    );
    assert_eq!(conn.requests_served(), 1);
    assert!(matches!(conn.poll().unwrap(), ServerEvent::NeedInput));
}

/// E-131 for `HEAD`: interim responses go to any method (RFC 9110 section
/// 15.2), and before the body has been read.
#[test]
fn test_server_send_informational_any_method_and_before_the_body() {
    let mut conn = ServerConn::new();
    let _ = conn.feed(b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n");
    assert!(matches!(conn.poll().unwrap(), ServerEvent::Request(_)));
    let mut out = Vec::new();
    conn.send_informational(&Response::new(103), &mut out)
        .unwrap();

    let mut conn = ServerConn::new();
    let _ = conn.feed(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n");
    assert!(matches!(conn.poll().unwrap(), ServerEvent::Request(_)));
    conn.send_informational(&Response::new(102), &mut out)
        .unwrap();
    assert!(out.ends_with(b"HTTP/1.1 102 Processing\r\n\r\n"));
}

/// E-132: only 102..=199 are interim responses this call sends (100 has
/// `send_continue`, 101 `switching_protocols`).
#[test]
fn test_server_send_informational_wrong_status_is_invalid_status() {
    for status in [99, 100, 101, 200, 204, 600] {
        let mut conn = server_at_request_end(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        let mut out = Vec::new();
        assert_eq!(
            conn.send_informational(&Response::new(status), &mut out),
            Err(HttpError::InvalidStatus),
            "{status}"
        );
        assert!(out.is_empty());
    }
}

/// E-133: never to an HTTP/1.0 client; never once the final response has
/// started; never with a body; never without a request.
#[test]
fn test_server_send_informational_refusals() {
    let mut out = Vec::new();
    let mut conn = server_at_request_end(b"GET / HTTP/1.0\r\n\r\n");
    assert_eq!(
        conn.send_informational(&Response::new(103), &mut out),
        Err(HttpError::InterimNotAllowed)
    );

    let mut conn = server_at_request_end(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    conn.respond(&Response::new(200).chunked(), &mut out)
        .unwrap();
    out.clear();
    assert_eq!(
        conn.send_informational(&Response::new(103), &mut out),
        Err(HttpError::InterimNotAllowed)
    );
    assert!(out.is_empty());

    let mut conn = server_at_request_end(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    assert_eq!(
        conn.send_informational(&Response::new(103).body(&b"x"[..]), &mut out),
        Err(HttpError::BodyNotAllowed)
    );
    assert_eq!(
        conn.send_informational(&Response::new(103).chunked(), &mut out),
        Err(HttpError::BodyNotAllowed)
    );
    // A builder error comes first.
    assert_eq!(
        conn.send_informational(&Response::new(103).header("upgrade", "x"), &mut out),
        Err(HttpError::ReservedHeader)
    );

    let mut conn = ServerConn::new();
    assert!(matches!(
        conn.send_informational(&Response::new(103), &mut out),
        Err(HttpError::InvalidState(_))
    ));
    let _ = conn.feed(b"GET / HTTP/1.1\r\n\r\n");
    assert!(conn.poll().is_err());
    assert!(matches!(
        conn.send_informational(&Response::new(103), &mut out),
        Err(HttpError::InvalidState(_))
    ));
}

/// E-134: interim responses are skipped by default and reported in order
/// with reporting on; a `100` nobody waited for is reported like any other.
#[test]
fn test_client_interim_responses_reported_when_on_skipped_when_off() {
    let response = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </b>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let request = Request::get("/").header("host", "a");
    let bytes: Vec<&[u8]> = response.chunks(1).collect();

    let on = drive_client_opts(&request, &[response], Limits::new(), INFORMATIONAL);
    assert_eq!(
        on,
        drive_client_opts(&request, &bytes, Limits::new(), INFORMATIONAL)
    );
    let statuses: Vec<u16> = on
        .iter()
        .filter_map(|e| match e {
            Ev::Informational { status, .. } => Some(*status),
            _ => None,
        })
        .collect();
    assert_eq!(statuses, [100, 103, 103]);
    assert!(on.contains(&Ev::Informational {
        status: 103,
        headers: vec![("Link".into(), b"</b>".to_vec())],
    }));
    assert!(on.contains(&Ev::Body(b"ok".to_vec())));

    let off = drive_client_opts(&request, &[response], Limits::new(), Opts::default());
    assert!(!off.iter().any(|e| matches!(e, Ev::Informational { .. })));
    assert!(off.contains(&Ev::Body(b"ok".to_vec())));
}

/// E-135 with reporting on: the count budget holds whether interim
/// responses are reported or skipped.
#[test]
fn test_client_interim_over_count_with_report_on_is_too_many_interim() {
    let one = b"HTTP/1.1 103 Early Hints\r\n\r\n";
    let request = Request::get("/").header("host", "a");
    let limits = Limits::new().with_max_interim(3);
    let mut at = one.repeat(3);
    at.extend_from_slice(b"HTTP/1.1 204 No Content\r\n\r\n");
    let events = drive_client_opts(&request, &[&at], limits, INFORMATIONAL);
    assert!(events.contains(&Ev::End), "{events:?}");
    let mut over = one.repeat(4);
    over.extend_from_slice(b"HTTP/1.1 204 No Content\r\n\r\n");
    for opts in [INFORMATIONAL, Opts::default()] {
        let events = drive_client_opts(&request, &[&over], limits, opts);
        assert_eq!(events.last(), Some(&Ev::Err(HttpError::TooManyInterim)));
    }
}

/// The `ResponseHead` of an interim response says so.
#[test]
fn test_client_informational_head_is_informational() {
    let mut conn = ClientConn::new();
    conn.set_report_informational(true);
    conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())
        .unwrap();
    let _ =
        conn.feed(b"HTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let ClientEvent::Informational(r) = conn.poll().unwrap() else {
        panic!()
    };
    assert!(r.is_informational());
    assert!(
        conn.response().is_none(),
        "an interim head is not the response"
    );
    let ClientEvent::Response(r) = conn.poll().unwrap() else {
        panic!()
    };
    assert!(!r.is_informational());
}

fn upload() -> Request {
    Request::put("/f")
        .header("host", "a")
        .content_length(4)
        .expect_continue()
}

/// FR-40: `100` first, then the body, then the final response; the
/// connection is reusable after.
#[test]
fn test_client_expect_continue_then_body_then_final() {
    let mut conn = ClientConn::new();
    let mut out = Vec::new();
    conn.send_request(&upload(), &mut out).unwrap();
    assert!(out.ends_with(b"expect: 100-continue\r\ncontent-length: 4\r\n\r\n"));
    assert!(conn.is_waiting_for_continue());
    assert!(matches!(conn.poll().unwrap(), ClientEvent::NeedInput));
    let _ = conn.feed(b"HTTP/1.1 100 Continue\r\n\r\n");
    assert!(matches!(conn.poll().unwrap(), ClientEvent::Continue));
    assert!(!conn.is_waiting_for_continue());
    conn.send_body(b"data", &mut out).unwrap();
    conn.end_body(&mut out).unwrap();
    assert!(out.ends_with(b"\r\n\r\ndata"));
    let _ = conn.feed(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n");
    assert!(matches!(conn.poll().unwrap(), ClientEvent::Response(r) if r.status() == 201));
    assert!(matches!(conn.poll().unwrap(), ClientEvent::ResponseEnd));
    assert!(matches!(conn.poll().unwrap(), ClientEvent::Idle));
    assert!(conn.is_reusable());
}

/// FR-40: the caller may send the body without waiting for `100`; a `100`
/// that arrives afterwards is then an ordinary interim response.
#[test]
fn test_client_expect_continue_body_without_waiting() {
    let mut conn = ClientConn::new();
    let mut out = Vec::new();
    conn.send_request(&upload(), &mut out).unwrap();
    conn.send_body(b"da", &mut out).unwrap();
    assert!(!conn.is_waiting_for_continue());
    conn.send_body(b"ta", &mut out).unwrap();
    conn.end_body(&mut out).unwrap();
    let _ = conn.feed(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n");
    assert!(matches!(conn.poll().unwrap(), ClientEvent::Response(r) if r.status() == 204));
    assert!(matches!(conn.poll().unwrap(), ClientEvent::ResponseEnd));
    assert!(matches!(conn.poll().unwrap(), ClientEvent::Idle));
}

/// E-136: a final status instead of `100` means the body must not be sent;
/// the promised body is never finished, so the connection closes.
#[test]
fn test_client_expect_continue_final_status_refuses_the_body() {
    let mut conn = ClientConn::new();
    let mut out = Vec::new();
    conn.send_request(&upload(), &mut out).unwrap();
    let _ = conn.feed(b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n");
    assert!(matches!(conn.poll().unwrap(), ClientEvent::Response(r) if r.status() == 417));
    assert!(!conn.is_waiting_for_continue());
    let before = out.len();
    assert!(matches!(
        conn.send_body(b"data", &mut out),
        Err(HttpError::InvalidState(_))
    ));
    assert!(matches!(
        conn.end_body(&mut out),
        Err(HttpError::InvalidState(_))
    ));
    assert!(matches!(
        conn.end_body_with_trailers(&[("x", b"1")], &mut out),
        Err(HttpError::InvalidState(_))
    ));
    assert_eq!(out.len(), before);
    assert!(matches!(conn.poll().unwrap(), ClientEvent::ResponseEnd));
    assert!(!conn.is_reusable());
    assert!(matches!(conn.poll().unwrap(), ClientEvent::Closed));
}

/// `expect_continue` needs a streamed body: a full body (empty or not) is
/// refused before anything is written.
#[test]
fn test_client_expect_continue_full_body_is_invalid_state() {
    for request in [
        Request::get("/").header("host", "a").expect_continue(),
        Request::post("/")
            .header("host", "a")
            .body(&b"abc"[..])
            .expect_continue(),
    ] {
        let mut conn = ClientConn::new();
        let mut out = Vec::new();
        assert!(matches!(
            conn.send_request(&request, &mut out),
            Err(HttpError::InvalidState(_))
        ));
        assert!(out.is_empty());
        assert!(conn.is_reusable());
    }
    // Asking twice writes the field once.
    let twice = Request::put("/")
        .header("host", "a")
        .chunked()
        .expect_continue()
        .expect_continue();
    let mut out = Vec::new();
    ClientConn::new().send_request(&twice, &mut out).unwrap();
    assert_eq!(out.windows(6).filter(|w| w == b"expect").count(), 1);
}

/// The server sees the client's expectation and answers it.
#[test]
fn test_expect_continue_round_trip_between_client_and_server() {
    let mut client = ClientConn::new();
    let mut server = ServerConn::new();
    let mut to_server = Vec::new();
    let mut to_client = Vec::new();
    client.send_request(&upload(), &mut to_server).unwrap();
    let _ = server.feed(&to_server);
    to_server.clear();
    let ServerEvent::Request(req) = server.poll().unwrap() else {
        panic!()
    };
    assert!(req.expects_continue());
    server.send_continue(&mut to_client).unwrap();
    let _ = client.feed(&to_client);
    to_client.clear();
    assert!(matches!(client.poll().unwrap(), ClientEvent::Continue));
    client.send_body(b"data", &mut to_server).unwrap();
    client.end_body(&mut to_server).unwrap();
    let _ = server.feed(&to_server);
    assert!(matches!(server.poll().unwrap(), ServerEvent::Body(b"data")));
    assert!(matches!(server.poll().unwrap(), ServerEvent::RequestEnd));
    server.respond(&Response::new(204), &mut to_client).unwrap();
    let _ = client.feed(&to_client);
    assert!(matches!(client.poll().unwrap(), ClientEvent::Response(r) if r.status() == 204));
}

/// E-129: `100 Continue` after a body byte was read is refused.
#[test]
fn test_server_send_continue_after_body_began_is_interim_not_allowed() {
    let mut conn = ServerConn::new();
    let _ = conn
        .feed(b"PUT / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\nab");
    assert!(matches!(conn.poll().unwrap(), ServerEvent::Request(_)));
    assert!(matches!(conn.poll().unwrap(), ServerEvent::Body(b"ab")));
    assert_eq!(
        conn.send_continue(&mut Vec::new()),
        Err(HttpError::InterimNotAllowed)
    );
}
