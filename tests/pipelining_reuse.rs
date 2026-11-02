//! Client pipelining (FR-42), connection reuse and buffer pooling (FR-48),
//! and wiping of consumed input (FR-59, threat T-36).

use http_net::{
    BodyFraming, ClientConn, ClientEvent, HttpError, Limits, Progress, Request, Response,
    ServerConn, ServerEvent,
};
use proptest::prelude::*;

fn get(path: &str) -> Request {
    Request::get(path).header("host", "a")
}

fn response(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// Feeds `wire` to `conn` in `pieces` and returns the bodies of the
/// responses in the order they completed, plus the final event name.
fn read_responses(conn: &mut ClientConn, wire: &[u8], cuts: &[usize]) -> (Vec<String>, String) {
    let mut bounds: Vec<usize> = cuts.iter().map(|c| c % (wire.len() + 1)).collect();
    bounds.push(0);
    bounds.push(wire.len());
    bounds.sort_unstable();
    bounds.dedup();
    let mut pieces = bounds.windows(2).map(|w| &wire[w[0]..w[1]]);
    let mut bodies = Vec::new();
    let mut current = Vec::new();
    loop {
        match conn.poll() {
            Ok(ClientEvent::Response(_)) => current.clear(),
            Ok(ClientEvent::Body(b)) => current.extend_from_slice(b),
            Ok(ClientEvent::ResponseEnd) => {
                bodies.push(String::from_utf8_lossy(&current).into_owned());
            }
            Ok(ClientEvent::NeedInput) => match pieces.next() {
                Some(p) => assert_eq!(conn.feed(p), p.len()),
                None => return (bodies, "NeedInput".into()),
            },
            Ok(ClientEvent::Idle) => return (bodies, "Idle".into()),
            Ok(ClientEvent::Closed) => return (bodies, "Closed".into()),
            Ok(other) => panic!("unexpected {other:?}"),
            Err(e) => return (bodies, format!("{e:?}")),
        }
    }
}

#[test]
fn test_pipelined_gets_responses_match_requests_in_order() {
    let mut conn = ClientConn::with_limits(Limits::new().with_pipeline_depth(8));
    let mut out = Vec::new();
    for i in 0..8 {
        conn.send_request(&get(&format!("/{i}")), &mut out).unwrap();
        assert_eq!(conn.outstanding(), i + 1);
    }
    assert!(!conn.can_send(), "the depth is full");
    assert!(matches!(
        conn.send_request(&get("/8"), &mut out),
        Err(HttpError::InvalidState(_))
    ));
    let wire: Vec<u8> = (0..8).flat_map(|i| response(&format!("r{i}"))).collect();
    let (bodies, last) = read_responses(&mut conn, &wire, &[]);
    assert_eq!(bodies, (0..8).map(|i| format!("r{i}")).collect::<Vec<_>>());
    assert_eq!(last, "Idle");
    assert_eq!(conn.outstanding(), 0);
}

#[test]
fn test_pipelined_head_response_is_framed_without_a_body() {
    let mut conn = ClientConn::with_limits(Limits::new().with_pipeline_depth(3));
    let mut out = Vec::new();
    conn.send_request(&get("/a"), &mut out).unwrap();
    conn.send_request(&Request::head("/b").header("host", "a"), &mut out)
        .unwrap();
    conn.send_request(&get("/c"), &mut out).unwrap();
    let mut wire = response("one");
    // The HEAD response announces a length but carries no body.
    wire.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n");
    wire.extend_from_slice(&response("three"));
    let (bodies, last) = read_responses(&mut conn, &wire, &[]);
    assert_eq!(bodies, ["one", "", "three"]);
    assert_eq!(last, "Idle");
}

#[test]
fn test_pipelining_refuses_unsafe_requests() {
    let mut out = Vec::new();
    // Depth 1: never pipelines.
    let mut conn = ClientConn::new();
    conn.send_request(&get("/"), &mut out).unwrap();
    assert!(matches!(
        conn.send_request(&get("/2"), &mut out),
        Err(HttpError::InvalidState(_))
    ));

    let limits = Limits::new().with_pipeline_depth(4);
    // A non-idempotent request cannot be pipelined, nor sent behind.
    let mut conn = ClientConn::with_limits(limits);
    conn.send_request(&get("/"), &mut out).unwrap();
    let post = Request::post("/").header("host", "a").body(&b"x"[..]);
    assert!(matches!(
        conn.send_request(&post, &mut out),
        Err(HttpError::InvalidState(_))
    ));
    let mut conn = ClientConn::with_limits(limits);
    conn.send_request(&post, &mut out).unwrap();
    assert!(!conn.can_send());

    // Streamed bodies: nothing goes behind one in progress, and a pipelined
    // request needs a full body.
    let mut conn = ClientConn::with_limits(limits);
    conn.send_request(&Request::put("/").header("host", "a").chunked(), &mut out)
        .unwrap();
    assert!(!conn.can_send());
    conn.end_body(&mut out).unwrap();
    assert!(conn.can_send());
    let streamed = Request::put("/2").header("host", "a").content_length(1);
    assert!(matches!(
        conn.send_request(&streamed, &mut out),
        Err(HttpError::InvalidState(_))
    ));

    // After a request that asked to close, nothing more is sent.
    let mut conn = ClientConn::with_limits(limits);
    conn.send_request(&get("/").close(), &mut out).unwrap();
    assert!(!conn.can_send());

    // An upgrade or CONNECT ends the pipeline.
    let mut conn = ClientConn::with_limits(limits);
    conn.send_request(&get("/ws").upgrade("websocket"), &mut out)
        .unwrap();
    assert!(!conn.can_send());
    let mut conn = ClientConn::with_limits(limits);
    conn.send_request(
        &Request::new("CONNECT", "a:443").header("host", "a:443"),
        &mut out,
    )
    .unwrap();
    assert!(!conn.can_send());
}

#[test]
fn test_pipeline_closed_by_the_server_reports_unanswered_requests() {
    let mut conn = ClientConn::with_limits(Limits::new().with_pipeline_depth(4));
    let mut out = Vec::new();
    for i in 0..4 {
        conn.send_request(&get(&format!("/{i}")), &mut out).unwrap();
    }
    let mut wire = response("first");
    wire.extend_from_slice(
        b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 6\r\n\r\nsecond",
    );
    let (bodies, last) = read_responses(&mut conn, &wire, &[]);
    assert_eq!(bodies, ["first", "second"]);
    assert_eq!(last, "Closed");
    // Two requests never got an answer: retry them elsewhere.
    assert_eq!(conn.outstanding(), 2);
    assert!(!conn.can_send());
}

#[test]
fn test_pipelined_requests_round_trip_through_a_server() {
    // What the pipelining client writes, the server reads as separate
    // requests, in order.
    let mut client = ClientConn::with_limits(Limits::new().with_pipeline_depth(5));
    let mut wire = Vec::new();
    for i in 0..5 {
        client
            .send_request(&get(&format!("/p{i}")), &mut wire)
            .unwrap();
    }
    let mut server = ServerConn::new();
    assert_eq!(server.feed(&wire), wire.len());
    let mut answers = Vec::new();
    let mut targets = Vec::new();
    loop {
        match server.poll().unwrap() {
            ServerEvent::Request(r) => targets.push(r.target().to_string()),
            ServerEvent::RequestEnd => {
                let path = targets.last().cloned().unwrap_or_default();
                server
                    .respond(&Response::text(200, &path), &mut answers)
                    .unwrap();
            }
            ServerEvent::NeedInput => break,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(targets, ["/p0", "/p1", "/p2", "/p3", "/p4"]);
    let (bodies, last) = read_responses(&mut client, &answers, &[]);
    assert_eq!(bodies, ["/p0", "/p1", "/p2", "/p3", "/p4"]);
    assert_eq!(last, "Idle");
}

proptest! {
    /// Responses are matched to pipelined requests in order for any split
    /// of the input and any mix of body framings.
    #[test]
    fn prop_pipelined_responses_match_in_order_for_any_split(
        n in 1usize..12,
        chunked in proptest::collection::vec(any::<bool>(), 12),
        cuts in proptest::collection::vec(any::<usize>(), 0..16),
    ) {
        let mut conn = ClientConn::with_limits(Limits::new().with_pipeline_depth(16));
        let mut out = Vec::new();
        for i in 0..n {
            conn.send_request(&get(&format!("/{i}")), &mut out).unwrap();
        }
        let mut wire = Vec::new();
        for (i, chunk) in chunked.iter().enumerate().take(n) {
            let body = format!("body {i}");
            if *chunk {
                wire.extend_from_slice(
                    format!(
                        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                );
            } else {
                wire.extend_from_slice(&response(&body));
            }
        }
        let (bodies, last) = read_responses(&mut conn, &wire, &cuts);
        prop_assert_eq!(bodies, (0..n).map(|i| format!("body {i}")).collect::<Vec<_>>());
        prop_assert_eq!(last, "Idle");
    }
}

#[test]
fn test_server_reset_reuses_the_object_for_a_new_socket() {
    let mut conn = ServerConn::new();
    let _ = conn.feed(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nab");
    assert!(matches!(conn.poll(), Ok(ServerEvent::Request(_))));
    conn.set_keep_alive(false);
    conn.reset();
    assert_eq!(conn.progress(), Progress::Idle);
    assert!(conn.keep_alive());
    assert_eq!(conn.requests_served(), 0);
    let _ = conn.feed(b"GET /fresh HTTP/1.1\r\nHost: a\r\n\r\n");
    let ServerEvent::Request(r) = conn.poll().unwrap() else {
        panic!("expected a request");
    };
    assert_eq!(r.target(), "/fresh");
    assert_eq!(r.framing(), BodyFraming::None);
}

#[test]
fn test_server_reset_checks_the_http2_preface_again() {
    let mut conn = ServerConn::new();
    let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    assert!(matches!(conn.poll(), Ok(ServerEvent::Request(_))));
    conn.reset();
    let _ = conn.feed(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    assert_eq!(conn.poll().unwrap_err(), HttpError::Http2Preface);
}

#[test]
fn test_server_with_buffer_uses_up_to_the_capacity_and_gives_it_back() {
    let limits = Limits::new()
        .with_max_start_line(1024)
        .with_max_header_bytes(1024);
    let mut conn = ServerConn::with_buffer(Vec::with_capacity(1 << 20), limits);
    // Far more input than the capacity: only the capacity is taken (E-187).
    let big = vec![b'a'; 1 << 20];
    assert_eq!(conn.feed(&big), limits.buffer_capacity());
    let back = conn.into_buffer();
    assert!(back.capacity() >= 1 << 20);
}

#[test]
fn test_shrink_idle_only_frees_an_idle_connection() {
    let mut conn = ServerConn::new();
    assert!(!conn.shrink_idle(), "nothing allocated yet");
    let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\nGET /next");
    assert!(matches!(conn.poll(), Ok(ServerEvent::Request(_))));
    assert!(!conn.shrink_idle(), "E-186: mid-request");
    assert!(matches!(conn.poll(), Ok(ServerEvent::RequestEnd)));
    conn.respond(&Response::new(204), &mut Vec::new()).unwrap();
    assert!(matches!(conn.poll(), Ok(ServerEvent::NeedInput)));
    assert!(!conn.shrink_idle(), "pipelined bytes are buffered");
    let _ = conn.feed(b" HTTP/1.1\r\nHost: a\r\n\r\n");
    assert!(matches!(conn.poll(), Ok(ServerEvent::Request(_))));
    assert!(matches!(conn.poll(), Ok(ServerEvent::RequestEnd)));
    conn.respond(&Response::new(204), &mut Vec::new()).unwrap();
    assert!(matches!(conn.poll(), Ok(ServerEvent::NeedInput)));
    assert!(conn.shrink_idle());
    // The connection keeps working after a shrink.
    let _ = conn.feed(b"GET /after HTTP/1.1\r\nHost: a\r\n\r\n");
    assert!(matches!(conn.poll(), Ok(ServerEvent::Request(r)) if r.target() == "/after"));
}

#[test]
fn test_client_reuse_reset_and_shrink() {
    let mut conn = ClientConn::with_buffer(Vec::with_capacity(4096), Limits::new());
    conn.send_request(&get("/"), &mut Vec::new()).unwrap();
    let _ = conn.feed(&response("ok"));
    let (bodies, last) = read_responses(&mut conn, &[], &[]);
    assert_eq!(bodies, ["ok"]);
    assert_eq!(last, "Idle");
    assert!(conn.shrink_idle());
    conn.send_request(&get("/"), &mut Vec::new()).unwrap();
    assert!(!conn.shrink_idle());
    conn.reset();
    assert_eq!(conn.outstanding(), 0);
    assert!(conn.can_send());
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Threat T-36, E-188: with wiping on, a finished request's bytes are zero
/// once the next request starts, and nothing is left on release.
#[test]
fn test_wipe_zeroes_finished_requests_and_the_released_buffer() {
    let secret = b"session=SECRET-TOKEN-1234";
    let request = format!(
        "POST /login HTTP/1.1\r\nHost: a\r\nCookie: {}\r\nContent-Length: 11\r\n\r\npassword=hi",
        String::from_utf8_lossy(secret)
    );
    let run = |wipe: bool| -> Vec<u8> {
        let mut conn = ServerConn::new();
        conn.set_wipe(wipe);
        let _ = conn.feed(request.as_bytes());
        while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
        conn.respond(&Response::new(204), &mut Vec::new()).unwrap();
        // The next poll releases the finished request.
        assert!(matches!(conn.poll().unwrap(), ServerEvent::NeedInput));
        let _ = conn.feed(b"GET /next HTTP/1.1\r\nHost: a\r\n\r\n");
        assert!(matches!(conn.poll().unwrap(), ServerEvent::Request(_)));
        // Take the storage without wiping it on the way out, to see what
        // the buffer held while the next request was in progress.
        conn.set_wipe(false);
        conn.into_buffer()
    };
    let kept = run(false);
    assert!(
        contains(&kept, secret),
        "control: without wiping the bytes stay"
    );
    let wiped = run(true);
    assert!(!contains(&wiped, secret));
    assert!(!contains(&wiped, b"password=hi"));
    assert!(
        contains(&wiped, b"GET /next"),
        "the request in progress is kept"
    );

    // Released with wiping on: the storage comes back zeroed.
    let mut conn = ServerConn::new();
    conn.set_wipe(true);
    let _ = conn.feed(request.as_bytes());
    assert!(matches!(conn.poll(), Ok(ServerEvent::Request(_))));
    let back = conn.into_buffer();
    assert!(back.iter().all(|&b| b == 0));
}

/// Threat T-36: `reset` with wiping on zeroes the whole buffer, so a
/// request cut off mid-body (the socket closed) leaves no credentials for
/// the next peer of a pooled connection. Wiping is switched off after the
/// reset so the storage is taken as the reset left it; the control run
/// without wiping shows the secret would otherwise stay.
#[test]
fn test_wipe_on_reset_zeroes_a_request_cut_off_mid_body() {
    let secret = b"RESET-SECRET";
    let run = |wipe: bool| -> Vec<u8> {
        let mut conn = ServerConn::new();
        conn.set_wipe(wipe);
        let _ = conn.feed(
            b"POST / HTTP/1.1\r\nHost: a\r\nCookie: session=RESET-SECRET\r\nContent-Length: 10\r\n\r\nab",
        );
        assert!(matches!(conn.poll(), Ok(ServerEvent::Request(_))));
        conn.reset();
        conn.set_wipe(false);
        conn.into_buffer()
    };
    let kept = run(false);
    assert!(
        contains(&kept, secret),
        "control: without wiping, reset keeps the bytes"
    );
    let wiped = run(true);
    assert!(!contains(&wiped, secret));
    assert!(!contains(&wiped, b"Cookie"));
    assert!(wiped.iter().all(|&b| b == 0));
}

/// Compaction moves the unread bytes to the front; with wiping on, the
/// stale copies it leaves behind are zeroed too.
#[test]
fn test_wipe_covers_stale_copies_left_by_compaction() {
    let limits = Limits::new()
        .with_max_start_line(64)
        .with_max_header_bytes(128);
    let secret = "Authorization: Bearer STALE-COPY-SECRET";
    let one = format!("GET /a HTTP/1.1\r\nHost: a\r\n{secret}\r\n\r\n");
    // 600 requests of about 70 bytes wrap the 17 KiB buffer several times,
    // fed in uneven pieces so compaction happens with input pending.
    let wire = one.repeat(600);
    let run = |wipe: bool| -> Vec<u8> {
        let mut conn = ServerConn::with_limits(limits);
        conn.set_wipe(wipe);
        let mut out = Vec::new();
        let mut rest: &[u8] = wire.as_bytes();
        while !rest.is_empty() {
            let piece = &rest[..rest.len().min(997)];
            let n = conn.feed(piece);
            rest = &rest[n..];
            loop {
                match conn.poll().unwrap() {
                    ServerEvent::RequestEnd => {
                        out.clear();
                        conn.respond(&Response::new(204), &mut out).unwrap();
                    }
                    ServerEvent::NeedInput => break,
                    _ => {}
                }
            }
        }
        assert_eq!(conn.requests_served(), 600);
        conn.set_wipe(false);
        conn.into_buffer()
    };
    assert!(
        contains(&run(false), b"STALE-COPY-SECRET"),
        "control: without wiping, old requests stay in the buffer"
    );
    assert!(!contains(&run(true), b"STALE-COPY-SECRET"));
}

/// RFC 9112 section 9.6: once the response being read says the connection
/// ends with it (`Connection: close`, HTTP/1.0 without keep-alive, a body
/// read until close), the client sends no further request on it (fixed in
/// 0.9.1: `can_send` looked only at the requests).
#[test]
fn test_no_pipelining_after_a_response_that_closes() {
    for response in [
        &b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 5\r\n\r\nab"[..],
        b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nab",
        b"HTTP/1.1 200 OK\r\n\r\nab",
    ] {
        let mut conn = ClientConn::with_limits(Limits::new().with_pipeline_depth(4));
        let mut out = Vec::new();
        conn.send_request(&get("/1"), &mut out).unwrap();
        // Before the head arrives, pipelining is allowed.
        assert!(conn.can_send());
        let _ = conn.feed(response);
        assert!(matches!(conn.poll(), Ok(ClientEvent::Response(r)) if !r.keep_alive()));
        assert!(matches!(conn.poll(), Ok(ClientEvent::Body(_))));
        assert!(!conn.can_send(), "{response:?}");
        let before = out.len();
        assert!(matches!(
            conn.send_request(&get("/2"), &mut out),
            Err(HttpError::InvalidState(_))
        ));
        assert_eq!(out.len(), before, "nothing written");
        assert_eq!(conn.outstanding(), 1);
    }
    // The same once the response is complete, before the poll that closes.
    let mut conn = ClientConn::with_limits(Limits::new().with_pipeline_depth(4));
    conn.send_request(&get("/1"), &mut Vec::new()).unwrap();
    let _ = conn.feed(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
    assert!(matches!(conn.poll(), Ok(ClientEvent::Response(_))));
    assert!(matches!(conn.poll(), Ok(ClientEvent::ResponseEnd)));
    assert!(!conn.can_send());
    assert!(matches!(conn.poll(), Ok(ClientEvent::Closed)));
    // A keep-alive response keeps the pipeline open.
    let mut conn = ClientConn::with_limits(Limits::new().with_pipeline_depth(4));
    conn.send_request(&get("/1"), &mut Vec::new()).unwrap();
    let _ = conn.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab");
    assert!(matches!(conn.poll(), Ok(ClientEvent::Response(_))));
    assert!(matches!(conn.poll(), Ok(ClientEvent::Body(_))));
    assert!(conn.can_send());
}
