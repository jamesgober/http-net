//! Property tests for the invariants in `dev/DIRECTIVES.md` section 4.
//!
//! - Round trip: a request serialized by `ClientConn` and parsed by
//!   `ServerConn` (and a response the other way) comes back with the same
//!   method, target, fields, status, and body, however the wire bytes are
//!   split.
//! - Split invariance: for any input, feeding it whole or in arbitrary
//!   pieces produces the same events.
//! - No panics and bounded buffering on arbitrary bytes: the drivers assert
//!   that the parser never asks for input while its buffer is full and
//!   never asks for input after EOF. Arbitrary bytes are fed from the first
//!   byte and also behind a valid head, so they reach the body, chunk, and
//!   trailer states too.
//! - Absolute-form targets round-trip with `host()` naming their
//!   authority, and keep-alive intent survives serialization.

mod common;

use common::{Ev, drive_client, drive_server, split};
use http_net::{BodyFraming, ClientConn, Limits, Request, Response, ServerConn, ServerEvent};
use proptest::prelude::*;

const RESERVED: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
];

fn token() -> impl Strategy<Value = String> {
    "[A-Za-z0-9!#$%&'*+.^_`|~-]{1,12}"
}

fn field_name() -> impl Strategy<Value = String> {
    token().prop_filter("reserved", |n| {
        !RESERVED.iter().any(|r| r.eq_ignore_ascii_case(n))
    })
}

fn field_value() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        Just(Vec::new()),
        "[!-~]([ -~\t]{0,20}[!-~])?".prop_map(String::into_bytes),
        proptest::collection::vec(0x80u8..=0xff, 1..8),
    ]
}

fn target() -> impl Strategy<Value = String> {
    (
        "/[A-Za-z0-9._~!$&'()*+,;=:@/-]{0,30}",
        proptest::option::of("[A-Za-z0-9=&%/?]{0,20}"),
    )
        .prop_map(|(path, query)| match query {
            Some(q) => format!("{path}?{}", q.replace('%', "%25")),
            None => path,
        })
}

fn method() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("GET".to_string()),
        Just("POST".to_string()),
        Just("PUT".to_string()),
        Just("DELETE".to_string()),
        Just("PATCH".to_string()),
        token().prop_filter("special", |m| m != "HEAD" && m != "CONNECT"),
    ]
}

#[derive(Clone, Debug)]
enum BodyMode {
    Full,
    Chunked(Vec<usize>),
    Length(Vec<usize>),
}

fn body_mode() -> impl Strategy<Value = BodyMode> {
    prop_oneof![
        Just(BodyMode::Full),
        proptest::collection::vec(0usize..64, 0..6).prop_map(BodyMode::Chunked),
        proptest::collection::vec(0usize..64, 0..6).prop_map(BodyMode::Length),
    ]
}

/// Splits `body` at `cuts` into the pieces a streaming sender would send.
fn pieces<'a>(body: &'a [u8], cuts: &[usize]) -> Vec<&'a [u8]> {
    split(body, cuts)
}

fn user_headers(headers: &[(String, Vec<u8>)]) -> Vec<(String, Vec<u8>)> {
    headers
        .iter()
        .filter(|(n, _)| !RESERVED.iter().any(|r| r.eq_ignore_ascii_case(n)))
        .cloned()
        .collect()
}

fn body_of(events: &[Ev]) -> Vec<u8> {
    events
        .iter()
        .filter_map(|e| match e {
            Ev::Body(b) => Some(b.clone()),
            _ => None,
        })
        .flatten()
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn prop_request_round_trip(
        method in method(),
        target in target(),
        headers in proptest::collection::vec((field_name(), field_value()), 0..8),
        body in proptest::collection::vec(any::<u8>(), 0..300),
        mode in body_mode(),
        cuts in proptest::collection::vec(any::<usize>(), 0..12),
    ) {
        let mut request = Request::new(&method, &target).header("host", "example.test");
        for (n, v) in &headers {
            request = request.header(n, v);
        }
        let request = match &mode {
            BodyMode::Full => request.body(body.clone()),
            BodyMode::Chunked(_) => request.chunked(),
            BodyMode::Length(_) => request.content_length(body.len() as u64),
        };
        let mut client = ClientConn::new();
        let mut wire = Vec::new();
        client.send_request(&request, &mut wire).unwrap();
        match &mode {
            BodyMode::Full => {}
            BodyMode::Chunked(c) | BodyMode::Length(c) => {
                for piece in pieces(&body, c) {
                    client.send_body(piece, &mut wire).unwrap();
                }
                client.end_body(&mut wire).unwrap();
            }
        }

        let events = drive_server(&split(&wire, &cuts), Limits::new());
        let Ev::Head { method: m, target: t, headers: h, .. } = &events[0] else {
            panic!("expected a request: {events:?}");
        };
        prop_assert_eq!(m, &method);
        prop_assert_eq!(t, &target);
        prop_assert_eq!(user_headers(h), headers.clone());
        prop_assert_eq!(body_of(&events), body.clone());
        prop_assert!(events.contains(&Ev::End));
        prop_assert_eq!(events.last(), Some(&Ev::Closed));
    }

    #[test]
    fn prop_response_round_trip(
        status in prop_oneof![200u16..=203, 205u16..=303, 305u16..=599],
        headers in proptest::collection::vec((field_name(), field_value()), 0..8),
        body in proptest::collection::vec(any::<u8>(), 0..300),
        mode in body_mode(),
        cuts in proptest::collection::vec(any::<usize>(), 0..12),
    ) {
        let mut server = ServerConn::new();
        let _ = server.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        while !matches!(server.poll().unwrap(), ServerEvent::RequestEnd) {}
        let mut response = Response::new(status);
        for (n, v) in &headers {
            response = response.header(n, v);
        }
        let response = match &mode {
            BodyMode::Full => response.body(body.clone()),
            BodyMode::Chunked(_) => response.chunked(),
            BodyMode::Length(_) => response.content_length(body.len() as u64),
        };
        let mut wire = Vec::new();
        server.respond(&response, &mut wire).unwrap();
        match &mode {
            BodyMode::Full => {}
            BodyMode::Chunked(c) | BodyMode::Length(c) => {
                for piece in pieces(&body, c) {
                    server.send_body(piece, &mut wire).unwrap();
                }
                server.end_body(&mut wire).unwrap();
            }
        }

        let request = Request::get("/").header("host", "a");
        let events = drive_client(&request, &split(&wire, &cuts), Limits::new());
        let Ev::Status { status: s, headers: h, framing } = &events[0] else {
            panic!("expected a response: {events:?}");
        };
        prop_assert_eq!(*s, status);
        prop_assert_ne!(*framing, BodyFraming::UntilClose);
        prop_assert_eq!(user_headers(h), headers.clone());
        prop_assert_eq!(body_of(&events), body.clone());
        prop_assert!(events.contains(&Ev::End));
    }
}

/// Fragments that steer random input into deep parser states.
const DICTIONARY: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"CONNECT ",
    b"OPTIONS ",
    b"/",
    b"/a?b=c",
    b"*",
    b"a.b:80",
    b" HTTP/1.1",
    b" HTTP/1.0",
    b" HTTP/2.0",
    b"\r\n",
    b"\r",
    b"\n",
    b" ",
    b"\t",
    b":",
    b"Host: a",
    b"Host:",
    b"Content-Length: ",
    b"Transfer-Encoding: ",
    b"chunked",
    b"gzip",
    b",",
    b";",
    b"=",
    b"\"",
    b"\\",
    b"0",
    b"1",
    b"5",
    b"a",
    b"f",
    b"ff",
    b"10000000000000000",
    b"Connection: close",
    b"Connection: upgrade",
    b"Upgrade: x",
    b"\x00",
    b"\x7f",
    b"\xff",
    b"HTTP/1.1 ",
    b"200 OK",
    b"101 Switching",
    b"204",
    b"100 Continue",
];

fn dictionary_input() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(
        prop_oneof![
            4 => proptest::sample::select(DICTIONARY).prop_map(<[u8]>::to_vec),
            1 => proptest::collection::vec(any::<u8>(), 1..4),
        ],
        0..60,
    )
    .prop_map(|parts| parts.concat())
}

fn tiny_limits() -> impl Strategy<Value = Limits> {
    (16usize..200, 2usize..200, 0usize..6, 0u64..64).prop_map(|(line, head, count, body)| {
        Limits::new()
            .with_max_start_line(line)
            .with_max_header_bytes(head)
            .with_max_headers(count)
            .with_max_body(body)
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn prop_server_never_panics_on_arbitrary_bytes(
        input in proptest::collection::vec(any::<u8>(), 0..512),
        cuts in proptest::collection::vec(any::<usize>(), 0..8),
    ) {
        let _ = drive_server(&split(&input, &cuts), Limits::new());
    }

    #[test]
    fn prop_client_never_panics_on_arbitrary_bytes(
        input in proptest::collection::vec(any::<u8>(), 0..512),
        cuts in proptest::collection::vec(any::<usize>(), 0..8),
    ) {
        let _ = drive_client(&Request::get("/").header("host", "a"), &split(&input, &cuts), Limits::new());
    }

    #[test]
    fn prop_server_split_invariant(
        input in dictionary_input(),
        cuts in proptest::collection::vec(any::<usize>(), 0..10),
        limits in tiny_limits(),
    ) {
        let whole = drive_server(&[&input], limits);
        let pieces = drive_server(&split(&input, &cuts), limits);
        prop_assert_eq!(whole, pieces);
    }

    #[test]
    fn prop_client_split_invariant(
        input in dictionary_input(),
        cuts in proptest::collection::vec(any::<usize>(), 0..10),
        limits in tiny_limits(),
        head in any::<bool>(),
    ) {
        let request = if head {
            Request::new("HEAD", "/").header("host", "a").upgrade("x")
        } else {
            Request::get("/").header("host", "a").upgrade("x")
        };
        let whole = drive_client(&request, &[&input], limits);
        let pieces = drive_client(&request, &split(&input, &cuts), limits);
        prop_assert_eq!(whole, pieces);
    }

    #[test]
    fn prop_bytewise_feeding_matches_whole(input in dictionary_input()) {
        let whole = drive_server(&[&input], Limits::new());
        let bytes: Vec<&[u8]> = input.chunks(1).collect();
        prop_assert_eq!(whole, drive_server(&bytes, Limits::new()));
    }
}

#[test]
fn test_hundred_thousand_pipelined_requests() {
    // Scale check for the linear-time claims: 100k pipelined requests in
    // 4 KiB reads, every one answered, none lost or merged.
    let one = b"GET /item HTTP/1.1\r\nHost: a\r\nAccept: */*\r\n\r\n";
    let input: Vec<u8> = one.repeat(100_000);
    let reads: Vec<&[u8]> = input.chunks(4096).collect();
    let events = drive_server(&reads, Limits::new());
    let heads = events
        .iter()
        .filter(|e| matches!(e, Ev::Head { .. }))
        .count();
    assert_eq!(heads, 100_000);
    assert_eq!(events.last(), Some(&Ev::Closed));
}

#[test]
fn test_large_head_fed_one_byte_at_a_time() {
    // A head at the full 16 KiB budget, one byte per read: the scanner
    // resumes where it stopped, so this stays linear.
    let mut input = b"GET / HTTP/1.1\r\nHost: a\r\n".to_vec();
    while input.len() < 16 * 1024 - 64 {
        input.extend_from_slice(b"X-Pad: 0123456789abcdef0123456789abcdef\r\n");
    }
    input.extend_from_slice(b"\r\n");
    let limits = Limits::new().with_max_headers(1000);
    let bytes: Vec<&[u8]> = input.chunks(1).collect();
    let events = drive_server(&bytes, limits);
    assert!(matches!(events[0], Ev::Head { .. }));
}

// ---------------------------------------------------------------------------
// Fuzz-style: arbitrary bytes behind a valid head, so random input reaches
// the body, chunk-line, chunk-data, trailer, and pipelining states that
// arbitrary bytes from the first byte almost never get past the start line
// to exercise.
// ---------------------------------------------------------------------------

const REQUEST_HEADS: &[&[u8]] = &[
    b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 40\r\n\r\n",
    b"POST / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
    b"GET http://a/x?y HTTP/1.1\r\nHost: b\r\n\r\n",
    b"GET /ws HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: x\r\n\r\n",
    b"POST / HTTP/1.0\r\nContent-Length: 5\r\n\r\n",
    b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5;e=\"q\"\r\nhello\r\n",
];

const RESPONSE_HEADS: &[&[u8]] = &[
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n",
    b"HTTP/1.1 200 OK\r\n\r\n",
    b"HTTP/1.0 200 OK\r\n\r\n",
    b"HTTP/1.1 100 Continue\r\n\r\n",
    b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n",
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: x\r\n\r\n",
    b"HTTP/1.1 204 No Content\r\n\r\n",
];

/// Fragments that steer noise into chunked framing and pipelining.
const BODY_DICTIONARY: &[&[u8]] = &[
    b"\r\n",
    b"0",
    b"1",
    b"a",
    b"ff",
    b";",
    b"=",
    b"\"",
    b"x: y",
    b"0\r\n\r\n",
    b"5\r\nhello\r\n",
    b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nz",
    b" ",
    b"\r",
    b"\n",
];

/// Bytes biased towards chunked framing, mixed with arbitrary ones.
fn body_noise() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(
        prop_oneof![
            3 => proptest::sample::select(BODY_DICTIONARY).prop_map(<[u8]>::to_vec),
            1 => proptest::collection::vec(any::<u8>(), 1..16),
        ],
        0..40,
    )
    .prop_map(|parts| parts.concat())
}

fn any_limits() -> impl Strategy<Value = Limits> {
    prop_oneof![Just(Limits::new()), tiny_limits()]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn prop_server_body_states_never_panic_and_are_split_invariant(
        head in proptest::sample::select(REQUEST_HEADS),
        noise in body_noise(),
        cuts in proptest::collection::vec(any::<usize>(), 0..10),
        limits in any_limits(),
    ) {
        let mut input = head.to_vec();
        input.extend_from_slice(&noise);
        let whole = drive_server(&[&input], limits);
        prop_assert_eq!(&whole, &drive_server(&split(&input, &cuts), limits));
    }

    #[test]
    fn prop_client_body_states_never_panic_and_are_split_invariant(
        head in proptest::sample::select(RESPONSE_HEADS),
        noise in body_noise(),
        cuts in proptest::collection::vec(any::<usize>(), 0..10),
        limits in any_limits(),
        upgrade in any::<bool>(),
    ) {
        let request = if upgrade {
            Request::get("/").header("host", "a").upgrade("x")
        } else {
            Request::get("/").header("host", "a")
        };
        let mut input = head.to_vec();
        input.extend_from_slice(&noise);
        let whole = drive_client(&request, &[&input], limits);
        prop_assert_eq!(&whole, &drive_client(&request, &split(&input, &cuts), limits));
    }

    #[test]
    fn prop_absolute_form_round_trip(
        host in "[a-z][a-z0-9-]{0,12}(\\.[a-z]{2,6})?",
        port in proptest::option::of(1u16..),
        path in proptest::option::of("/[A-Za-z0-9._~/-]{0,20}"),
        query in proptest::option::of("[A-Za-z0-9=&]{0,12}"),
        decoy in "[a-z]{1,8}",
    ) {
        // The authority of an absolute-form target is what host() reports,
        // whatever Host says; path() and query() match the origin form.
        let authority = match port {
            Some(p) => format!("{host}:{p}"),
            None => host.clone(),
        };
        let mut target = format!("http://{authority}{}", path.as_deref().unwrap_or(""));
        if let Some(q) = &query {
            target.push('?');
            target.push_str(q);
        }
        let mut wire = Vec::new();
        ClientConn::new()
            .send_request(&Request::get(&target).header("host", &decoy), &mut wire)
            .unwrap();
        let mut server = ServerConn::new();
        prop_assert_eq!(server.feed(&wire), wire.len());
        let ServerEvent::Request(req) = server.poll().unwrap() else {
            panic!("expected a request");
        };
        prop_assert_eq!(req.target(), target.as_str());
        prop_assert_eq!(req.host(), Some(authority.as_str()));
        prop_assert_eq!(req.header("host"), Some(decoy.as_bytes()));
        prop_assert_eq!(req.path(), path.as_deref().unwrap_or("/"));
        prop_assert_eq!(req.query(), query.as_deref());
    }

    #[test]
    fn prop_keep_alive_round_trip(close in any::<bool>(), http10 in any::<bool>()) {
        // What the client asks for is what the server hears, and what the
        // server answers is what the client concludes.
        let request = if close {
            Request::get("/").header("host", "a").close()
        } else {
            Request::get("/").header("host", "a")
        };
        let mut wire = Vec::new();
        ClientConn::new().send_request(&request, &mut wire).unwrap();
        if http10 {
            // The crate's client always speaks HTTP/1.1; check the 1.0 rule
            // with the same request downgraded by hand.
            let text = String::from_utf8(wire).unwrap().replace("HTTP/1.1", "HTTP/1.0");
            wire = text.into_bytes();
        }
        let events = drive_server(&[&wire], Limits::new());
        let Ev::Head { keep_alive, .. } = &events[0] else {
            panic!("expected a request: {events:?}");
        };
        prop_assert_eq!(*keep_alive, !close && !http10);
    }
}
