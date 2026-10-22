//! `ServerConn::respond_head_only` (A-224): the head it writes, plus the
//! body the caller sends after a `Raw` plan, is byte for byte what
//! `respond` writes, and it leaves the connection in the same state.

use http_net::{BodyPlan, HttpError, Response, ServerConn, ServerEvent};
use proptest::prelude::*;

/// A connection that has read `request` to its end.
fn ready(request: &[u8]) -> ServerConn {
    let mut conn = ServerConn::new();
    let _ = conn.feed(request);
    loop {
        match conn.poll() {
            Ok(ServerEvent::RequestEnd) => return conn,
            Ok(ServerEvent::Request(_) | ServerEvent::Body(_)) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
}

/// What the next poll says after the response (the follow-up state).
fn after(conn: &mut ServerConn) -> String {
    let keep_alive = conn.keep_alive();
    format!("{:?} {keep_alive}", conn.poll())
}

fn response(status: u16, body: &[u8], kind: u8) -> Response {
    let r = Response::new(status).header("x-kind", "test");
    match kind {
        0 => r.body(body.to_vec()),
        1 => r.body(body.to_vec()).close(),
        2 => r.chunked(),
        _ => r.content_length(body.len() as u64),
    }
}

const REQUESTS: [&[u8]; 4] = [
    b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
    b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n",
    b"GET / HTTP/1.0\r\n\r\n",
    b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn prop_head_only_plus_body_equals_respond(
        request in 0usize..REQUESTS.len(),
        status in prop::sample::select(vec![200u16, 201, 204, 206, 299, 304, 404, 500, 599]),
        body in prop::collection::vec(any::<u8>(), 0..9000),
        kind in 0u8..4,
    ) {
        let r = response(status, &body, kind);

        let mut whole = ready(REQUESTS[request]);
        let mut expected = Vec::new();
        let full = whole.respond(&r, &mut expected);

        let mut split = ready(REQUESTS[request]);
        let mut got = Vec::new();
        let plan = split.respond_head_only(&r, &mut got);

        match (full, plan) {
            (Ok(()), Ok(plan)) => {
                match plan {
                    BodyPlan::Raw => got.extend_from_slice(r.body_bytes().expect("full body")),
                    BodyPlan::None => prop_assert!(kind <= 1, "None for a streamed body"),
                    BodyPlan::Stream => prop_assert!(kind >= 2, "Stream for a full body"),
                    _ => unreachable!("unknown plan"),
                }
                prop_assert_eq!(&got, &expected);
                if plan != BodyPlan::Stream {
                    prop_assert_eq!(after(&mut split), after(&mut whole));
                }
            }
            (Err(a), Err(b)) => {
                prop_assert_eq!(a, b);
                prop_assert!(got.is_empty(), "bytes written on error");
            }
            (a, b) => prop_assert!(false, "respond {a:?}, head only {b:?}"),
        }
    }
}

#[test]
fn test_head_only_plans() {
    let big = vec![b'x'; 10_000];
    let mut conn = ready(REQUESTS[0]);
    let mut out = Vec::new();
    assert_eq!(
        conn.respond_head_only(&Response::new(200).body(big.clone()), &mut out),
        Ok(BodyPlan::Raw)
    );
    assert!(out.ends_with(b"content-length: 10000\r\n\r\n"));

    // HEAD: the length is announced and nothing follows.
    let mut conn = ready(REQUESTS[1]);
    let mut out = Vec::new();
    assert_eq!(
        conn.respond_head_only(&Response::new(200).body(big.clone()), &mut out),
        Ok(BodyPlan::None)
    );
    assert!(out.ends_with(b"content-length: 10000\r\n\r\n"));

    // Empty body, 204, and a streamed body.
    for (r, plan) in [
        (Response::new(200), BodyPlan::None),
        (Response::new(204), BodyPlan::None),
        (Response::new(200).chunked(), BodyPlan::Stream),
    ] {
        let mut conn = ready(REQUESTS[0]);
        assert_eq!(conn.respond_head_only(&r, &mut Vec::new()), Ok(plan));
    }
}

#[test]
fn test_head_only_errors_write_nothing() {
    // No request yet.
    let mut conn = ServerConn::new();
    let mut out = Vec::new();
    assert!(matches!(
        conn.respond_head_only(&Response::new(200), &mut out),
        Err(HttpError::InvalidState(_))
    ));
    assert!(out.is_empty());

    // A body on a 204, and a second response.
    let mut conn = ready(REQUESTS[0]);
    assert_eq!(
        conn.respond_head_only(&Response::new(204).body(&b"x"[..]), &mut out),
        Err(HttpError::BodyNotAllowed)
    );
    assert!(out.is_empty());
    assert_eq!(
        conn.respond_head_only(&Response::new(200), &mut out),
        Ok(BodyPlan::None)
    );
    let len = out.len();
    assert!(matches!(
        conn.respond_head_only(&Response::new(200), &mut out),
        Err(HttpError::InvalidState(_))
    ));
    assert_eq!(out.len(), len);
}
