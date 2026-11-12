//! The linearity guard (spec section 11.2): a head fed one byte at a time
//! costs time linear in its size. The scanner resumes where its search
//! stopped and the buffer compacts only when full, so 8 times the bytes
//! must cost about 8 times the time; a scanner that re-read the head on
//! each call would cost about 64 times. The test compares sizes within one
//! run (best of nine each, the sizes alternating), so it holds on slow and
//! busy machines alike.

use std::time::{Duration, Instant};

use http_net::{Limits, Response, ServerConn, ServerEvent};

fn head(size: usize) -> Vec<u8> {
    let mut head = b"GET /linear HTTP/1.1\r\nHost: a\r\n".to_vec();
    let mut i = 0;
    while head.len() + 64 < size {
        head.extend_from_slice(format!("X-Field-{i:04}: {:045}\r\n", i).as_bytes());
        i += 1;
    }
    head.extend_from_slice(b"\r\n");
    head
}

fn limits() -> Limits {
    Limits::new()
        .with_max_header_bytes(64 * 1024)
        .with_max_headers(1024)
}

/// Feeds `head` one byte at a time and answers it; returns the elapsed time.
fn byte_at_a_time(conn: &mut ServerConn, head: &[u8]) -> Duration {
    let mut out = Vec::new();
    let started = Instant::now();
    let mut fed = 0;
    loop {
        match conn.poll().expect("a valid head") {
            ServerEvent::NeedInput => fed += conn.feed(&head[fed..=fed]),
            ServerEvent::RequestEnd => {
                out.clear();
                conn.respond(&Response::new(204), &mut out)
                    .expect("respond");
                return started.elapsed();
            }
            _ => {}
        }
    }
}

/// The best of nine runs at each size, the sizes alternating so a burst of
/// load on a shared machine falls on both rather than on one.
fn best_of_nine_interleaved(small: usize, large: usize) -> (Duration, Duration) {
    let (small, large) = (head(small), head(large));
    let mut conn = ServerConn::with_limits(limits());
    let mut best = (Duration::MAX, Duration::MAX);
    for _ in 0..9 {
        best.0 = best.0.min(byte_at_a_time(&mut conn, &small));
        best.1 = best.1.min(byte_at_a_time(&mut conn, &large));
    }
    best
}

#[test]
fn test_byte_at_a_time_cost_grows_linearly_with_the_head() {
    let (small, large) = best_of_nine_interleaved(4 * 1024, 32 * 1024);
    let ratio = large.as_secs_f64() / small.as_secs_f64();
    // Linear is 8x and a rescanning parser 64x. The bound sits between
    // them with room for a loaded machine, where the 32 KiB head loses
    // more of its cache than the 4 KiB one (21x measured at load 70).
    assert!(
        ratio < 32.0,
        "8x the bytes cost {ratio:.1}x the time ({small:?} for 4 KiB, {large:?} for 32 KiB)"
    );
}

#[test]
fn test_byte_at_a_time_parses_what_whole_input_parses() {
    let head = head(16 * 1024);
    let mut whole = ServerConn::with_limits(limits());
    let _ = whole.feed(&head);
    let ServerEvent::Request(expected) = whole.poll().expect("whole") else {
        panic!("no request");
    };
    let expected: Vec<(String, Vec<u8>)> = expected
        .headers()
        .map(|(n, v)| (n.to_string(), v.to_vec()))
        .collect();

    let mut conn = ServerConn::with_limits(limits());
    let mut fed = 0;
    let got = loop {
        match conn.poll().expect("byte at a time") {
            ServerEvent::NeedInput => fed += conn.feed(&head[fed..=fed]),
            ServerEvent::Request(r) => {
                break r
                    .headers()
                    .map(|(n, v)| (n.to_string(), v.to_vec()))
                    .collect::<Vec<_>>();
            }
            other => panic!("unexpected {other:?}"),
        }
    };
    assert_eq!(got, expected);
    assert!(expected.len() > 200);
}

/// `forward_from` on a head whose fields and `Connection` options a client
/// controls is linear: eight times the fields and options cost about eight
/// times the time. Before 0.10 each field re-read every option and every
/// field, so the same growth cost 64 times.
#[test]
fn test_forward_from_is_linear_in_fields_and_connection_options() {
    use http_net::Request;

    let limits = Limits::new()
        .with_max_headers(20_000)
        .with_max_header_bytes(1 << 20)
        .with_max_field_line(64 * 1024);
    // `fields` plain fields and one `Connection` line of `options` distinct
    // options, none of which names a field.
    let head = |fields: usize, options: usize| {
        let mut wire = b"GET / HTTP/1.1\r\nHost: a\r\n".to_vec();
        if options > 0 {
            let list: Vec<String> = (0..options).map(|i| format!("o{i}")).collect();
            wire.extend_from_slice(format!("Connection: {}\r\n", list.join(",")).as_bytes());
        }
        for i in 0..fields {
            wire.extend_from_slice(format!("x{i:05}: v\r\n").as_bytes());
        }
        wire.extend_from_slice(b"\r\n");
        let mut conn = ServerConn::with_limits(limits);
        assert_eq!(conn.feed(&wire), wire.len());
        match conn.poll() {
            Ok(ServerEvent::Request(req)) => req.to_owned(),
            other => panic!("{other:?}"),
        }
    };
    let time = |head: &http_net::OwnedRequestHead| {
        let started = Instant::now();
        for _ in 0..3 {
            let r = Request::forward_from(&head.view());
            assert!(r.header_value("x00000").is_some());
        }
        started.elapsed() / 3
    };
    for (what, small, large) in [
        ("fields", head(1_000, 0), head(8_000, 0)),
        ("fields and options", head(250, 500), head(2_000, 4_000)),
    ] {
        let (mut s, mut l) = (Duration::MAX, Duration::MAX);
        for _ in 0..9 {
            s = s.min(time(&small));
            l = l.min(time(&large));
        }
        eprintln!("forward_from, {what}: {s:?} small, {l:?} 8x");
        // Linear is 8x, the old cost 64x.
        assert!(l < s * 32, "{what}: {s:?} small, {l:?} at 8x");
    }
}
