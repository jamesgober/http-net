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
    assert!(
        ratio < 16.0,
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
