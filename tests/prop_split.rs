//! Split invariance where the default drivers do not reach, and every
//! budget at its limit and one over at every split.
//!
//! The same bytes must give the same events however they arrive: the
//! lenient client (its obs-fold rewrite holds a byte back at each line end),
//! trailer and interim reporting under tiny budgets, the pipelining client,
//! and the stateless parser against the connection. A budget is exact
//! wherever a read happens to end: on the fast path, on the general path,
//! whole, in two pieces at every offset, and one byte at a time.

mod common;

use common::{Ev, Opts, drive_client, drive_client_opts, drive_server, drive_server_opts, split};
use http_net::{ClientConn, ClientEvent, ClientLeniency, HttpError, Limits, Request};
use proptest::prelude::*;

const RESP_DICT: &[&[u8]] = &[
    b"HTTP/1.1 200 OK\r\n",
    b"HTTP/1.1 103 Early Hints\r\n",
    b"HTTP/1.1 100 Continue\r\n",
    b"HTTP/1.0 200 OK\r\n",
    b"HTTP/1.1 204\r\n",
    b"Content-Length: 3\r\n",
    b"Content-Length: 0\r\n",
    b"Transfer-Encoding: chunked\r\n",
    b"Connection: close\r\n",
    b"X-A: b\r\n",
    b"X-A: b",
    b"X-F: one\r\n two\r\n",
    b"X-F: one\r\n\ttwo\r\n\r\n",
    b"\r\n3\r\nabc\r\n0\r\nT: v\r\n\r\n",
    b"\r\n",
    b"\r\n ",
    b"\r\n\t",
    b" ",
    b"\t",
    b"\r",
    b"\n",
    b"abc",
    b"3\r\nabc\r\n",
    b"0\r\n",
    b"T: v\r\n",
    b":",
];

fn resp_noise() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(
        prop_oneof![
            6 => proptest::sample::select(RESP_DICT).prop_map(<[u8]>::to_vec),
            1 => proptest::collection::vec(any::<u8>(), 1..4),
        ],
        0..40,
    )
    .prop_map(|p| p.concat())
}

fn small_limits() -> impl Strategy<Value = Limits> {
    (
        16usize..80,
        2usize..120,
        0usize..6,
        4usize..60,
        2usize..60,
        0usize..4,
        0u64..40,
        0u16..4,
    )
        .prop_map(|(line, head, count, field, tb, tf, body, interim)| {
            Limits::new()
                .with_max_start_line(line)
                .with_max_header_bytes(head)
                .with_max_headers(count)
                .with_max_field_line(field)
                .with_max_trailer_bytes(tb)
                .with_max_trailer_fields(tf)
                .with_max_body(body)
                .with_max_interim(interim)
        })
}

/// A client driver with obs-fold leniency (the common driver has none).
fn drive_lenient_client(pieces: &[&[u8]], limits: Limits, head: bool) -> Vec<Ev> {
    let mut conn = ClientConn::with_limits(limits);
    conn.set_leniency(ClientLeniency::new().with_obs_fold_in_responses(true));
    conn.set_report_trailers(true);
    conn.set_report_informational(true);
    let req = if head {
        Request::head("/").header("host", "a")
    } else {
        Request::get("/").header("host", "a")
    };
    conn.send_request(&req, &mut Vec::new()).unwrap();
    let mut events = Vec::new();
    let (mut next, mut pending): (usize, &[u8]) = (0, &[]);
    for _ in 0..1_000_000 {
        match conn.poll() {
            Ok(ClientEvent::Response(r)) => events.push(Ev::Status {
                status: r.status(),
                headers: r
                    .headers()
                    .map(|(n, v)| (n.to_string(), v.to_vec()))
                    .collect(),
                framing: r.framing(),
            }),
            Ok(ClientEvent::Informational(r)) => events.push(Ev::Informational {
                status: r.status(),
                headers: r
                    .headers()
                    .map(|(n, v)| (n.to_string(), v.to_vec()))
                    .collect(),
            }),
            Ok(ClientEvent::Body(b)) => {
                if let Some(Ev::Body(x)) = events.last_mut() {
                    x.extend_from_slice(b);
                } else {
                    events.push(Ev::Body(b.to_vec()));
                }
            }
            Ok(ClientEvent::Trailers(t)) => events.push(Ev::Trailers(
                t.map(|(n, v)| (n.to_string(), v.to_vec())).collect(),
            )),
            Ok(ClientEvent::ResponseEnd) => events.push(Ev::End),
            Ok(ClientEvent::NeedInput | ClientEvent::Idle) => {
                while pending.is_empty() && next < pieces.len() {
                    pending = pieces[next];
                    next += 1;
                }
                if pending.is_empty() {
                    conn.feed_eof();
                    if matches!(events.last(), Some(Ev::Closed)) {
                        return events;
                    }
                    // one more poll after EOF
                    match conn.poll() {
                        Ok(ClientEvent::Closed) | Ok(ClientEvent::Idle) => {
                            events.push(Ev::Closed);
                            return events;
                        }
                        Ok(ClientEvent::ResponseEnd) => {
                            events.push(Ev::End);
                            continue;
                        }
                        Ok(ClientEvent::Body(b)) => {
                            events.push(Ev::Body(b.to_vec()));
                            continue;
                        }
                        Ok(_) => continue,
                        Err(e) => {
                            events.push(Ev::Err(e));
                            return events;
                        }
                    }
                }
                let n = conn.feed(pending);
                assert!(n > 0, "buffer full while waiting");
                pending = &pending[n..];
            }
            Ok(ClientEvent::Upgraded) => {
                events.push(Ev::Upgraded(Vec::new()));
                return events;
            }
            Ok(ClientEvent::Closed) => {
                events.push(Ev::Closed);
                return events;
            }
            Ok(other) => panic!("{other:?}"),
            Err(e) => {
                events.push(Ev::Err(e));
                return events;
            }
        }
    }
    panic!("no end");
}

const REQ_DICT: &[&[u8]] = &[
    b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
    b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n",
    b"PUT / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\n",
    b"3\r\nabc\r\n",
    b"0\r\n",
    b"0\r\nT: v\r\n\r\n",
    b"3\r\nabc\r\n0\r\n\r\n",
    b"1;e=\"q\"\r\nz\r\n",
    b"T: v\r\n",
    b"Trailer-Two: vv\r\n",
    b"\r\n",
    b" ",
    b"\r",
    b"\n",
    b"abc",
];

fn req_noise() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(
        prop_oneof![
            6 => proptest::sample::select(REQ_DICT).prop_map(<[u8]>::to_vec),
            1 => proptest::collection::vec(any::<u8>(), 1..4),
        ],
        0..30,
    )
    .prop_map(|p| p.concat())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// The obs-fold rewrite holds back one byte per line end; the result
    /// must not depend on how the response arrives.
    #[test]
    fn prop_lenient_client_split_invariant(
        input in resp_noise(),
        cuts in proptest::collection::vec(any::<usize>(), 0..12),
        limits in prop_oneof![Just(Limits::new()), small_limits()],
        head in any::<bool>(),
    ) {
        let whole = drive_lenient_client(&[&input], limits, head);
        let pieces = drive_lenient_client(&split(&input, &cuts), limits, head);
        prop_assert_eq!(&whole, &pieces);
        let bytes: Vec<&[u8]> = input.chunks(1).collect();
        prop_assert_eq!(&whole, &drive_lenient_client(&bytes, limits, head));
    }

    /// Server with trailer reporting on, every budget small (field line,
    /// trailer bytes and count included).
    #[test]
    fn prop_server_trailers_tiny_limits_split_invariant(
        input in req_noise(),
        cuts in proptest::collection::vec(any::<usize>(), 0..12),
        limits in small_limits(),
        report in any::<bool>(),
    ) {
        let opts = Opts { report_trailers: report, report_informational: false };
        let whole = drive_server_opts(&[&input], limits, opts);
        prop_assert_eq!(&whole, &drive_server_opts(&split(&input, &cuts), limits, opts));
        let bytes: Vec<&[u8]> = input.chunks(1).collect();
        prop_assert_eq!(&whole, &drive_server_opts(&bytes, limits, opts));
    }

    /// Strict client with trailers and interim reporting on, small budgets.
    #[test]
    fn prop_client_reporting_tiny_limits_split_invariant(
        input in resp_noise(),
        cuts in proptest::collection::vec(any::<usize>(), 0..12),
        limits in small_limits(),
    ) {
        let opts = Opts { report_trailers: true, report_informational: true };
        let req = Request::get("/").header("host", "a");
        let whole = drive_client_opts(&req, &[&input], limits, opts);
        prop_assert_eq!(&whole, &drive_client_opts(&req, &split(&input, &cuts), limits, opts));
    }

    /// Pipelined client (depth 4, three GET/HEAD requests outstanding).
    #[test]
    fn prop_pipelined_client_split_invariant(
        input in resp_noise(),
        cuts in proptest::collection::vec(any::<usize>(), 0..12),
        heads in proptest::collection::vec(any::<bool>(), 3),
    ) {
        let whole = drive_pipelined(&[&input], &heads);
        prop_assert_eq!(&whole, &drive_pipelined(&split(&input, &cuts), &heads));
    }

    /// The stateless parser and the connection agree on every request head.
    #[test]
    fn prop_stateless_parser_matches_connection(
        input in req_noise(),
        limits in prop_oneof![Just(Limits::new()), small_limits()],
    ) {
        let mut slots = [http_net::FieldSpan::default(); 8];
        let stateless = http_net::parse_request_head(&input, &limits, &mut slots);
        let events = drive_server(&[&input], limits);
        match (stateless, events.first()) {
            (Ok(http_net::Parsed::Complete { head, .. }), Some(Ev::Head { target, .. })) => {
                prop_assert_eq!(head.view().target(), target.as_str());
            }
            (Err(e), Some(Ev::Err(f))) => {
                // The connection may refuse with TooManyHeaders where the 8
                // slots run out first; otherwise they must agree.
                if e != HttpError::TooManyHeaders {
                    prop_assert_eq!(e, *f);
                }
            }
            (Ok(http_net::Parsed::Partial), _) => {}
            (Err(HttpError::TooManyHeaders), Some(Ev::Head { .. })) => {}
            (s, c) => prop_assert!(false, "stateless {:?} vs connection {:?}", s.map(|_| ()), c),
        }
    }
}

fn drive_pipelined(pieces: &[&[u8]], heads: &[bool]) -> Vec<Ev> {
    let mut conn = ClientConn::with_limits(Limits::new().with_pipeline_depth(4));
    let mut out = Vec::new();
    for &h in heads {
        let r = if h {
            Request::head("/")
        } else {
            Request::get("/")
        }
        .header("host", "a");
        conn.send_request(&r, &mut out).unwrap();
    }
    let mut events = Vec::new();
    let (mut next, mut pending): (usize, &[u8]) = (0, &[]);
    let mut eof = false;
    for _ in 0..1_000_000 {
        match conn.poll() {
            Ok(ClientEvent::Response(r)) => events.push(Ev::Status {
                status: r.status(),
                headers: vec![],
                framing: r.framing(),
            }),
            Ok(ClientEvent::Body(b)) => {
                if let Some(Ev::Body(x)) = events.last_mut() {
                    x.extend_from_slice(b);
                } else {
                    events.push(Ev::Body(b.to_vec()));
                }
            }
            Ok(ClientEvent::ResponseEnd) => events.push(Ev::End),
            Ok(ClientEvent::NeedInput | ClientEvent::Idle) => {
                while pending.is_empty() && next < pieces.len() {
                    pending = pieces[next];
                    next += 1;
                }
                if pending.is_empty() {
                    if eof {
                        events.push(Ev::Closed);
                        return events;
                    }
                    conn.feed_eof();
                    eof = true;
                    continue;
                }
                let n = conn.feed(pending);
                assert!(n > 0);
                pending = &pending[n..];
            }
            Ok(ClientEvent::Closed) => {
                events.push(Ev::Closed);
                events.push(Ev::Body(vec![conn.outstanding() as u8]));
                return events;
            }
            Ok(other) => {
                events.push(Ev::Upgraded(format!("{other:?}").into_bytes()));
                return events;
            }
            Err(e) => {
                events.push(Ev::Err(e));
                return events;
            }
        }
    }
    panic!("no end");
}

// ---------------------------------------------------------------------------
// Budgets: exactly at the limit accepted, one over refused, at every split
// ---------------------------------------------------------------------------

/// Whole input, every two-piece split, and byte-at-a-time must agree.
fn all_splits_server(input: &[u8], limits: Limits, opts: Opts) -> Vec<Ev> {
    let whole = drive_server_opts(&[input], limits, opts);
    for i in 0..=input.len() {
        let (a, b) = input.split_at(i);
        assert_eq!(
            whole,
            drive_server_opts(&[a, b], limits, opts),
            "split at {i}"
        );
    }
    let bytes: Vec<&[u8]> = input.chunks(1).collect();
    assert_eq!(whole, drive_server_opts(&bytes, limits, opts), "bytewise");
    whole
}

fn first_err(ev: &[Ev]) -> Option<HttpError> {
    ev.iter().find_map(|e| match e {
        Ev::Err(e) => Some(*e),
        _ => None,
    })
}

#[test]
fn test_header_section_budget_edges_every_split() {
    // header section = field lines + final CRLF must fit max_header_bytes.
    let field = b"X: 0123456789\r\n"; // 15 bytes
    for n in [30usize, 31, 32, 33] {
        let limits = Limits::new().with_max_header_bytes(n);
        // Host line 9 bytes + field 15 + final 2 = 26 ... pad the field value
        let pad = n.saturating_sub(26);
        let mut input = b"GET / HTTP/1.1\r\nHost: a\r\nX: 0123456789".to_vec();
        input.extend(std::iter::repeat_n(b'z', pad));
        input.extend_from_slice(b"\r\n\r\n");
        let _ = field;
        let ev = all_splits_server(&input, limits, Opts::default());
        assert_eq!(first_err(&ev), None, "exactly at {n}");
        input.insert(input.len() - 4, b'z');
        let ev = all_splits_server(&input, limits, Opts::default());
        assert_eq!(
            first_err(&ev),
            Some(HttpError::HeadersTooLarge),
            "one over {n}"
        );
    }
}

#[test]
fn test_field_line_budget_edges_every_split() {
    for n in [10usize, 11, 40] {
        let limits = Limits::new().with_max_field_line(n);
        // "X: " + value + CRLF == n
        let mut input = b"GET / HTTP/1.1\r\nHost: a\r\nX: ".to_vec();
        input.extend(std::iter::repeat_n(b'v', n - 5));
        input.extend_from_slice(b"\r\n\r\n");
        let ev = all_splits_server(&input, limits, Opts::default());
        assert_eq!(first_err(&ev), None, "exactly {n}");
        input.insert(input.len() - 4, b'v');
        let ev = all_splits_server(&input, limits, Opts::default());
        assert_eq!(
            first_err(&ev),
            Some(HttpError::FieldLineTooLong),
            "one over {n}"
        );
    }
}

#[test]
fn test_start_line_budget_with_leading_empty_lines_every_split() {
    // The empty lines before the request line count against its budget.
    let line = b"GET / HTTP/1.1\r\n"; // 16
    for skip in [0usize, 1, 3] {
        let limits = Limits::new().with_max_start_line(16 + 2 * skip);
        let mut input = b"\r\n".repeat(skip);
        input.extend_from_slice(line);
        input.extend_from_slice(b"Host: a\r\n\r\n");
        let ev = all_splits_server(&input, limits, Opts::default());
        assert_eq!(first_err(&ev), None);
        let mut over = b"\r\n".to_vec();
        over.extend_from_slice(&input);
        let ev = all_splits_server(&over, limits, Opts::default());
        assert_eq!(first_err(&ev), Some(HttpError::StartLineTooLong));
    }
}

#[test]
fn test_trailer_budget_edges_every_split() {
    let head = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nz\r\n0\r\n";
    for report in [false, true] {
        let opts = Opts {
            report_trailers: report,
            report_informational: false,
        };
        for n in [10usize, 11, 20] {
            let limits = Limits::new().with_max_trailer_bytes(n);
            // "T: " + v + CRLF + final CRLF == n
            let mut input = head.to_vec();
            input.extend_from_slice(b"T: ");
            input.extend(std::iter::repeat_n(b'v', n - 7));
            input.extend_from_slice(b"\r\n\r\n");
            let ev = all_splits_server(&input, limits, opts);
            assert_eq!(first_err(&ev), None, "exactly {n}");
            input.insert(input.len() - 4, b'v');
            let ev = all_splits_server(&input, limits, opts);
            assert_eq!(
                first_err(&ev),
                Some(HttpError::HeadersTooLarge),
                "one over {n}"
            );
        }
    }
}

#[test]
fn test_chunk_extension_budget_every_split() {
    let head = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n";
    // The budget is shared with the head's own field section (39 bytes).
    let limits = Limits::new().with_max_header_bytes(64);
    // ";e=" and 61 bytes are 64 bytes of extension: exactly the budget.
    let mut ok = head.to_vec();
    ok.extend_from_slice(b"1;e=");
    ok.extend(std::iter::repeat_n(b'x', 61));
    ok.extend_from_slice(b"\r\nz\r\n0\r\n\r\n");
    let ev = all_splits_server(&ok, limits, Opts::default());
    assert_eq!(first_err(&ev), None);
    let mut over = head.to_vec();
    over.extend_from_slice(b"1;e=");
    over.extend(std::iter::repeat_n(b'x', 62));
    over.extend_from_slice(b"\r\nz\r\n0\r\n\r\n");
    let ev = all_splits_server(&over, limits, Opts::default());
    assert_eq!(first_err(&ev), Some(HttpError::ChunkExtensionsTooLarge));
}

#[test]
fn test_body_budgets_exact_every_split() {
    let limits = Limits::new().with_max_body(5);
    let ok = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n3\r\ncde\r\n0\r\n\r\n";
    assert_eq!(
        first_err(&all_splits_server(ok, limits, Opts::default())),
        None
    );
    let over = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n4\r\ncdef\r\n0\r\n\r\n";
    assert_eq!(
        first_err(&all_splits_server(over, limits, Opts::default())),
        Some(HttpError::BodyTooLarge)
    );
    let cl_ok = b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nabcde";
    assert_eq!(
        first_err(&all_splits_server(cl_ok, limits, Opts::default())),
        None
    );
    let cl_over = b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\n\r\nabcdef";
    assert_eq!(
        first_err(&all_splits_server(cl_over, limits, Opts::default())),
        Some(HttpError::BodyTooLarge)
    );
}

#[test]
fn test_client_until_close_budget_every_split() {
    let limits = Limits::new().with_max_body(5);
    let req = Request::get("/").header("host", "a");
    for (input, err) in [
        (&b"HTTP/1.1 200 OK\r\n\r\nabcde"[..], None),
        (
            &b"HTTP/1.1 200 OK\r\n\r\nabcdef"[..],
            Some(HttpError::BodyTooLarge),
        ),
    ] {
        let whole = drive_client(&req, &[input], limits);
        for i in 0..=input.len() {
            let (a, b) = input.split_at(i);
            assert_eq!(whole, drive_client(&req, &[a, b], limits), "split {i}");
        }
        assert_eq!(first_err(&whole), err);
    }
}
