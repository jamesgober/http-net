//! The Tier-3 writer and the standalone chunked decoder against the paths
//! they share code with.
//!
//! - `ServerConn::write_head` (borrowed fields, any `Output`) must write the
//!   same bytes as `respond` for the equivalent `Response`, fail with the
//!   same error, and leave the connection in the same state.
//! - `ChunkedDecoder` must decode exactly what a `ServerConn` decodes from a
//!   chunked request body: the same body, the same trailers, the same error,
//!   the same bytes left over, whatever the split.

use http_net::{
    BodyPlan, ChunkStep, ChunkedDecoder, HttpDate, HttpError, Limits, OutgoingBody, Response,
    ResponseHeadRef, ServerConn, ServerEvent,
};
use proptest::prelude::*;

#[derive(Clone, Debug)]
enum Body {
    /// No body; written to the borrowed head as `Empty` or `Full(0)`.
    None {
        as_full: bool,
    },
    Full(Vec<u8>),
    Length(Vec<u8>),
    Chunked(Vec<Vec<u8>>),
}

fn body() -> impl Strategy<Value = Body> {
    prop_oneof![
        any::<bool>().prop_map(|as_full| Body::None { as_full }),
        proptest::collection::vec(any::<u8>(), 1..64).prop_map(Body::Full),
        proptest::collection::vec(any::<u8>(), 0..64).prop_map(Body::Length),
        proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..16), 0..4)
            .prop_map(Body::Chunked),
    ]
}

/// Field names, valid and not: plain tokens, reserved names, `date`, and a
/// name that is not a token.
fn field_name() -> impl Strategy<Value = String> {
    prop_oneof![
        8 => "[a-z][a-z0-9-]{0,10}",
        1 => Just("date".to_string()),
        1 => prop::sample::select(vec!["content-length", "Connection", "te", "trailer", "bad name"])
            .prop_map(str::to_string),
    ]
}

fn field_value() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        8 => "[!-~]([ -~]{0,20}[!-~])?".prop_map(String::into_bytes),
        1 => Just(Vec::new()),
        1 => prop::sample::select(vec![&b" lead"[..], b"a\r\nInjected: 1", b"nul\x00"])
            .prop_map(<[u8]>::to_vec),
    ]
}

fn request() -> impl Strategy<Value = &'static [u8]> {
    prop::sample::select(vec![
        &b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"[..],
        b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET / HTTP/1.0\r\n\r\n",
        b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\nbody",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\n",
        b"CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: websocket, foo/2\r\n\r\n",
        b"GET / HTTP/1.1\r\n\r\n", // a parse error: one error response allowed
    ])
}

/// A connection fed `request` and polled up to the point of answering:
/// the end of the request, a parse error, or a head whose body is still to
/// come.
fn ready(request: &[u8]) -> ServerConn {
    let mut conn = ServerConn::new();
    let _ = conn.feed(request);
    loop {
        match conn.poll() {
            Ok(ServerEvent::Request(_) | ServerEvent::Body(_)) => {}
            _ => return conn,
        }
    }
}

/// Everything observable after a response: the remaining events, as text.
fn after(conn: &mut ServerConn) -> String {
    let mut log = String::new();
    for _ in 0..8 {
        let e = format!("{:?}", conn.poll());
        let stop = !e.contains("Body") && !e.contains("RequestEnd");
        log.push_str(&e);
        log.push('|');
        if stop {
            break;
        }
    }
    format!("{log}{:?}{}", conn.progress(), conn.requests_served())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn prop_write_head_equals_respond(
        request in request(),
        status in prop::sample::select(vec![99u16, 100, 103, 200, 201, 204, 299, 304, 404, 500, 600]),
        fields in proptest::collection::vec((field_name(), field_value()), 0..5),
        body in body(),
        close in any::<bool>(),
        dated in any::<bool>(),
    ) {
        let date = HttpDate::from_unix_seconds(1_000_000_000);
        let date = dated.then_some(&date);

        let mut response = Response::new(status);
        for (n, v) in &fields {
            response = response.header(n, v);
        }
        response = match &body {
            Body::None { .. } => response,
            Body::Full(b) => response.body(b.clone()),
            Body::Length(b) => response.content_length(b.len() as u64),
            Body::Chunked(_) => response.chunked(),
        };
        if close {
            response = response.close();
        }
        let borrowed: Vec<(&str, &[u8])> = fields.iter().map(|(n, v)| (n.as_str(), v.as_slice())).collect();
        let head = ResponseHeadRef {
            status,
            fields: &borrowed,
            body: match &body {
                Body::None { as_full: false } => OutgoingBody::Empty,
                Body::None { as_full: true } => OutgoingBody::Full(0),
                Body::Full(b) => OutgoingBody::Full(b.len() as u64),
                Body::Length(b) => OutgoingBody::Length(b.len() as u64),
                Body::Chunked(_) => OutgoingBody::Chunked,
            },
            close,
            upgrade: None,
        };

        let (mut a, mut b) = (ready(request), ready(request));
        let (mut out_a, mut out_b) = (Vec::new(), Vec::new());
        let ra = a.respond_into(&response, date, &mut out_a);
        let rb = b.write_head(&head, date, &mut out_b);
        prop_assert_eq!(ra.is_ok(), rb.is_ok(), "{:?} vs {:?}", ra, rb);
        if let (Err(ea), Err(eb)) = (&ra, &rb) {
            prop_assert_eq!(ea, eb);
            prop_assert!(out_b.is_empty());
        }
        if rb == Ok(BodyPlan::Raw) {
            if let Body::Full(bytes) = &body {
                out_b.extend_from_slice(bytes);
            }
        }
        if rb == Ok(BodyPlan::Stream) {
            match &body {
                Body::Length(bytes) => {
                    a.send_body(bytes, &mut out_a).unwrap();
                    b.send_body_into(bytes, &mut out_b).unwrap();
                }
                Body::Chunked(chunks) => {
                    for c in chunks {
                        a.send_body(c, &mut out_a).unwrap();
                        b.send_body_into(c, &mut out_b).unwrap();
                    }
                }
                _ => {}
            }
            prop_assert_eq!(a.end_body(&mut out_a), b.end_body_into(&[], &mut out_b));
        }
        prop_assert_eq!(&out_a, &out_b);
        prop_assert_eq!(after(&mut a), after(&mut b));
    }

    #[test]
    fn prop_write_head_upgrade_equals_switching_protocols(
        request in prop::sample::select(vec![
            &b"GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: websocket, foo/2\r\n\r\n"[..],
            b"GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: h2c\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
        ]),
        protocol in prop::sample::select(vec!["websocket", "WebSocket", "foo", "foo/2", "foo/3", "irc", "h2c", "a b"]),
        fields in proptest::collection::vec((field_name(), field_value()), 0..3),
    ) {
        let mut response = Response::switching_protocols(protocol);
        for (n, v) in &fields {
            response = response.header(n, v);
        }
        let borrowed: Vec<(&str, &[u8])> = fields.iter().map(|(n, v)| (n.as_str(), v.as_slice())).collect();
        let head = ResponseHeadRef {
            status: 101,
            fields: &borrowed,
            body: OutgoingBody::Empty,
            close: false,
            upgrade: Some(protocol),
        };
        let (mut a, mut b) = (ready(request), ready(request));
        let (mut out_a, mut out_b) = (Vec::new(), Vec::new());
        let ra = a.respond_into(&response, None, &mut out_a);
        let rb = b.write_head(&head, None, &mut out_b);
        prop_assert_eq!(ra.err(), rb.err());
        prop_assert_eq!(&out_a, &out_b);
        prop_assert_eq!(a.is_upgraded(), b.is_upgraded());
    }
}

// ---------------------------------------------------------------------------
// ChunkedDecoder against the connection
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
struct Decoded {
    body: Vec<u8>,
    trailer_fields: usize,
    rest: Vec<u8>,
}

const HEAD: &[u8] = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n";

fn by_connection(chunked: &[u8], limits: Limits, cuts: &[usize]) -> Result<Decoded, HttpError> {
    let mut conn = ServerConn::with_limits(limits);
    conn.set_report_trailers(true);
    let mut wire = HEAD.to_vec();
    wire.extend_from_slice(chunked);
    let pieces = split(&wire, cuts);
    let mut next = 0;
    let mut pending: &[u8] = &[];
    let (mut body, mut trailer_fields) = (Vec::new(), 0);
    loop {
        match conn.poll()? {
            ServerEvent::Request(_) => {}
            ServerEvent::Body(b) => body.extend_from_slice(b),
            ServerEvent::Trailers(t) => trailer_fields = t.len(),
            ServerEvent::RequestEnd => {
                let mut rest = conn.remaining_input().to_vec();
                rest.extend_from_slice(pending);
                for p in &pieces[next..] {
                    rest.extend_from_slice(p);
                }
                return Ok(Decoded {
                    body,
                    trailer_fields,
                    rest,
                });
            }
            ServerEvent::NeedInput => {
                while pending.is_empty() && next < pieces.len() {
                    pending = pieces[next];
                    next += 1;
                }
                if pending.is_empty() {
                    conn.feed_eof();
                } else {
                    let n = conn.feed(pending);
                    pending = &pending[n..];
                }
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}

fn by_decoder(chunked: &[u8], limits: Limits, cuts: &[usize]) -> Result<Decoded, HttpError> {
    let mut d = ChunkedDecoder::new(&limits);
    let pieces = split(chunked, cuts);
    let mut next = 0;
    let mut buf: Vec<u8> = Vec::new();
    let (mut body, mut trailer_fields) = (Vec::new(), 0);
    loop {
        let eof = next == pieces.len();
        match d.decode(&buf, eof)? {
            ChunkStep::Data { skip, len } => {
                body.extend_from_slice(&buf[skip..skip + len]);
                let _ = buf.drain(..skip + len);
            }
            ChunkStep::Trailers { skip, len } => {
                let section = &buf[skip..skip + len];
                trailer_fields = section.windows(2).filter(|w| w == b"\r\n").count() - 1;
                let _ = buf.drain(..skip + len);
            }
            ChunkStep::Done { consumed } => {
                let _ = buf.drain(..consumed);
                for p in &pieces[next..] {
                    buf.extend_from_slice(p);
                }
                return Ok(Decoded {
                    body,
                    trailer_fields,
                    rest: buf,
                });
            }
            ChunkStep::NeedMore { consumed } => {
                let _ = buf.drain(..consumed);
                buf.extend_from_slice(pieces[next]);
                next += 1;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}

fn split<'a>(bytes: &'a [u8], cuts: &[usize]) -> Vec<&'a [u8]> {
    let mut points: Vec<usize> = cuts.iter().map(|c| c % (bytes.len() + 1)).collect();
    points.push(0);
    points.push(bytes.len());
    points.sort_unstable();
    points.dedup();
    points.windows(2).map(|w| &bytes[w[0]..w[1]]).collect()
}

/// A chunked body built from parts, valid unless a part is mangled.
fn chunked_body() -> impl Strategy<Value = Vec<u8>> {
    let chunk = (
        proptest::collection::vec(any::<u8>(), 1..24),
        prop::sample::select(vec!["", ";a", ";a=b", " ; q=\"x,y\"", ";\"bad"]),
    );
    (
        proptest::collection::vec(chunk, 0..5),
        prop::sample::select(vec![
            "",
            "T: 1\r\n",
            "A: 1\r\nB: 2\r\n",
            "Bad Name: x\r\n",
            " fold\r\n",
        ]),
        prop::sample::select(vec!["", "GET / HTTP/1.1\r\n"]),
        prop::option::of((any::<prop::sample::Index>(), any::<u8>())),
    )
        .prop_map(|(chunks, trailers, next, mangle)| {
            let mut wire = Vec::new();
            for (data, ext) in chunks {
                wire.extend_from_slice(format!("{:x}{ext}\r\n", data.len()).as_bytes());
                wire.extend_from_slice(&data);
                wire.extend_from_slice(b"\r\n");
            }
            wire.extend_from_slice(b"0\r\n");
            wire.extend_from_slice(trailers.as_bytes());
            wire.extend_from_slice(b"\r\n");
            wire.extend_from_slice(next.as_bytes());
            if let Some((at, byte)) = mangle {
                let i = at.index(wire.len());
                wire[i] = byte;
            }
            wire
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn prop_chunked_decoder_equals_connection(
        chunked in chunked_body(),
        cuts in proptest::collection::vec(any::<usize>(), 0..8),
        small in any::<bool>(),
    ) {
        let limits = if small {
            Limits::new().with_max_body(32).with_max_trailer_fields(1)
        } else {
            Limits::new()
        };
        let a = by_connection(&chunked, limits, &cuts);
        let b = by_decoder(&chunked, limits, &cuts);
        prop_assert_eq!(a, b, "{:?}", String::from_utf8_lossy(&chunked));
    }
}
