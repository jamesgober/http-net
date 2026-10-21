//! Shared pieces of the fuzz targets: drivers that run a connection over
//! input split into pieces and record what it reports, and the independent
//! reference parser used by `reference_diff` and `chunk_line`.
//!
//! The drivers check the connection's invariants as they go and panic on a
//! violation, which libFuzzer reports as a crash:
//!
//! - the connection never asks for input while its buffer is full;
//! - the buffered input never exceeds the buffer capacity;
//! - after a parse error, `poll` reports only `Closed`, whatever is fed;
//! - after a server-side parse error exactly one response can be sent.

// Shared with the integration tests, so both differential checks use one
// reference.
#[path = "../../tests/common/reference.rs"]
pub mod reference;

use http_net::{
    BodyFraming, ClientConn, ClientEvent, HttpError, Limits, Request, Response, ServerConn,
    ServerEvent, Version,
};

/// Upper bound on driver steps, so a bug that loops is reported as a crash
/// rather than a timeout.
const MAX_STEPS: usize = 1_000_000;

/// What a connection reported, with body runs merged so the record does not
/// depend on where the input was split.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ev {
    Head {
        method: String,
        target: String,
        version: Version,
        headers: Vec<(String, Vec<u8>)>,
        framing: BodyFraming,
        keep_alive: bool,
        upgrade: bool,
    },
    Status {
        status: u16,
        headers: Vec<(String, Vec<u8>)>,
        framing: BodyFraming,
    },
    Body(Vec<u8>),
    End,
    Upgraded(Vec<u8>),
    Closed,
    Err(HttpError),
}

fn push_body(events: &mut Vec<Ev>, chunk: &[u8]) {
    if let Some(Ev::Body(b)) = events.last_mut() {
        b.extend_from_slice(chunk);
    } else {
        events.push(Ev::Body(chunk.to_vec()));
    }
}

/// Splits `input` at the given cut points (taken modulo the length).
pub fn split<'a>(input: &'a [u8], cuts: &[u16]) -> Vec<&'a [u8]> {
    if input.is_empty() {
        return vec![input];
    }
    let mut points: Vec<usize> = cuts.iter().map(|&c| usize::from(c) % input.len()).collect();
    points.sort_unstable();
    points.dedup();
    let mut pieces = Vec::new();
    let mut last = 0;
    for p in points {
        pieces.push(&input[last..p]);
        last = p;
    }
    pieces.push(&input[last..]);
    pieces
}

/// Limits from four fuzzer-chosen numbers; `None` keeps the defaults.
pub fn limits_from(raw: Option<(u16, u16, u8, u16)>) -> Limits {
    match raw {
        None => Limits::new(),
        Some((line, headers, count, body)) => Limits::new()
            .with_max_start_line(usize::from(line))
            .with_max_header_bytes(usize::from(headers))
            .with_max_headers(usize::from(count))
            .with_max_body(u64::from(body)),
    }
}

/// The first protocol an upgrade request offers, skipping `h2c`, so the
/// driver answers with a protocol the client asked for.
fn offered_protocol(upgrade: Option<&[u8]>) -> Option<String> {
    let value = upgrade?;
    value
        .split(|&b| b == b',')
        .map(|e| {
            let s = std::str::from_utf8(e).unwrap_or("");
            s.trim_matches(|c| c == ' ' || c == '\t').to_string()
        })
        .find(|p| !p.is_empty() && !p.eq_ignore_ascii_case("h2c"))
}

/// Answers the current request: 101 for an upgrade (with the first
/// offered protocol), otherwise an empty 200. Falls back to 200 when the
/// 101 is refused, which must then succeed.
fn answer(conn: &mut ServerConn, protocol: Option<&str>, out: &mut Vec<u8>) {
    if let Some(p) = protocol {
        if conn.respond(&Response::switching_protocols(p), out).is_ok() {
            return;
        }
    }
    if let Err(e) = conn.respond(&Response::new(200), out) {
        panic!("a 200 to a complete request was refused: {e:?}");
    }
}

/// Checks the server's behaviour after a parse error: one response may be
/// sent, a second is refused, and nothing but `Closed` is reported again,
/// even when more bytes arrive.
fn check_server_after_error(conn: &mut ServerConn, rest: &[&[u8]]) {
    let mut out = Vec::new();
    assert!(
        conn.respond(&Response::new(400), &mut out).is_ok(),
        "the one error response was refused"
    );
    assert!(
        conn.respond(&Response::new(400), &mut out).is_err(),
        "a second response after an error was accepted"
    );
    for piece in rest {
        let _ = conn.feed(piece);
        assert!(
            matches!(conn.poll(), Ok(ServerEvent::Closed)),
            "a failed connection reported something other than Closed"
        );
    }
    assert!(matches!(conn.poll(), Ok(ServerEvent::Closed)));
}

/// Feeds `pieces` to a server connection, answering every request, then
/// signals EOF. Returns the events.
pub fn drive_server(pieces: &[&[u8]], limits: Limits) -> Vec<Ev> {
    let cap = limits.buffer_capacity();
    let mut conn = ServerConn::with_limits(limits);
    let mut out = Vec::new();
    let mut events = Vec::new();
    let mut next = 0;
    let mut pending: &[u8] = &[];
    let mut eof = false;
    let mut protocol: Option<String> = None;
    for _ in 0..MAX_STEPS {
        match conn.poll() {
            Ok(ServerEvent::Request(r)) => {
                protocol = if r.is_upgrade() {
                    offered_protocol(r.header("upgrade"))
                } else {
                    None
                };
                events.push(Ev::Head {
                    method: r.method_str().to_string(),
                    target: r.target().to_string(),
                    version: r.version(),
                    headers: r
                        .headers()
                        .map(|(n, v)| (n.to_string(), v.to_vec()))
                        .collect(),
                    framing: r.framing(),
                    keep_alive: r.keep_alive(),
                    upgrade: r.is_upgrade(),
                });
            }
            Ok(ServerEvent::Body(b)) => push_body(&mut events, b),
            Ok(ServerEvent::RequestEnd) => {
                events.push(Ev::End);
                out.clear();
                answer(&mut conn, protocol.as_deref(), &mut out);
            }
            Ok(ServerEvent::NeedInput) => {
                assert!(!eof, "NeedInput after EOF");
                assert!(
                    conn.remaining_input().len() <= cap,
                    "buffer over its capacity"
                );
                while pending.is_empty() && next < pieces.len() {
                    pending = pieces[next];
                    next += 1;
                }
                if pending.is_empty() {
                    conn.feed_eof();
                    eof = true;
                } else {
                    let n = conn.feed(pending);
                    assert!(n > 0, "buffer full while the parser waits for input");
                    pending = &pending[n..];
                }
            }
            Ok(ServerEvent::AwaitingResponse) => panic!("the driver always responds"),
            Ok(ServerEvent::Upgraded) => {
                let mut rest = conn.remaining_input().to_vec();
                rest.extend_from_slice(pending);
                for p in &pieces[next..] {
                    rest.extend_from_slice(p);
                }
                events.push(Ev::Upgraded(rest));
                return events;
            }
            Ok(ServerEvent::Closed) => {
                events.push(Ev::Closed);
                return events;
            }
            Ok(other) => panic!("unknown event {other:?}"),
            Err(e) => {
                events.push(Ev::Err(e));
                let mut rest = vec![pending];
                rest.extend_from_slice(&pieces[next..]);
                check_server_after_error(&mut conn, &rest);
                return events;
            }
        }
    }
    panic!("server driver did not terminate");
}

/// Sends `request` on a client connection, feeds `pieces` as the response,
/// then EOF. Returns the events.
pub fn drive_client(request: &Request, pieces: &[&[u8]], limits: Limits) -> Vec<Ev> {
    let cap = limits.buffer_capacity();
    let mut conn = ClientConn::with_limits(limits);
    let mut out = Vec::new();
    if let Err(e) = conn.send_request(request, &mut out) {
        panic!("a valid request was refused: {e:?}");
    }
    let mut events = Vec::new();
    let mut next = 0;
    let mut pending: &[u8] = &[];
    let mut eof = false;
    for _ in 0..MAX_STEPS {
        match conn.poll() {
            Ok(ClientEvent::Response(r)) => events.push(Ev::Status {
                status: r.status(),
                headers: r
                    .headers()
                    .map(|(n, v)| (n.to_string(), v.to_vec()))
                    .collect(),
                framing: r.framing(),
            }),
            Ok(ClientEvent::Body(b)) => push_body(&mut events, b),
            Ok(ClientEvent::ResponseEnd) => events.push(Ev::End),
            Ok(ClientEvent::NeedInput) => {
                assert!(!eof, "NeedInput after EOF");
                assert!(
                    conn.remaining_input().len() <= cap,
                    "buffer over its capacity"
                );
                while pending.is_empty() && next < pieces.len() {
                    pending = pieces[next];
                    next += 1;
                }
                if pending.is_empty() {
                    conn.feed_eof();
                    eof = true;
                } else {
                    let n = conn.feed(pending);
                    assert!(n > 0, "buffer full while the parser waits for input");
                    pending = &pending[n..];
                }
            }
            Ok(ClientEvent::Idle) => {
                // Bytes after the response are unsolicited; feed them so the
                // record does not depend on whether they arrived in the same
                // read as the response.
                while pending.is_empty() && next < pieces.len() {
                    pending = pieces[next];
                    next += 1;
                }
                if pending.is_empty() {
                    return events;
                }
                let n = conn.feed(pending);
                assert!(n > 0, "buffer full while idle");
                pending = &pending[n..];
            }
            Ok(ClientEvent::Upgraded) => {
                let mut rest = conn.remaining_input().to_vec();
                rest.extend_from_slice(pending);
                for p in &pieces[next..] {
                    rest.extend_from_slice(p);
                }
                events.push(Ev::Upgraded(rest));
                return events;
            }
            Ok(ClientEvent::Closed) => {
                events.push(Ev::Closed);
                return events;
            }
            Ok(other) => panic!("unknown event {other:?}"),
            Err(e) => {
                events.push(Ev::Err(e));
                for piece in std::iter::once(pending).chain(pieces[next..].iter().copied()) {
                    let _ = conn.feed(piece);
                    assert!(
                        matches!(conn.poll(), Ok(ClientEvent::Closed)),
                        "a failed client connection reported something other than Closed"
                    );
                }
                assert!(matches!(conn.poll(), Ok(ClientEvent::Closed)));
                return events;
            }
        }
    }
    panic!("client driver did not terminate");
}
