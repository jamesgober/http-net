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
//! - after a server-side parse error exactly one response can be sent;
//! - trailers and interim responses are reported only when asked for;
//! - an interim response to an HTTP/1.1 request is accepted, to an HTTP/1.0
//!   one refused;
//! - with keep-alive switched off, the connection ends after one response;
//! - `requests_served` counts every answered request.

// Shared with the integration tests, so both differential checks use one
// reference.
#[path = "../../tests/common/reference.rs"]
pub mod reference;

use arbitrary::Arbitrary;
use http_net::{
    BodyFraming, ClientConn, ClientEvent, ClientLeniency, HttpError, Limits, Request, Response,
    ServerConn, ServerEvent, Version,
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
    Trailers(Vec<(String, Vec<u8>)>),
    Informational {
        status: u16,
        headers: Vec<(String, Vec<u8>)>,
    },
    Continue,
    End,
    Upgraded(Vec<u8>),
    Closed,
    Err(HttpError),
}

/// What a driver asks the connection for beyond the defaults, chosen by the
/// fuzzer.
#[derive(Arbitrary, Clone, Copy, Debug, Default)]
pub struct Options {
    pub report_trailers: bool,
    pub report_informational: bool,
    /// Server: switch keep-alive off before answering.
    pub keep_alive_off: bool,
    /// Server: send a `103` before each answer.
    pub send_hints: bool,
    /// Client: replace obsolete line folds in response heads.
    pub lenient_folds: bool,
}

/// Fuzzer-chosen budgets; `None` fields keep the defaults.
#[derive(Arbitrary, Clone, Copy, Debug)]
pub struct RawLimits {
    pub line: u16,
    pub headers: u16,
    pub count: u8,
    pub body: u16,
    pub field_line: Option<u16>,
    pub trailer_bytes: Option<u16>,
    pub trailer_fields: Option<u8>,
    pub interim: Option<u8>,
}

fn fields_of<'a>(it: impl Iterator<Item = (&'a str, &'a [u8])>) -> Vec<(String, Vec<u8>)> {
    it.map(|(n, v)| (n.to_string(), v.to_vec())).collect()
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

/// Limits from fuzzer-chosen numbers; `None` keeps the defaults.
pub fn limits_from(raw: Option<RawLimits>) -> Limits {
    let Some(raw) = raw else {
        return Limits::new();
    };
    let mut limits = Limits::new()
        .with_max_start_line(usize::from(raw.line))
        .with_max_header_bytes(usize::from(raw.headers))
        .with_max_headers(usize::from(raw.count))
        .with_max_body(u64::from(raw.body));
    if let Some(n) = raw.field_line {
        limits = limits.with_max_field_line(usize::from(n));
    }
    if let Some(n) = raw.trailer_bytes {
        limits = limits.with_max_trailer_bytes(usize::from(n));
    }
    if let Some(n) = raw.trailer_fields {
        limits = limits.with_max_trailer_fields(usize::from(n));
    }
    if let Some(n) = raw.interim {
        limits = limits.with_max_interim(u16::from(n));
    }
    limits
}

/// The first protocol an upgrade request offers (`h2c` is never offered),
/// so the driver answers with a protocol the client asked for.
fn offered_protocol(r: &http_net::RequestHead<'_>) -> Option<String> {
    r.upgrade_protocols()
        .next()
        .and_then(|p| std::str::from_utf8(p).ok())
        .map(str::to_string)
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
    drive_server_with(pieces, limits, Options::default())
}

/// As [`drive_server`], with fuzzer-chosen options and their oracles.
pub fn drive_server_with(pieces: &[&[u8]], limits: Limits, opts: Options) -> Vec<Ev> {
    let cap = limits.buffer_capacity();
    let mut conn = ServerConn::with_limits(limits);
    conn.set_report_trailers(opts.report_trailers);
    let mut out = Vec::new();
    let mut events = Vec::new();
    let mut next = 0;
    let mut pending: &[u8] = &[];
    let mut eof = false;
    let mut protocol: Option<String> = None;
    let mut version = Version::Http11;
    let mut answered = 0u64;
    for _ in 0..MAX_STEPS {
        // Getters never panic and never claim more than the state allows.
        let _ = conn.progress();
        let _ = conn.keep_alive();
        match conn.poll() {
            Ok(ServerEvent::Request(r)) => {
                protocol = if r.is_upgrade() {
                    offered_protocol(&r)
                } else {
                    None
                };
                version = r.version();
                let _ = (
                    r.has_unknown_expectation(),
                    r.content_length(),
                    r.target_form(),
                );
                assert!(
                    r.upgrade_protocols()
                        .all(|p| !p.eq_ignore_ascii_case(b"h2c") && !p.is_empty()),
                    "h2c or an empty element offered"
                );
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
            Ok(ServerEvent::Trailers(t)) => {
                assert!(opts.report_trailers, "trailers reported without asking");
                assert!(
                    t.clone().next().is_some(),
                    "an empty trailer section was reported"
                );
                events.push(Ev::Trailers(fields_of(t)));
            }
            Ok(ServerEvent::RequestEnd) => {
                events.push(Ev::End);
                out.clear();
                if opts.send_hints {
                    let sent = conn.send_informational(&Response::new(103), &mut out);
                    match version {
                        Version::Http11 => {
                            assert!(sent.is_ok(), "103 to HTTP/1.1 refused: {sent:?}")
                        }
                        _ => assert_eq!(sent, Err(HttpError::InterimNotAllowed)),
                    }
                }
                if opts.keep_alive_off {
                    conn.set_keep_alive(false);
                }
                answer(&mut conn, protocol.as_deref(), &mut out);
                answered += 1;
                assert_eq!(
                    conn.requests_served(),
                    answered,
                    "requests_served miscounted"
                );
                if opts.keep_alive_off {
                    assert!(
                        !conn.keep_alive(),
                        "keep-alive still on after set_keep_alive(false)"
                    );
                }
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
    drive_client_with(request, pieces, limits, Options::default())
}

/// As [`drive_client`], with fuzzer-chosen options and their oracles. A
/// request built with `expect_continue` and a 4-byte streamed body gets its
/// body sent at `Continue`.
pub fn drive_client_with(
    request: &Request,
    pieces: &[&[u8]],
    limits: Limits,
    opts: Options,
) -> Vec<Ev> {
    let cap = limits.buffer_capacity();
    let mut conn = ClientConn::with_limits(limits);
    conn.set_report_trailers(opts.report_trailers);
    conn.set_report_informational(opts.report_informational);
    conn.set_leniency(ClientLeniency::new().with_obs_fold_in_responses(opts.lenient_folds));
    let mut out = Vec::new();
    if let Err(e) = conn.send_request(request, &mut out) {
        panic!("a valid request was refused: {e:?}");
    }
    let mut events = Vec::new();
    let mut next = 0;
    let mut pending: &[u8] = &[];
    let mut eof = false;
    for _ in 0..MAX_STEPS {
        let _ = (
            conn.progress(),
            conn.is_reusable(),
            conn.is_waiting_for_continue(),
        );
        match conn.poll() {
            Ok(ClientEvent::Informational(r)) => {
                assert!(opts.report_informational, "interim reported without asking");
                assert!(r.is_informational() && r.status() != 101);
                events.push(Ev::Informational {
                    status: r.status(),
                    headers: fields_of(r.headers()),
                });
            }
            Ok(ClientEvent::Continue) => {
                events.push(Ev::Continue);
                assert!(!conn.is_waiting_for_continue());
                conn.send_body(b"data", &mut out).expect("body after 100");
                conn.end_body(&mut out).expect("end after 100");
            }
            Ok(ClientEvent::Trailers(t)) => {
                assert!(opts.report_trailers, "trailers reported without asking");
                assert!(
                    t.clone().next().is_some(),
                    "an empty trailer section was reported"
                );
                events.push(Ev::Trailers(fields_of(t)));
            }
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
