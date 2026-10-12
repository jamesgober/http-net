//! Drivers shared by the integration tests: run a connection over input
//! split into arbitrary pieces and record what it reports, with body runs
//! merged so the record does not depend on where the input was split.

#![allow(dead_code)]

use http_net::{
    BodyFraming, ClientConn, ClientEvent, HttpError, Limits, Request, Response, ServerConn,
    ServerEvent, Version,
};

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
pub fn split<'a>(input: &'a [u8], cuts: &[usize]) -> Vec<&'a [u8]> {
    if input.is_empty() {
        return vec![input];
    }
    let mut points: Vec<usize> = cuts.iter().map(|c| c % input.len()).collect();
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

/// Feeds `pieces` to a server connection, answering every request with an
/// empty 200 (or 101 for upgrades), then signals EOF. Returns the events.
pub fn drive_server(pieces: &[&[u8]], limits: Limits) -> Vec<Ev> {
    let mut conn = ServerConn::with_limits(limits);
    let mut out = Vec::new();
    let mut events = Vec::new();
    let mut next = 0;
    let mut pending: &[u8] = &[];
    let mut eof = false;
    let mut upgrade_requested = false;
    for _ in 0..10_000_000 {
        match conn.poll() {
            Ok(ServerEvent::Request(r)) => {
                upgrade_requested = r.is_upgrade();
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
                let response = if upgrade_requested {
                    Response::switching_protocols("test")
                } else {
                    Response::new(200)
                };
                conn.respond(&response, &mut out).expect("respond");
            }
            Ok(ServerEvent::NeedInput) => {
                assert!(!eof, "NeedInput after EOF");
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
            Ok(ServerEvent::AwaitingResponse) => panic!("driver always responds"),
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
                return events;
            }
        }
    }
    panic!("driver did not terminate");
}

/// Sends `request` on a client connection, feeds `pieces` as the response,
/// then EOF. Returns the events.
pub fn drive_client(request: &Request, pieces: &[&[u8]], limits: Limits) -> Vec<Ev> {
    let mut conn = ClientConn::with_limits(limits);
    let mut out = Vec::new();
    conn.send_request(request, &mut out).expect("send");
    let mut events = Vec::new();
    let mut next = 0;
    let mut pending: &[u8] = &[];
    let mut eof = false;
    for _ in 0..10_000_000 {
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
                // Bytes still to come after the response are unsolicited;
                // feed them so the record does not depend on whether they
                // arrived in the same read as the response.
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
                // Everything after the switch, buffered or not yet fed, so
                // the record does not depend on where the input was split.
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
                return events;
            }
        }
    }
    panic!("driver did not terminate");
}

/// The first error a server reports for `input` fed whole, if any.
pub fn server_error(input: &[u8]) -> Option<HttpError> {
    drive_server(&[input], Limits::new())
        .into_iter()
        .find_map(|e| match e {
            Ev::Err(e) => Some(e),
            _ => None,
        })
}
