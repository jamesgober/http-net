//! Proxy-side helpers and the two connection-start and leniency rules of
//! 0.5: hop-by-hop removal and `Request::forward_from` (FR-47), HTTP/2
//! preface detection (FR-51, T-42), and the opt-in client obs-fold
//! tolerance (FR-60, T-7).

mod common;

use common::{Ev, drive_server};
use http_net::{
    BodyFraming, ClientConn, ClientEvent, ClientLeniency, HttpError, Limits, Request, Response,
    ServerConn, ServerEvent, is_hop_by_hop,
};

/// A response's head fields, or the error, as a client with `lenient`
/// obs-fold tolerance reads `pieces`.
fn client_head(pieces: &[&[u8]], lenient: bool) -> Result<Vec<(String, Vec<u8>)>, HttpError> {
    let mut conn = ClientConn::new();
    conn.set_leniency(ClientLeniency::new().with_obs_fold_in_responses(lenient));
    conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())
        .expect("send");
    let mut next = 0;
    loop {
        match conn.poll()? {
            ClientEvent::Response(r) => {
                return Ok(r
                    .headers()
                    .map(|(n, v)| (n.to_string(), v.to_vec()))
                    .collect());
            }
            ClientEvent::NeedInput => match pieces.get(next) {
                Some(p) => {
                    assert_eq!(conn.feed(p), p.len());
                    next += 1;
                }
                None => conn.feed_eof(),
            },
            other => panic!("unexpected {other:?}"),
        }
    }
}

/// Runs `input` whole and byte by byte; both must agree.
fn client_head_every_split(
    input: &[u8],
    lenient: bool,
) -> Result<Vec<(String, Vec<u8>)>, HttpError> {
    let whole = client_head(&[input], lenient);
    let bytes: Vec<&[u8]> = input.chunks(1).collect();
    assert_eq!(
        whole,
        client_head(&bytes, lenient),
        "split changed the result"
    );
    for cut in 1..input.len() {
        let (a, b) = input.split_at(cut);
        assert_eq!(whole, client_head(&[a, b], lenient), "cut at {cut}");
    }
    whole
}

fn field<'a>(fields: &'a [(String, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    fields
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
}

/// T-7: obs-fold in a response is refused by default and, with the opt-in
/// tolerance, replaced by spaces in place: whole, byte by byte, and at
/// every cut.
#[test]
fn test_obs_fold_in_response_refused_by_default_replaced_when_lenient() {
    let folded =
        b"HTTP/1.1 200 OK\r\nX-Long: one,\r\n two,\r\n\tthree\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(
        client_head_every_split(folded, false),
        Err(HttpError::ObsFold)
    );
    let fields = client_head_every_split(folded, true).expect("lenient");
    // Each fold's CR LF becomes two spaces; the continuation's own leading
    // space or tab stays.
    assert_eq!(field(&fields, "x-long"), Some(&b"one,   two,  \tthree"[..]));
    assert_eq!(field(&fields, "content-length"), Some(&b"0"[..]));
    assert_eq!(fields.len(), 2);
}

/// The tolerance covers folds only: every other refusal stays (T-1, T-5,
/// T-6, T-8), and whitespace before the first field is still refused.
#[test]
fn test_obs_fold_leniency_tolerates_nothing_else() {
    let cases: &[(&[u8], HttpError)] = &[
        (b"HTTP/1.1 200 OK\r\n X: a\r\n\r\n", HttpError::ObsFold),
        (b"HTTP/1.1 200 OK\r\nX: a\nY: b\r\n\r\n", HttpError::BareLf),
        (b"HTTP/1.1 200 OK\r\nX: a\rb\r\n\r\n", HttpError::BareCr),
        (
            b"HTTP/1.1 200 OK\r\nX : a\r\n\r\n",
            HttpError::WhitespaceBeforeColon,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
            HttpError::ConflictingFraming,
        ),
        // A fold cannot hide a second Content-Length line from the check.
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n x\r\nContent-Length: 2\r\n\r\n",
            HttpError::InvalidContentLength,
        ),
    ];
    for &(input, err) in cases {
        assert_eq!(
            client_head_every_split(input, true),
            Err(err),
            "{}",
            String::from_utf8_lossy(input)
        );
    }
}

/// A folded line still counts as one field line against the budgets.
#[test]
fn test_obs_fold_leniency_keeps_the_field_line_budget() {
    let limits = Limits::new().with_max_field_line(16);
    let mut conn = ClientConn::with_limits(limits);
    conn.set_leniency(ClientLeniency::new().with_obs_fold_in_responses(true));
    conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())
        .unwrap();
    let _ = conn.feed(b"HTTP/1.1 200 OK\r\nX: aaaaaa\r\n bbbbbbbb\r\n\r\n");
    assert_eq!(conn.poll().unwrap_err(), HttpError::FieldLineTooLong);
}

/// Requests are never parsed leniently: the server refuses every fold.
#[test]
fn test_server_never_tolerates_obs_fold() {
    let events = drive_server(
        &[b"GET / HTTP/1.1\r\nHost: a\r\nX: a\r\n b\r\n\r\n"],
        Limits::new(),
    );
    assert_eq!(events.last(), Some(&Ev::Err(HttpError::ObsFold)));
}

/// Interim heads are unfolded too, and the next head starts fresh.
#[test]
fn test_obs_fold_leniency_applies_to_each_head() {
    let input = b"HTTP/1.1 103 Early Hints\r\nLink: </a>,\r\n </b>\r\n\r\nHTTP/1.1 200 OK\r\nX: 1\r\n 2\r\nContent-Length: 0\r\n\r\n";
    let fields = client_head_every_split(input, true).expect("lenient");
    assert_eq!(field(&fields, "x"), Some(&b"1   2"[..]));
}

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// T-42, E-18: the HTTP/2 preface at the start of a connection is
/// `Http2Preface` (505), however the bytes arrive, and the connection
/// waits while the input could still be the preface.
#[test]
fn test_h2_preface_at_connection_start_at_every_split() {
    let mut input = PREFACE.to_vec();
    input.extend_from_slice(b"\x00\x00\x12\x04\x00\x00\x00\x00\x00");
    for cut in 0..=input.len() {
        let (a, b) = input.split_at(cut);
        let events = drive_server(&[a, b], Limits::new());
        assert_eq!(
            events.last(),
            Some(&Ev::Err(HttpError::Http2Preface)),
            "cut {cut}"
        );
    }
    assert_eq!(HttpError::Http2Preface.status(), Some(505));
    // Below 24 bytes the connection waits rather than deciding.
    let mut conn = ServerConn::new();
    let _ = conn.feed(&PREFACE[..20]);
    assert!(matches!(conn.poll(), Ok(ServerEvent::NeedInput)));
    // One error response is allowed, then the connection closes.
    let _ = conn.feed(&PREFACE[20..]);
    let err = conn.poll().unwrap_err();
    let mut out = Vec::new();
    conn.respond(&Response::from_error(&err), &mut out).unwrap();
    assert!(out.starts_with(b"HTTP/1.1 505 HTTP Version Not Supported\r\n"));
    assert!(matches!(conn.poll(), Ok(ServerEvent::Closed)));
}

/// The preface is checked only before the first request: later, the same
/// bytes are an ordinary request with an unsupported version.
#[test]
fn test_h2_preface_only_at_connection_start() {
    let mut input = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n".to_vec();
    input.extend_from_slice(PREFACE);
    let events = drive_server(&[&input], Limits::new());
    assert!(
        matches!(events.first(), Some(Ev::Head { .. })),
        "{events:?}"
    );
    assert_eq!(events.last(), Some(&Ev::Err(HttpError::UnsupportedVersion)));
    // A connection that ends inside a preface prefix is a normal EOF case.
    let events = drive_server(&[&PREFACE[..5]], Limits::new());
    assert_eq!(events.last(), Some(&Ev::Err(HttpError::UnexpectedEof)));
    // Empty input still closes cleanly.
    assert_eq!(drive_server(&[], Limits::new()).last(), Some(&Ev::Closed));
}

fn received(input: &[u8]) -> (ServerConn, Request) {
    let mut conn = ServerConn::new();
    let _ = conn.feed(input);
    let request = match conn.poll() {
        Ok(ServerEvent::Request(head)) => Request::forward_from(&head),
        other => panic!("expected a request, got {other:?}"),
    };
    (conn, request)
}

/// FR-47: `forward_from` drops exactly the hop-by-hop fields (the fixed set
/// and the names listed in `Connection`), keeps the rest in order, and keeps
/// the framing mode.
#[test]
fn test_forward_from_drops_exactly_the_hop_by_hop_fields() {
    let input = b"PUT /f HTTP/1.1\r\nHost: up\r\nConnection: keep-alive, X-Hop\r\nKeep-Alive: timeout=5\r\nProxy-Connection: keep-alive\r\nTE: trailers\r\nTrailer: Digest\r\nX-Hop: 1\r\nAccept: */*\r\nX-End: 2\r\nTransfer-Encoding: chunked\r\n\r\n";
    let (_, req) = received(input);
    let mut out = Vec::new();
    ClientConn::new().send_request(&req, &mut out).unwrap();
    assert_eq!(
        out,
        b"PUT /f HTTP/1.1\r\nHost: up\r\nAccept: */*\r\nX-End: 2\r\ntransfer-encoding: chunked\r\n\r\n"
    );
}

/// The body mode follows the head: a length stays that length, no body
/// stays no body; the upstream sees the same framing.
#[test]
fn test_forward_from_round_trips_through_client_and_server() {
    for (input, framing, body) in [
        (
            &b"POST /a?b=1 HTTP/1.1\r\nHost: up\r\nContent-Length: 3\r\n\r\nxyz"[..],
            BodyFraming::Length(3),
            &b"xyz"[..],
        ),
        (
            &b"POST /c HTTP/1.1\r\nHost: up\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nxyz\r\n0\r\n\r\n"[..],
            BodyFraming::Chunked,
            &b"xyz"[..],
        ),
        (&b"GET /d HTTP/1.1\r\nHost: up\r\nCookie: a=1\r\n\r\n"[..], BodyFraming::None, &b""[..]),
        (
            &b"GET http://up/e HTTP/1.1\r\nHost: up\r\n\r\n"[..],
            BodyFraming::None,
            &b""[..],
        ),
    ] {
        let (_, req) = received(input);
        let mut upstream = ClientConn::new();
        let mut wire = Vec::new();
        upstream.send_request(&req, &mut wire).unwrap();
        if framing != BodyFraming::None {
            upstream.send_body(body, &mut wire).unwrap();
            upstream.end_body(&mut wire).unwrap();
        }
        let events = drive_server(&[&wire], Limits::new());
        let original = drive_server(&[input], Limits::new());
        let (Some(Ev::Head { target: t1, headers: h1, framing: f1, .. }), Some(Ev::Head { target: t2, headers: h2, framing: f2, .. })) =
            (events.first(), original.first())
        else {
            panic!("{events:?} {original:?}");
        };
        assert_eq!(t1, t2);
        assert_eq!(f1, f2);
        assert_eq!(*f1, framing);
        let end_to_end = |h: &[(String, Vec<u8>)]| -> Vec<(String, Vec<u8>)> {
            h.iter()
                .filter(|(n, _)| {
                    !n.eq_ignore_ascii_case("content-length")
                        && !n.eq_ignore_ascii_case("transfer-encoding")
                })
                .map(|(n, v)| (n.to_ascii_lowercase(), v.clone()))
                .collect()
        };
        assert_eq!(end_to_end(h1), end_to_end(h2));
        let got: Vec<u8> = events
            .iter()
            .filter_map(|e| if let Ev::Body(b) = e { Some(b.clone()) } else { None })
            .flatten()
            .collect();
        assert_eq!(got, body);
    }
}

/// An upgrade request is hop-by-hop as a whole: `forward_from` refuses it
/// (a proxy tunnels it instead); a missing `Host` surfaces at send.
#[test]
fn test_forward_from_refuses_upgrades_and_reports_builder_errors() {
    let (_, req) = received(
        b"GET /ws HTTP/1.1\r\nHost: up\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
    );
    assert!(matches!(
        ClientConn::new().send_request(&req, &mut Vec::new()),
        Err(HttpError::InvalidState(_))
    ));
    let (_, req) = received(b"GET / HTTP/1.0\r\n\r\n");
    assert_eq!(
        ClientConn::new().send_request(&req, &mut Vec::new()),
        Err(HttpError::MissingHost)
    );
    let (_, req) = received(b"GET / HTTP/1.0\r\n\r\n");
    assert!(
        ClientConn::new()
            .send_request(&req.header("host", "up"), &mut Vec::new())
            .is_ok()
    );
}

/// `is_hop_by_hop` reads the options across every `Connection` line.
#[test]
fn test_is_hop_by_hop_uses_every_connection_line() {
    let mut conn = ServerConn::new();
    let _ =
        conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: a\r\nconnection: B, \"c\"\r\n\r\n");
    let ServerEvent::Request(head) = conn.poll().unwrap() else {
        panic!()
    };
    assert!(is_hop_by_hop("A", head.connection_options()));
    assert!(is_hop_by_hop("b", head.connection_options()));
    assert!(!is_hop_by_hop("d", head.connection_options()));
    assert_eq!(head.connection_options().count(), 3);
}
