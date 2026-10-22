//! The stateless parsers (`parse_request_head`, `parse_response_head`) and
//! the connections run the same scanner and interpretation code; these
//! properties check that they also give the same answer, for arbitrary
//! near-HTTP input: the same refusal with the same error, or the same head
//! (bytes, field spans, every fact), and `Partial` exactly where a
//! connection asks for more input.

use http_net::{
    Asked, ClientConn, ClientEvent, FieldSpan, HttpError, Limits, Parsed, Request, RequestHead,
    ResponseHead, ServerConn, ServerEvent, parse_request_head, parse_response_head,
};
use proptest::prelude::*;

/// Pieces that make near-HTTP requests: valid parts, and the bytes and
/// shapes the parser refuses.
const REQUEST_PIECES: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"OPTIONS ",
    b"CONNECT ",
    b"get ",
    b"/",
    b"/a?b",
    b"*",
    b"http://h/p",
    b"h:443",
    b" HTTP/1.1",
    b" HTTP/1.0",
    b" HTTP/2.0",
    b"\r\n",
    b"\n",
    b"\r",
    b"Host: a\r\n",
    b"Host: :80\r\n",
    b"host: b\r\n",
    b"Content-Length: 5\r\n",
    b"Content-Length: 0\r\n",
    b"Transfer-Encoding: chunked\r\n",
    b"Connection: close\r\n",
    b"Connection: upgrade\r\nUpgrade: websocket\r\n",
    b"Expect: 100-continue\r\n",
    b"X: \"a,b\"\r\n",
    b" folded\r\n",
    b"Bad Name: x\r\n",
    b"X : y\r\n",
    b"\x00",
    b"\xff",
    b":",
    b" ",
];

const RESPONSE_PIECES: &[&[u8]] = &[
    b"HTTP/1.1 200 OK\r\n",
    b"HTTP/1.0 204 No Content\r\n",
    b"HTTP/1.1 304 \r\n",
    b"HTTP/1.1 404\r\n",
    b"HTTP/1.1 600 X\r\n",
    b"HTTP/1.1 20 X\r\n",
    b"HTTP/2.0 200 OK\r\n",
    b"Content-Length: 3\r\n",
    b"Content-Length: 3, 3\r\n",
    b"Transfer-Encoding: chunked\r\n",
    b"Transfer-Encoding: gzip\r\n",
    b"Connection: keep-alive\r\n",
    b"Set-Cookie: a=1\r\n",
    b"\r\n",
    b"\n",
    b"\r",
    b" folded\r\n",
    b"X : y\r\n",
    b"\x7f",
    b" ",
];

fn assemble(pieces: &'static [&'static [u8]]) -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(
        prop_oneof![
            4 => proptest::sample::select(pieces).prop_map(<[u8]>::to_vec),
            1 => proptest::collection::vec(any::<u8>(), 1..4),
        ],
        0..14,
    )
    .prop_map(|parts| parts.concat())
}

/// A request with a valid start, then arbitrary pieces, so most inputs get
/// past the request line.
fn near_request() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![
            Just(b"GET / HTTP/1.1\r\n".to_vec()),
            Just(b"POST /x HTTP/1.1\r\nHost: a\r\n".to_vec()),
            Just(b"\r\nGET / HTTP/1.0\r\n".to_vec()),
            Just(Vec::new()),
        ],
        assemble(REQUEST_PIECES),
        prop_oneof![Just(b"\r\n".to_vec()), Just(Vec::new())],
    )
        .prop_map(|(a, b, c)| [a, b, c].concat())
}

fn near_response() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![Just(b"HTTP/1.1 200 OK\r\n".to_vec()), Just(Vec::new())],
        assemble(RESPONSE_PIECES),
        prop_oneof![Just(b"\r\n".to_vec()), Just(Vec::new())],
    )
        .prop_map(|(a, b, c)| [a, b, c].concat())
}

fn small_limits() -> impl Strategy<Value = Limits> {
    prop_oneof![
        Just(Limits::new()),
        (16usize..64, 2usize..96, 0usize..6, 4usize..40).prop_map(|(line, bytes, count, field)| {
            Limits::new()
                .with_max_start_line(line)
                .with_max_header_bytes(bytes)
                .with_max_headers(count)
                .with_max_field_line(field)
        }),
    ]
}

/// Everything a request view says, for comparison.
fn request_facts(r: &RequestHead<'_>) -> String {
    let raw = r.raw();
    format!(
        "{} {} {:?} {:?} {:?} {:?} {:?} {} {} {} {} {:?} {:?} {:?} {:?}",
        r.method_str(),
        r.target(),
        r.target_form(),
        r.version(),
        r.framing(),
        r.content_length(),
        r.host(),
        r.keep_alive(),
        r.is_upgrade(),
        r.expects_continue(),
        r.has_unknown_expectation(),
        r.headers().collect::<Vec<_>>(),
        raw.bytes(),
        raw.fields(),
        (raw.start_line(), raw.method(), raw.target(), raw.version()),
    )
}

fn response_facts(r: &ResponseHead<'_>) -> String {
    let raw = r.raw();
    format!(
        "{} {} {:?} {:?} {:?} {} {:?} {:?} {:?} {:?}",
        r.status(),
        r.reason(),
        r.version(),
        r.framing(),
        r.content_length(),
        r.keep_alive(),
        r.headers().collect::<Vec<_>>(),
        raw.bytes(),
        raw.fields(),
        (raw.start_line(), raw.version(), raw.status()),
    )
}

/// What the server connection makes of `input`, fed whole.
fn server_outcome(input: &[u8], limits: Limits) -> Result<Option<String>, HttpError> {
    let mut conn = ServerConn::with_limits(limits);
    let taken = conn.feed(input);
    assert_eq!(taken, input.len(), "test inputs fit the buffer");
    match conn.poll()? {
        ServerEvent::Request(head) => Ok(Some(request_facts(&head))),
        ServerEvent::NeedInput => Ok(None),
        other => panic!("unexpected first event {other:?}"),
    }
}

fn stateless_request(input: &[u8], limits: Limits) -> Result<Option<String>, HttpError> {
    let mut fields = [FieldSpan::default(); 64];
    match parse_request_head(input, &limits, &mut fields)? {
        Parsed::Complete { head, len } => {
            assert_eq!(head.view().raw().bytes(), &input[..len]);
            Ok(Some(request_facts(&head.view())))
        }
        Parsed::Partial => Ok(None),
        _ => panic!("unknown outcome"),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8192))]

    #[test]
    fn prop_stateless_request_parse_equals_server_connection(
        input in near_request(),
        limits in small_limits(),
    ) {
        prop_assert_eq!(stateless_request(&input, limits), server_outcome(&input, limits));
    }

    #[test]
    fn prop_stateless_request_parse_equals_server_on_arbitrary_bytes(
        input in proptest::collection::vec(any::<u8>(), 0..200),
    ) {
        prop_assert_eq!(
            stateless_request(&input, Limits::new()),
            server_outcome(&input, Limits::new())
        );
    }

    /// Final (non-1xx) responses: the client connection and the stateless
    /// parser agree. Interim heads are skipped by the connection and
    /// returned by the stateless parser, so they are left out.
    #[test]
    fn prop_stateless_response_parse_equals_client_connection(
        input in near_response(),
        limits in small_limits(),
        head_request in any::<bool>(),
    ) {
        let request = if head_request { Request::head("/") } else { Request::get("/") };
        let mut conn = ClientConn::with_limits(limits);
        conn.send_request(&request.header("host", "a"), &mut Vec::new()).unwrap();
        let _ = conn.feed(&input);
        let client = match conn.poll() {
            Ok(ClientEvent::Response(head)) => Ok(Some(response_facts(&head))),
            Ok(ClientEvent::NeedInput) => Ok(None),
            Ok(other) => panic!("unexpected first event {other:?}"),
            Err(e) => Err(e),
        };
        let mut fields = [FieldSpan::default(); 64];
        let asked = Asked { head: head_request, connect: false };
        let stateless = match parse_response_head(&input, &limits, asked, &mut fields) {
            Ok(Parsed::Complete { head, .. }) if (100..200).contains(&head.view().status()) => {
                return Ok(());
            }
            Ok(Parsed::Complete { head, .. }) => Ok(Some(response_facts(&head.view()))),
            Ok(Parsed::Partial) => Ok(None),
            Ok(_) => panic!("unknown outcome"),
            Err(e) => Err(e),
        };
        prop_assert_eq!(stateless, client);
    }

    /// A head copied out and rebuilt reads the same as the original.
    #[test]
    fn prop_copied_head_rebuilds_the_same_view(input in near_request()) {
        let mut conn = ServerConn::new();
        let _ = conn.feed(&input);
        if let Ok(ServerEvent::Request(head)) = conn.poll() {
            let (mut bytes, mut fields) = (Vec::new(), Vec::new());
            let facts = head.copy_into(&mut bytes, &mut fields).unwrap();
            let owned = http_net::OwnedRequestHead::from_parts(bytes, fields, facts);
            prop_assert!(owned.is_ok(), "{:?}", owned);
            let owned = owned.unwrap();
            prop_assert_eq!(request_facts(&owned.view()), request_facts(&head));
        }
    }
}

#[test]
fn test_stateless_parse_matches_every_rfc_case_split() {
    // A valid head parsed whole and from every prefix: Partial until it is
    // complete, then the same head.
    let input = b"\r\nPOST /notes?x=1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nX: \"q,r\"\r\n\r\nhello";
    let whole = stateless_request(input, Limits::new()).unwrap().unwrap();
    for cut in 0..input.len() {
        let got = stateless_request(&input[..cut], Limits::new()).unwrap();
        let server = server_outcome(&input[..cut], Limits::new()).unwrap();
        assert_eq!(got, server, "cut {cut}");
        if let Some(facts) = got {
            assert_eq!(facts, whole);
        }
    }
}
