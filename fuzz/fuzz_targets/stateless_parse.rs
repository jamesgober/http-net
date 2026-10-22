//! The stateless parsers against the connections, on arbitrary bytes under
//! fuzzer-chosen limits and field-array sizes. Oracles: no panic;
//! `parse_request_head` gives the same refusal (with the same error) or the
//! same head (bytes, spans, every fact) as `ServerConn`, and `Partial`
//! exactly where the connection asks for more input, with the field array
//! large enough; with a smaller array a head that does not fit is
//! `TooManyHeaders`; a head that is accepted copies out and rebuilds through
//! `OwnedRequestHead::from_parts` to the same view; `parse_response_head`
//! agrees with `ClientConn` on final (non-1xx) responses.

#![no_main]

use arbitrary::Arbitrary;
use http_net::{
    Asked, ClientConn, ClientEvent, FieldSpan, HttpError, OwnedRequestHead, Parsed, Request,
    RequestHead, ResponseHead, ServerConn, ServerEvent, parse_request_head, parse_response_head,
};
use http_net_fuzz::{RawLimits, limits_from};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    limits: Option<RawLimits>,
    slots: u8,
    head_request: bool,
    data: Vec<u8>,
}

fn request_facts(r: &RequestHead<'_>) -> String {
    let raw = r.raw();
    format!(
        "{} {} {:?} {:?} {:?} {:?} {:?} {} {} {} {} {:?} {:?} {:?}",
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
    )
}

fn response_facts(r: &ResponseHead<'_>) -> String {
    let raw = r.raw();
    format!(
        "{} {:?} {:?} {:?} {} {:?} {:?} {:?}",
        r.status(),
        r.version(),
        r.framing(),
        r.content_length(),
        r.keep_alive(),
        r.headers().collect::<Vec<_>>(),
        raw.bytes(),
        raw.fields(),
    )
}

fuzz_target!(|input: Input| {
    let limits = limits_from(input.limits);
    let data = &input.data;

    // The connection's reading of the input, fed whole.
    let mut conn = ServerConn::with_limits(limits);
    if conn.feed(data) != data.len() {
        return;
    }
    let server: Result<Option<String>, HttpError> = match conn.poll() {
        Ok(ServerEvent::Request(head)) => {
            // A copied head rebuilds to the same view.
            let (mut bytes, mut fields) = (Vec::new(), Vec::new());
            let facts = head.copy_into(&mut bytes, &mut fields).expect("copy_into");
            let owned = OwnedRequestHead::from_parts(bytes, fields, facts)
                .unwrap_or_else(|e| panic!("a copied head was refused: {e:?}"));
            assert_eq!(request_facts(&owned.view()), request_facts(&head));
            Ok(Some(request_facts(&head)))
        }
        Ok(ServerEvent::NeedInput) => Ok(None),
        Ok(other) => panic!("unexpected first event {other:?}"),
        Err(e) => Err(e),
    };

    // With room for every field, the stateless parse is the same.
    let mut big = vec![FieldSpan::default(); limits.max_headers() + 1];
    let stateless = match parse_request_head(data, &limits, &mut big) {
        Ok(Parsed::Complete { head, len }) => {
            assert_eq!(head.view().raw().bytes(), &data[..len]);
            Ok(Some(request_facts(&head.view())))
        }
        Ok(Parsed::Partial) => Ok(None),
        Ok(_) => unreachable!("unknown outcome"),
        Err(e) => Err(e),
    };
    assert_eq!(stateless, server, "stateless parse differs from ServerConn");

    // With a smaller array, a head that does not fit is TooManyHeaders, and
    // one that fits is unchanged.
    let mut small = vec![FieldSpan::default(); usize::from(input.slots % 8)];
    match parse_request_head(data, &limits, &mut small) {
        Ok(Parsed::Complete { head, .. }) => {
            assert_eq!(Ok(Some(request_facts(&head.view()))), server);
        }
        Ok(Parsed::Partial) => {}
        Ok(_) => unreachable!("unknown outcome"),
        Err(HttpError::TooManyHeaders) => {}
        Err(e) => assert_eq!(Err(e), server),
    }

    // Responses: the same bytes read as a response to GET or HEAD.
    let request = if input.head_request {
        Request::head("/")
    } else {
        Request::get("/")
    };
    let mut client = ClientConn::with_limits(limits);
    if client
        .send_request(&request.header("host", "a"), &mut Vec::new())
        .is_err()
    {
        return;
    }
    if client.feed(data) != data.len() {
        return;
    }
    let client_view = match client.poll() {
        Ok(ClientEvent::Response(head)) => Ok(Some(response_facts(&head))),
        Ok(ClientEvent::NeedInput) => Ok(None),
        Ok(other) => panic!("unexpected first client event {other:?}"),
        Err(e) => Err(e),
    };
    let asked = Asked {
        head: input.head_request,
        connect: false,
    };
    let mut fields = vec![FieldSpan::default(); limits.max_headers() + 1];
    let stateless = match parse_response_head(data, &limits, asked, &mut fields) {
        // The connection skips interim heads (and refuses an unasked 101);
        // the stateless parser returns them. Not comparable.
        Ok(Parsed::Complete { head, .. }) if head.view().status() < 200 => return,
        Ok(Parsed::Complete { head, .. }) => Ok(Some(response_facts(&head.view()))),
        Ok(Parsed::Partial) => Ok(None),
        Ok(_) => unreachable!("unknown outcome"),
        Err(e) => Err(e),
    };
    assert_eq!(stateless, client_view, "stateless response parse differs from ClientConn");
});
