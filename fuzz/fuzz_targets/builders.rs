//! `Request` and `Response` built from arbitrary methods, targets,
//! statuses, field names, values, and bodies. Oracle: the builder either
//! reports an error, or its output parses back on the other side to the
//! same method, target, status, fields, and body. A builder must never
//! write bytes the crate's own parser refuses.

#![no_main]

use arbitrary::Arbitrary;
use http_net::{ClientConn, ClientEvent, Limits, Request, Response, ServerConn, ServerEvent};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Mode {
    Full,
    Chunked,
    Length,
}

#[derive(Arbitrary, Debug)]
struct Input {
    method: String,
    target: String,
    status: u16,
    fields: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
    mode: Mode,
}

/// Fields the connection writes itself rather than the caller.
fn is_connection_field(name: &str) -> bool {
    ["content-length", "transfer-encoding", "connection"]
        .iter()
        .any(|f| f.eq_ignore_ascii_case(name))
}

/// Budgets large enough for anything the builders accept, so a refusal on
/// the reading side means the bytes were wrong, not too long.
fn roomy() -> Limits {
    Limits::new()
        .with_max_start_line(1 << 20)
        .with_max_header_bytes(1 << 20)
        .with_max_body(1 << 20)
}

fn caller_fields<'a>(fields: impl Iterator<Item = (&'a str, &'a [u8])>) -> Vec<(String, Vec<u8>)> {
    fields
        .filter(|(n, _)| !is_connection_field(n))
        .map(|(n, v)| (n.to_string(), v.to_vec()))
        .collect()
}

fn check_request(input: &Input, fields: &[(String, Vec<u8>)]) {
    let mut request = Request::new(&input.method, &input.target).header("host", "a");
    for (n, v) in fields {
        request = request.header(n, v);
    }
    request = match input.mode {
        Mode::Full => request.body(input.body.clone()),
        Mode::Chunked => request.chunked(),
        Mode::Length => request.content_length(input.body.len() as u64),
    };
    let mut client = ClientConn::new();
    let mut wire = Vec::new();
    if client.send_request(&request, &mut wire).is_err() {
        return;
    }
    if !matches!(input.mode, Mode::Full) {
        client
            .send_body(&input.body, &mut wire)
            .expect("declared length");
        client.end_body(&mut wire).expect("end of body");
    }

    let mut server = ServerConn::with_limits(roomy());
    assert_eq!(
        server.feed(&wire),
        wire.len(),
        "request larger than the buffer"
    );
    let (method, target, got) = match server.poll() {
        Ok(ServerEvent::Request(head)) => (
            head.method_str().to_string(),
            head.target().to_string(),
            caller_fields(head.headers()),
        ),
        other => panic!(
            "the server refused a built request ({other:?}): {:?}",
            String::from_utf8_lossy(&wire)
        ),
    };
    assert_eq!(method, request.method());
    assert_eq!(target, request.target());
    let mut want = vec![("host".to_string(), b"a".to_vec())];
    want.extend(fields.iter().cloned());
    assert_eq!(got, want, "request fields changed on the way");
    let mut body = Vec::new();
    loop {
        match server.poll() {
            Ok(ServerEvent::Body(b)) => body.extend_from_slice(b),
            Ok(ServerEvent::RequestEnd) => break,
            other => panic!("a built request body did not parse: {other:?}"),
        }
    }
    assert_eq!(body, input.body);
}

fn check_response(input: &Input, fields: &[(String, Vec<u8>)]) {
    let mut response = Response::new(input.status);
    for (n, v) in fields {
        response = response.header(n, v);
    }
    response = match input.mode {
        Mode::Full => response.body(input.body.clone()),
        Mode::Chunked => response.chunked(),
        Mode::Length => response.content_length(input.body.len() as u64),
    };
    let mut server = ServerConn::new();
    let _ = server.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    while !matches!(server.poll(), Ok(ServerEvent::RequestEnd)) {}
    let mut wire = Vec::new();
    if server.respond(&response, &mut wire).is_err() {
        return;
    }
    if !matches!(input.mode, Mode::Full) {
        server
            .send_body(&input.body, &mut wire)
            .expect("declared length");
        server.end_body(&mut wire).expect("end of body");
    }
    // 204 and 304 carry no body (a non-empty full body is refused above,
    // a streamed one is dropped).
    let bodiless = input.status == 204 || input.status == 304;

    let mut client = ClientConn::with_limits(roomy());
    client
        .send_request(&Request::get("/").header("host", "a"), &mut Vec::new())
        .expect("send");
    assert_eq!(
        client.feed(&wire),
        wire.len(),
        "response larger than the buffer"
    );
    let (status, got) = match client.poll() {
        Ok(ClientEvent::Response(head)) => (head.status(), caller_fields(head.headers())),
        other => panic!(
            "the client refused a built response ({other:?}): {:?}",
            String::from_utf8_lossy(&wire)
        ),
    };
    assert_eq!(status, input.status);
    assert_eq!(got, fields, "response fields changed on the way");
    let mut body = Vec::new();
    loop {
        match client.poll() {
            Ok(ClientEvent::Body(b)) => body.extend_from_slice(b),
            Ok(ClientEvent::ResponseEnd) => break,
            other => panic!("a built response body did not parse: {other:?}"),
        }
    }
    if bodiless {
        assert!(body.is_empty(), "a 204 or 304 carried a body");
    } else {
        assert_eq!(body, input.body);
    }
}

fuzz_target!(|input: Input| {
    if input.body.len() > 16 * 1024 {
        return;
    }
    let fields = &input.fields[..input.fields.len().min(8)];
    check_request(&input, fields);
    check_response(&input, fields);
});
