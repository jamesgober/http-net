//! T-35: credentials leaked through logs.
//!
//! Every `Debug` output of the crate replaces the values of
//! `authorization`, `proxy-authorization`, `cookie`, and `set-cookie` with
//! `<redacted N bytes>`, for every spelling of the field name, in both the
//! compact and the pretty form. Accessors keep returning the real values.

use http_net::{
    Asked, ClientConn, ClientEvent, FieldSpan, Limits, OwnedRequestHead, Parsed, Request, Response,
    ServerConn, ServerEvent, parse_request_head, parse_response_head,
};

/// The four credential fields, each in several spellings.
const SPELLINGS: &[&str] = &[
    "authorization",
    "Authorization",
    "AUTHORIZATION",
    "aUtHoRiZaTiOn",
    "proxy-authorization",
    "Proxy-Authorization",
    "PROXY-AUTHORIZATION",
    "cookie",
    "Cookie",
    "COOKIE",
    "cOoKiE",
    "set-cookie",
    "Set-Cookie",
    "SET-COOKIE",
    "sEt-CoOkIe",
];

/// A secret value that differs per field, so a leak names its source.
fn secret(name: &str) -> String {
    format!("s3cr3t-{}-0123456789", name.len())
}

/// Asserts `shown` (a `Debug` rendering) never contains `secret` and does
/// contain the redaction marker with the secret's length.
fn assert_redacted(what: &str, shown: &str, secret: &str) {
    assert!(!shown.contains(secret), "{what}: secret printed in {shown}");
    let marker = format!("<redacted {} bytes>", secret.len());
    assert!(shown.contains(&marker), "{what}: no {marker} in {shown}");
}

fn both(value: &impl std::fmt::Debug) -> [String; 2] {
    [format!("{value:?}"), format!("{value:#?}")]
}

fn request_with(name: &str, value: &str) -> Vec<u8> {
    format!("GET / HTTP/1.1\r\nHost: a\r\nX-Visible: shown\r\n{name}: {value}\r\n\r\n").into_bytes()
}

fn response_with(name: &str, value: &str) -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\nX-Visible: shown\r\n{name}: {value}\r\nContent-Length: 0\r\n\r\n")
        .into_bytes()
}

#[test]
fn test_request_head_headers_and_event_debug_redact_every_spelling() {
    for name in SPELLINGS {
        let value = secret(name);
        let mut conn = ServerConn::new();
        let _ = conn.feed(&request_with(name, &value));
        let event = conn.poll().unwrap();
        for shown in both(&event) {
            assert_redacted(&format!("ServerEvent::Request / {name}"), &shown, &value);
            assert!(
                shown.contains("shown"),
                "other fields stay visible: {shown}"
            );
        }
        let ServerEvent::Request(req) = event else {
            panic!("expected a request");
        };
        for shown in both(&req) {
            assert_redacted(&format!("RequestHead / {name}"), &shown, &value);
        }
        for shown in both(&req.headers()) {
            assert_redacted(&format!("Headers / {name}"), &shown, &value);
        }
        for shown in both(&req.header_all(name)) {
            assert_redacted(&format!("HeaderValues / {name}"), &shown, &value);
        }
        // Accessors still return the real bytes.
        assert_eq!(req.header(name), Some(value.as_bytes()));
        assert_eq!(req.header_all(name).next(), Some(value.as_bytes()));
        assert!(req.headers().any(|(_, v)| v == value.as_bytes()));
    }
}

#[test]
fn test_response_head_and_client_event_debug_redact_every_spelling() {
    for name in SPELLINGS {
        let value = secret(name);
        let mut conn = ClientConn::new();
        conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())
            .unwrap();
        let _ = conn.feed(&response_with(name, &value));
        let event = conn.poll().unwrap();
        for shown in both(&event) {
            assert_redacted(&format!("ClientEvent::Response / {name}"), &shown, &value);
        }
        let ClientEvent::Response(resp) = event else {
            panic!("expected a response");
        };
        for shown in both(&resp) {
            assert_redacted(&format!("ResponseHead / {name}"), &shown, &value);
            assert!(shown.contains("shown"));
        }
        for shown in both(&resp.headers()) {
            assert_redacted(&format!("Headers / {name}"), &shown, &value);
        }
        for shown in both(&resp.header_all(name)) {
            assert_redacted(&format!("HeaderValues / {name}"), &shown, &value);
        }
        assert_eq!(resp.header(name), Some(value.as_bytes()));
    }
}

#[test]
fn test_builders_debug_redact_every_spelling() {
    for name in SPELLINGS {
        let value = secret(name);
        let request = Request::get("/")
            .header("host", "a")
            .header("x-visible", "shown")
            .header(name, &value);
        for shown in both(&request) {
            assert_redacted(&format!("Request / {name}"), &shown, &value);
            assert!(shown.contains("shown"));
        }
        assert_eq!(request.header_value(name), Some(value.as_bytes()));

        let response = Response::new(200)
            .header("x-visible", "shown")
            .header(name, &value);
        for shown in both(&response) {
            assert_redacted(&format!("Response / {name}"), &shown, &value);
        }
        assert_eq!(response.header_value(name), Some(value.as_bytes()));
    }
}

#[test]
fn test_repeated_credential_fields_are_each_redacted() {
    let mut conn = ServerConn::new();
    let _ = conn
        .feed(b"GET / HTTP/1.1\r\nHost: a\r\nCookie: first=aaaa\r\ncookie: second=bbbbbb\r\n\r\n");
    let ServerEvent::Request(req) = conn.poll().unwrap() else {
        panic!("expected a request");
    };
    for shown in both(&req)
        .into_iter()
        .chain(both(&req.header_all("cookie")))
    {
        assert!(
            !shown.contains("first=aaaa") && !shown.contains("second=bbbbbb"),
            "{shown}"
        );
        assert!(
            shown.contains("<redacted 10 bytes>") && shown.contains("<redacted 13 bytes>"),
            "{shown}"
        );
    }
}

#[test]
fn test_empty_credential_value_is_redacted_as_zero_bytes() {
    let mut conn = ServerConn::new();
    let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nAuthorization:\r\n\r\n");
    let ServerEvent::Request(req) = conn.poll().unwrap() else {
        panic!("expected a request");
    };
    assert!(format!("{req:?}").contains("<redacted 0 bytes>"));
}

/// T-35: the views that copy or rebuild a head redact like the borrowed
/// ones. An `Authorization: Bearer s3cr3t` request head through
/// `RequestHead::to_owned`, through `OwnedRequestHead::from_parts` of its
/// own `into_parts`, and through `parse_request_head` (the `Parsed` result
/// and the head), and a response with `Set-Cookie` through
/// `parse_response_head`, never print the secret in `{:?}` or `{:#?}` and
/// print `<redacted N bytes>` instead.
#[test]
fn test_owned_and_stateless_views_debug_redact_credentials() {
    let value = "Bearer s3cr3t";
    let input = request_with("Authorization", value);
    let mut conn = ServerConn::new();
    let _ = conn.feed(&input);
    let ServerEvent::Request(req) = conn.poll().unwrap() else {
        panic!("expected a request");
    };
    let owned = req.to_owned();
    for shown in both(&owned) {
        assert_redacted("OwnedRequestHead (to_owned)", &shown, value);
        assert!(shown.contains("shown"), "{shown}");
    }
    for shown in both(&owned.view()) {
        assert_redacted("OwnedRequestHead::view", &shown, value);
    }
    let (bytes, fields, facts) = owned.into_parts();
    let rebuilt = OwnedRequestHead::from_parts(bytes, fields, facts).unwrap();
    for shown in both(&rebuilt) {
        assert_redacted("OwnedRequestHead (from_parts)", &shown, value);
    }
    assert_eq!(
        rebuilt.view().header("authorization"),
        Some(value.as_bytes())
    );

    let mut slots = [FieldSpan::default(); 16];
    let parsed = parse_request_head(&input, &Limits::new(), &mut slots).unwrap();
    for shown in both(&parsed) {
        assert_redacted("Parsed<ParsedRequest>", &shown, value);
    }
    let Parsed::Complete { head, .. } = parsed else {
        panic!("expected a complete head");
    };
    for shown in both(&head).into_iter().chain(both(&head.view())) {
        assert_redacted("ParsedRequest", &shown, value);
    }

    let cookie = "sid=s3cr3t-session; HttpOnly";
    let input = response_with("Set-Cookie", cookie);
    let mut slots = [FieldSpan::default(); 16];
    let parsed = parse_response_head(&input, &Limits::new(), Asked::default(), &mut slots).unwrap();
    for shown in both(&parsed) {
        assert_redacted("Parsed<ParsedResponse>", &shown, cookie);
    }
    let Parsed::Complete { head, .. } = parsed else {
        panic!("expected a complete head");
    };
    for shown in both(&head).into_iter().chain(both(&head.view())) {
        assert_redacted("ParsedResponse", &shown, cookie);
        assert!(shown.contains("shown"), "{shown}");
    }
    assert_eq!(head.view().header("set-cookie"), Some(cookie.as_bytes()));
}

#[cfg(feature = "std")]
#[test]
fn test_blocking_client_response_debug_redacts_set_cookie() {
    use http_net::blocking;

    let server = blocking::Server::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr();
    let stop = server.shutdown_handle();
    let thread = std::thread::spawn(move || {
        server.serve(|_req, _body| {
            Response::text(200, "ok")
                .header("Set-Cookie", "sid=s3cr3t-session-value; HttpOnly")
                .header("set-cookie", "csrf=s3cr3t-csrf-token")
                .header("x-visible", "shown")
        })
    });
    let resp = blocking::get(&format!("http://{addr}/")).unwrap();
    for shown in both(&resp) {
        assert!(!shown.contains("s3cr3t"), "secret printed in {shown}");
        assert!(shown.contains("<redacted 34 bytes>"), "{shown}");
        assert!(shown.contains("<redacted 22 bytes>"), "{shown}");
        assert!(shown.contains("shown"), "{shown}");
    }
    assert_eq!(
        resp.header("set-cookie"),
        Some(&b"sid=s3cr3t-session-value; HttpOnly"[..])
    );
    stop.shutdown();
    thread.join().unwrap().unwrap();
}

/// `ResponseHeadRef` (the allocation-free writer's head) redacts like every
/// other type that prints fields (fixed in 0.9.0: it derived `Debug`).
#[test]
fn test_response_head_ref_debug_redacts_every_spelling() {
    use http_net::{OutgoingBody, ResponseHeadRef};

    for &name in SPELLINGS {
        let value = secret(name);
        let fields: &[(&str, &[u8])] = &[(name, value.as_bytes()), ("x-visible", b"shown")];
        let head = ResponseHeadRef::new(200, fields, OutgoingBody::Empty);
        for shown in both(&head) {
            assert_redacted(name, &shown, &value);
            assert!(shown.contains("shown"), "{shown}");
            assert!(shown.contains("200"), "{shown}");
        }
    }
}

/// `blocking::Connection` holds the last request body and the last
/// serialized response; its `Debug` prints their lengths only (fixed in
/// 0.9.0: it derived `Debug` and printed both).
#[cfg(feature = "std")]
#[test]
fn test_blocking_connection_debug_never_prints_its_buffers() {
    use std::io::{Read, Write};

    use http_net::{Limits, blocking::Connection};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let client = std::thread::spawn(move || {
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        stream
            .write_all(
                b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 20\r\n\r\ns3cr3t-request-body!",
            )
            .unwrap();
        let mut reply = Vec::new();
        let mut buf = [0u8; 512];
        while !reply.windows(2).any(|w| w == b"ok") {
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0);
            reply.extend_from_slice(&buf[..n]);
        }
    });
    let (stream, _) = listener.accept().unwrap();
    let mut conn = Connection::new(stream, Limits::new());
    assert!(conn.next_request().unwrap().is_some());
    conn.respond(&Response::text(200, "ok").header("set-cookie", "sid=s3cr3t-session"))
        .unwrap();
    client.join().unwrap();
    for shown in both(&conn) {
        assert!(!shown.contains("s3cr3t"), "secret printed in {shown}");
        assert!(
            !shown.contains("115, 51, 99"),
            "secret bytes printed in {shown}"
        );
        assert!(shown.contains("out_len"), "{shown}");
    }
}
