//! The origin over a real localhost socket: the echo body is what the Garden
//! parses, so these tests pin it byte for byte.

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use http_net_garden::{base64, serve_connection};

fn start() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            thread::spawn(move || {
                let _ = serve_connection(&mut stream);
            });
        }
    });
    addr
}

/// Sends `payload`, closes the sending side, and reads everything back.
fn exchange(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(payload).unwrap();
    s.shutdown(Shutdown::Write).unwrap();
    let mut got = Vec::new();
    s.read_to_end(&mut got).unwrap();
    got
}

/// Splits a run of `Content-Length` responses into (status, body) pairs.
fn responses(mut wire: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    while !wire.is_empty() {
        let end = wire
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("a complete head");
        let head = std::str::from_utf8(&wire[..end]).unwrap();
        let status: u16 = head[9..12].parse().unwrap();
        let len: usize = head
            .lines()
            .find_map(|l| {
                let (n, v) = l.split_once(':')?;
                n.eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse().unwrap())
            })
            .unwrap_or(0);
        let start = end + 4;
        out.push((status, wire[start..start + len].to_vec()));
        wire = &wire[start + len..];
    }
    out
}

fn echo(method: &str, version: &str, uri: &str, headers: &[(&str, &[u8])], body: &[u8]) -> Vec<u8> {
    let fields: Vec<String> = headers
        .iter()
        .map(|(n, v)| format!("[\"{}\",\"{}\"]", base64(n.as_bytes()), base64(v)))
        .collect();
    format!(
        "{{\"method\":\"{}\",\"version\":\"{}\",\"uri\":\"{}\",\"headers\":[{}],\"body\":\"{}\"}}",
        base64(method.as_bytes()),
        base64(version.as_bytes()),
        base64(uri.as_bytes()),
        fields.join(","),
        base64(body)
    )
    .into_bytes()
}

#[test]
fn simple_get_matches_the_garden_format_exactly() {
    let addr = start();
    let got = responses(&exchange(addr, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"));
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, 200);
    assert_eq!(
        String::from_utf8(got[0].1.clone()).unwrap(),
        r#"{"method":"R0VU","version":"MS4x","uri":"Lw==","headers":[["SG9zdA==","YQ=="]],"body":""}"#
    );
}

#[test]
fn chunked_body_is_decoded_and_headers_keep_order_and_case() {
    let addr = start();
    let got = responses(&exchange(
        addr,
        b"POST /p?q=1 HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nX-Dup: 1\r\nx-dup: 2\r\n\r\n\
          5\r\nhello\r\n1;ext=v\r\n!\r\n0\r\n\r\n",
    ));
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, 200);
    let want = echo(
        "POST",
        "1.1",
        "/p?q=1",
        &[
            ("Host", b"h"),
            ("Transfer-Encoding", b"chunked"),
            ("X-Dup", b"1"),
            ("x-dup", b"2"),
        ],
        b"hello!",
    );
    assert_eq!(got[0].1, want);
}

#[test]
fn pipelined_requests_are_answered_in_order() {
    let addr = start();
    let got = responses(&exchange(
        addr,
        b"PUT /1 HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc\
          GET /2 HTTP/1.0\r\n\r\n",
    ));
    assert_eq!(got.len(), 2);
    assert_eq!(
        got[0].1,
        echo(
            "PUT",
            "1.1",
            "/1",
            &[("Host", b"a"), ("Content-Length", b"3")],
            b"abc"
        )
    );
    // HTTP/1.0 without Host is allowed, and closes after its response.
    assert_eq!(got[1].1, echo("GET", "1.0", "/2", &[], b""));
}

#[test]
fn refusals_get_one_error_response_and_close() {
    let addr = start();
    for payload in [
        &b"GET / HTTP/1.1\r\n\r\n"[..],
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nHeader: v\x00\ralue\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n",
    ] {
        let got = responses(&exchange(addr, payload));
        assert_eq!(got.len(), 1, "{payload:?}");
        assert!(got[0].0 >= 400, "{payload:?} got {}", got[0].0);
    }
}

#[test]
fn answers_without_waiting_for_the_peer_to_close() {
    // The Garden writes a payload, then reads until the socket is quiet,
    // without closing its side. Each response must arrive in that window.
    let addr = start();
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut wire = Vec::new();
    for piece in [
        &b"GET /a HTTP/1.1\r\nHost: a\r\n\r\n"[..],
        b"GET /b HTTP/1.1\r\nHost: a\r\n\r\n",
    ] {
        s.write_all(piece).unwrap();
        let mut buf = [0u8; 4096];
        loop {
            match s.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => wire.extend_from_slice(&buf[..n]),
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
                Err(e) => panic!("{e}"),
            }
        }
    }
    let got = responses(&wire);
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].1, echo("GET", "1.1", "/a", &[("Host", b"a")], b""));
    assert_eq!(got[1].1, echo("GET", "1.1", "/b", &[("Host", b"a")], b""));
}
