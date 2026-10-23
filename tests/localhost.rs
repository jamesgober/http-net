//! Integration over real localhost sockets: the blocking server and client,
//! keep-alive, pipelining, chunked bodies both ways, error answers, the
//! connection cap, the upgrade hand-off, and shutdown.

#![cfg(feature = "std")]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use http_net::{
    ClientConn, ClientEvent, Limits, Request, RequestHead, Response,
    blocking::{self, Connection, Server, ServerConfig, ShutdownHandle},
};

struct Running {
    addr: SocketAddr,
    stop: ShutdownHandle,
    thread: Option<JoinHandle<std::io::Result<()>>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.shutdown();
        if let Some(t) = self.thread.take() {
            t.join().expect("server thread").expect("serve");
        }
    }
}

fn start(server: Server, handler: fn(&RequestHead<'_>, &[u8]) -> Response) -> Running {
    let addr = server.local_addr();
    let stop = server.shutdown_handle();
    let thread = Some(thread::spawn(move || server.serve(handler)));
    Running { addr, stop, thread }
}

fn echo(req: &RequestHead<'_>, body: &[u8]) -> Response {
    match req.path() {
        "/echo" => Response::new(200)
            .header("content-type", "application/octet-stream")
            .body(body.to_vec()),
        "/stream" => Response::new(200).chunked(),
        path => Response::text(200, &format!("{} {path}", req.method_str())),
    }
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    s
}

/// Reads one response from `stream` with a `ClientConn`; returns status and body.
fn read_response(stream: &mut TcpStream, conn: &mut ClientConn) -> (u16, Vec<u8>, bool) {
    let mut status = 0;
    let mut body = Vec::new();
    let mut close = false;
    loop {
        match conn.poll().expect("response") {
            ClientEvent::Response(r) => {
                status = r.status();
                close = !r.keep_alive();
            }
            ClientEvent::Body(b) => body.extend_from_slice(b),
            ClientEvent::ResponseEnd => return (status, body, close),
            ClientEvent::NeedInput => {
                let n = stream.read(conn.read_buf()).expect("read");
                if n == 0 {
                    conn.feed_eof();
                } else {
                    conn.commit(n);
                }
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[test]
fn test_tier1_server_and_get() {
    let running = start(Server::bind("127.0.0.1:0").unwrap(), echo);
    for path in ["/", "/a/b?c=d", "/%7Euser"] {
        let resp = blocking::get(&format!("http://{}{path}", running.addr)).unwrap();
        assert_eq!(resp.status(), 200);
        let expected = format!("GET {}", path.split('?').next().unwrap());
        assert_eq!(resp.text(), Some(expected.as_str()));
        assert!(resp.header("date").is_some_and(|d| d.ends_with(b" GMT")));
        assert_eq!(
            resp.header("content-type"),
            Some(&b"text/plain; charset=utf-8"[..])
        );
    }
}

#[test]
fn test_keep_alive_and_pipelining_on_one_socket() {
    let running = start(Server::bind("127.0.0.1:0").unwrap(), echo);
    let mut stream = connect(running.addr);
    let mut conn = ClientConn::new();

    // Sequential keep-alive requests.
    for i in 0..5 {
        let mut out = Vec::new();
        conn.send_request(
            &Request::get(&format!("/seq/{i}")).header("host", "x"),
            &mut out,
        )
        .unwrap();
        stream.write_all(&out).unwrap();
        let (status, body, close) = read_response(&mut stream, &mut conn);
        assert_eq!((status, close), (200, false));
        assert_eq!(body, format!("GET /seq/{i}").as_bytes());
        assert!(matches!(conn.poll().unwrap(), ClientEvent::Idle));
    }

    // Three pipelined requests in one write; responses come back in order.
    // `ClientConn` keeps one request outstanding, so the responses (which
    // may arrive in one read) are checked on the raw bytes.
    stream
        .write_all(
            b"GET /p1 HTTP/1.1\r\nHost: x\r\n\r\nGET /p2 HTTP/1.1\r\nHost: x\r\n\r\n\
              GET /p3 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8(raw).unwrap();
    let bodies: Vec<&str> = text
        .split("HTTP/1.1 200 OK\r\n")
        .skip(1)
        .map(|r| r.rsplit("\r\n\r\n").next().unwrap())
        .collect();
    assert_eq!(bodies, ["GET /p1", "GET /p2", "GET /p3"]);
}

#[test]
fn test_chunked_upload_echo_and_chunked_download() {
    let running = start(Server::bind("127.0.0.1:0").unwrap(), echo);
    let mut stream = connect(running.addr);
    let mut conn = ClientConn::new();
    let mut out = Vec::new();
    conn.send_request(
        &Request::post("/echo").header("host", "x").chunked(),
        &mut out,
    )
    .unwrap();
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    for piece in payload.chunks(7_919) {
        conn.send_body(piece, &mut out).unwrap();
    }
    conn.end_body(&mut out).unwrap();
    stream.write_all(&out).unwrap();
    let (status, body, _) = read_response(&mut stream, &mut conn);
    assert_eq!(status, 200);
    assert_eq!(body, payload);
}

#[test]
fn test_streamed_response_through_connection() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut conn = Connection::new(stream, Limits::new());
        while let Some(req) = conn.next_request().unwrap() {
            let lines: usize = req.head().query().unwrap_or("3").parse().unwrap();
            conn.respond(&Response::new(200).chunked()).unwrap();
            for i in 0..lines {
                conn.send_body(format!("line {i}\n").as_bytes()).unwrap();
            }
            conn.end_body().unwrap();
        }
        conn.close();
    });
    let resp = blocking::get(&format!("http://{addr}/log?4")).unwrap();
    assert_eq!(resp.text(), Some("line 0\nline 1\nline 2\nline 3\n"));
    assert_eq!(resp.header("transfer-encoding"), Some(&b"chunked"[..]));
    server.join().unwrap();
}

#[test]
fn test_bad_requests_are_answered_and_closed() {
    let running = start(Server::bind("127.0.0.1:0").unwrap(), echo);
    for (raw, status) in [
        (&b"GET / HTTP/1.1\r\n\r\n"[..], &b"HTTP/1.1 400 "[..]),
        (b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n", b"HTTP/1.1 400 "),
        (b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2000000\r\n\r\n", b"HTTP/1.1 413 "),
        (b"GET / HTTP/2.0\r\nHost: x\r\n\r\n", b"HTTP/1.1 505 "),
        (b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", b"HTTP/1.1 501 "),
    ] {
        let mut stream = connect(running.addr);
        stream.write_all(raw).unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert!(reply.starts_with(status), "{}", String::from_utf8_lossy(&reply));
        assert!(reply.windows(17).any(|w| w == b"connection: close"));
    }
    // A request line over 8 KiB gets 414.
    let mut stream = connect(running.addr);
    let mut long = b"GET /".to_vec();
    long.extend(std::iter::repeat_n(b'a', 9000));
    long.extend_from_slice(b" HTTP/1.1\r\nHost: x\r\n\r\n");
    stream.write_all(&long).unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).unwrap();
    assert!(reply.starts_with(b"HTTP/1.1 414 "));
}

#[test]
fn test_http10_client_gets_close() {
    let running = start(Server::bind("127.0.0.1:0").unwrap(), echo);
    let mut stream = connect(running.addr);
    stream.write_all(b"GET /old HTTP/1.0\r\n\r\n").unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).unwrap();
    assert!(reply.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(reply.ends_with(b"GET /old"));
}

#[test]
fn test_connection_cap_answers_503() {
    let server = Server::bind("127.0.0.1:0").unwrap().with_config(
        ServerConfig::new()
            .with_max_connections(1)
            .with_read_timeout(Some(Duration::from_secs(5))),
    );
    let running = start(server, echo);
    // The first connection takes the only slot.
    let mut first = connect(running.addr);
    first
        .write_all(b"GET /hold HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut conn = ClientConn::new();
    conn.send_request(&Request::get("/hold").header("host", "x"), &mut Vec::new())
        .unwrap();
    let (status, _, _) = read_response(&mut first, &mut conn);
    assert_eq!(status, 200);
    // The second is turned away while the first is open.
    let mut second = connect(running.addr);
    let mut reply = Vec::new();
    second.read_to_end(&mut reply).unwrap();
    assert!(
        reply.starts_with(b"HTTP/1.1 503 "),
        "{}",
        String::from_utf8_lossy(&reply)
    );
    drop(first);
}

#[test]
fn test_upgrade_hands_over_the_socket() {
    let upgrades = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&upgrades);
    let server = Server::bind("127.0.0.1:0")
        .unwrap()
        .on_upgrade(move |mut up| {
            let _ = seen.fetch_add(1, Ordering::SeqCst);
            assert_eq!(up.target, "/rpc");
            // Echo the bytes that came with the request, then echo the stream.
            up.stream.write_all(&up.leftover).unwrap();
            let mut buf = [0u8; 64];
            loop {
                match up.stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => up.stream.write_all(&buf[..n]).unwrap(),
                }
            }
        });
    let running = start(server, |req, _| {
        if req.is_upgrade() && req.header("upgrade") == Some(b"echo") {
            Response::switching_protocols("echo")
        } else {
            Response::new(426)
        }
    });

    let mut stream = connect(running.addr);
    let mut conn = ClientConn::new();
    let mut out = Vec::new();
    conn.send_request(
        &Request::get("/rpc").header("host", "x").upgrade("echo"),
        &mut out,
    )
    .unwrap();
    out.extend_from_slice(b"early");
    stream.write_all(&out).unwrap();
    loop {
        match conn.poll().unwrap() {
            ClientEvent::Response(r) => assert_eq!(r.status(), 101),
            ClientEvent::Upgraded => break,
            ClientEvent::NeedInput => {
                let n = stream.read(conn.read_buf()).unwrap();
                assert!(n > 0);
                conn.commit(n);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    let mut got = conn.remaining_input().to_vec();
    stream.write_all(b" and late").unwrap();
    let want = b"early and late";
    let mut buf = [0u8; 64];
    while got.len() < want.len() {
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(&got, want);
    drop(stream);
    drop(running);
    assert_eq!(upgrades.load(Ordering::SeqCst), 1);
}

#[test]
fn test_client_errors() {
    // Nothing listens on a port we just released.
    let addr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let err = blocking::Client::new()
        .with_timeout(Duration::from_secs(2))
        .get(&format!("http://{addr}/"))
        .unwrap_err();
    assert!(matches!(err, blocking::Error::Io(_)));

    // A response over the client's body limit is refused.
    let running = start(Server::bind("127.0.0.1:0").unwrap(), |_, _| {
        Response::new(200).body(vec![b'x'; 4096])
    });
    let err = blocking::Client::new()
        .with_limits(Limits::new().with_max_body(1024))
        .get(&format!("http://{}/", running.addr))
        .unwrap_err();
    assert!(matches!(
        err,
        blocking::Error::Http(http_net::HttpError::BodyTooLarge)
    ));
}

#[test]
fn test_shutdown_with_idle_server_returns() {
    let server = Server::bind("127.0.0.1:0").unwrap();
    let stop = server.shutdown_handle();
    let t = thread::spawn(move || server.serve(echo));
    stop.shutdown();
    t.join().unwrap().unwrap();
}

// ---------------------------------------------------------------------------
// Adversarial review: timing, budgets, and handler misuse
// ---------------------------------------------------------------------------

/// Writes `piece` every `every` until `total` has passed, ignoring errors
/// (the server may close first, which is the point of some tests).
fn trickle(mut stream: TcpStream, piece: &'static [u8], every: Duration, total: Duration) {
    let start = Instant::now();
    while start.elapsed() < total {
        if stream.write_all(piece).is_err() {
            return;
        }
        thread::sleep(every);
    }
}

#[test]
fn test_slow_request_is_cut_off_by_the_request_timeout() {
    // Slowloris: each byte arrives well inside the read timeout, so only a
    // deadline on the whole request can end it.
    let server = Server::bind("127.0.0.1:0").unwrap().with_config(
        ServerConfig::new()
            .with_read_timeout(Some(Duration::from_secs(5)))
            .with_request_timeout(Some(Duration::from_secs(1))),
    );
    let running = start(server, echo);
    let mut stream = connect(running.addr);
    stream.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").unwrap();
    let writer = stream.try_clone().unwrap();
    let t = thread::spawn(move || {
        trickle(
            writer,
            b"X: 1\r\n",
            Duration::from_millis(150),
            Duration::from_secs(6),
        );
    });
    let started = Instant::now();
    let mut sink = Vec::new();
    let _ = stream.read_to_end(&mut sink);
    let took = started.elapsed();
    assert!(
        took < Duration::from_secs(4),
        "connection held for {took:?}"
    );
    assert!(
        sink.starts_with(b"HTTP/1.1 408 "),
        "{}",
        String::from_utf8_lossy(&sink)
    );
    t.join().unwrap();
}

/// T-25, slow body: the head arrives at once and the body one byte every
/// 150 ms, each well inside the read timeout. The request deadline (1 s)
/// still ends the request: the server answers `408 Request Timeout` and
/// closes long before the body would be complete.
#[test]
fn test_slow_body_is_cut_off_by_the_request_timeout() {
    let server = Server::bind("127.0.0.1:0").unwrap().with_config(
        ServerConfig::new()
            .with_read_timeout(Some(Duration::from_secs(5)))
            .with_request_timeout(Some(Duration::from_secs(1))),
    );
    let running = start(server, echo);
    let mut stream = connect(running.addr);
    stream
        .write_all(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n")
        .unwrap();
    let writer = stream.try_clone().unwrap();
    let t = thread::spawn(move || {
        trickle(
            writer,
            b"x",
            Duration::from_millis(150),
            Duration::from_secs(6),
        );
    });
    let started = Instant::now();
    let mut sink = Vec::new();
    let _ = stream.read_to_end(&mut sink);
    let took = started.elapsed();
    assert!(
        took < Duration::from_secs(4),
        "connection held for {took:?}"
    );
    assert!(
        sink.starts_with(b"HTTP/1.1 408 "),
        "{}",
        String::from_utf8_lossy(&sink)
    );
    t.join().unwrap();
}

#[test]
fn test_request_timeout_does_not_count_idle_keep_alive_time() {
    let server = Server::bind("127.0.0.1:0").unwrap().with_config(
        ServerConfig::new()
            .with_read_timeout(Some(Duration::from_secs(5)))
            .with_request_timeout(Some(Duration::from_millis(700))),
    );
    let running = start(server, echo);
    let mut stream = connect(running.addr);
    let mut conn = ClientConn::new();
    for i in 0..2 {
        // Idle longer than the request timeout between requests.
        thread::sleep(Duration::from_millis(900));
        let mut out = Vec::new();
        conn.send_request(
            &Request::get(&format!("/{i}")).header("host", "x"),
            &mut out,
        )
        .unwrap();
        stream.write_all(&out).unwrap();
        let (status, _, close) = read_response(&mut stream, &mut conn);
        assert_eq!((status, close), (200, false));
        assert!(matches!(conn.poll().unwrap(), ClientEvent::Idle));
    }
}

#[test]
fn test_busy_refusal_never_stalls_the_accept_loop() {
    let server = Server::bind("127.0.0.1:0").unwrap().with_config(
        ServerConfig::new()
            .with_max_connections(1)
            .with_read_timeout(Some(Duration::from_secs(10))),
    );
    let running = start(server, echo);
    // The only slot is held by an idle keep-alive connection.
    let mut first = connect(running.addr);
    first
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut conn = ClientConn::new();
    conn.send_request(&Request::get("/").header("host", "x"), &mut Vec::new())
        .unwrap();
    assert_eq!(read_response(&mut first, &mut conn).0, 200);

    // A refused client that keeps sending must not hold up the next accept.
    let slow = connect(running.addr);
    let t = thread::spawn(move || {
        trickle(
            slow,
            b"x",
            Duration::from_millis(50),
            Duration::from_secs(3),
        );
    });
    thread::sleep(Duration::from_millis(200));
    let started = Instant::now();
    let mut third = connect(running.addr);
    let mut reply = Vec::new();
    let _ = third.read_to_end(&mut reply);
    let took = started.elapsed();
    assert!(
        reply.starts_with(b"HTTP/1.1 503 "),
        "{}",
        String::from_utf8_lossy(&reply)
    );
    assert!(
        took < Duration::from_millis(1500),
        "accept loop stalled for {took:?}"
    );
    t.join().unwrap();
    drop(first);
}

#[test]
fn test_lingering_close_has_a_total_deadline() {
    // After `connection: close` the server drains what the client still
    // sends, but only for a bounded time: a client that never stops must
    // not keep the connection slot.
    let server = Server::bind("127.0.0.1:0").unwrap().with_config(
        ServerConfig::new()
            .with_max_connections(1)
            .with_read_timeout(Some(Duration::from_secs(10))),
    );
    let running = start(server, echo);
    let mut stream = connect(running.addr);
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let writer = stream.try_clone().unwrap();
    let t = thread::spawn(move || {
        trickle(
            writer,
            b"x",
            Duration::from_millis(50),
            Duration::from_secs(5),
        );
    });
    let mut reply = Vec::new();
    let _ = stream.read_to_end(&mut reply);
    assert!(reply.starts_with(b"HTTP/1.1 200 "));
    // The drain stops after one second in total; the client keeps sending
    // for longer than this wait, so an unbounded drain would still hold
    // the slot.
    thread::sleep(Duration::from_millis(2500));
    // The slot is free again: a new connection is served, not refused.
    let mut next = connect(running.addr);
    next.write_all(b"GET /n HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut reply = Vec::new();
    let _ = next.read_to_end(&mut reply);
    assert!(
        reply.starts_with(b"HTTP/1.1 200 "),
        "{}",
        String::from_utf8_lossy(&reply)
    );
    t.join().unwrap();
}

/// T-40, lingering-close abuse, byte cap: after a `connection: close`
/// answer the server drains what the client still sends, at most 256 KiB,
/// so a client that writes 8 MiB as fast as it can does not keep the only
/// connection slot (`max_connections(1)`). The answer arrives, and a new
/// connection is served 200 instead of 503, within 2 s of the request.
///
/// The bound is generous on purpose: on loopback the byte cap ends the
/// drain within milliseconds, but a loaded CI runner can be slow, and the
/// drain's 1 s total-time cap would also end it inside 2 s. So this test
/// proves the slot is freed while the peer is still sending, not which cap
/// freed it (a bound under 1 s would tell them apart, at the cost of
/// flakiness). The new connection is retried while the server finishes the
/// drain, since the slot is released a moment after the answer is read;
/// each refusal on the way must be a 503 (or a reset of the refused
/// socket), never a hang.
#[test]
fn test_lingering_close_drain_is_capped_in_bytes() {
    let server = Server::bind("127.0.0.1:0").unwrap().with_config(
        ServerConfig::new()
            .with_max_connections(1)
            .with_read_timeout(Some(Duration::from_secs(10))),
    );
    let running = start(server, echo);
    let mut stream = connect(running.addr);
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut writer = stream.try_clone().unwrap();
    let started = Instant::now();
    let flood = thread::spawn(move || {
        // Unpaced; the server closing the socket first is the expected end.
        let _ = writer.write_all(&vec![b'x'; 8 << 20]);
    });
    let mut reply = Vec::new();
    let _ = stream.read_to_end(&mut reply);
    let answered = started.elapsed();
    assert!(
        reply.starts_with(b"HTTP/1.1 200 "),
        "{}",
        String::from_utf8_lossy(&reply)
    );
    assert!(
        answered < Duration::from_secs(2),
        "answered after {answered:?}"
    );

    let deadline = started + Duration::from_secs(2);
    let mut refusals = 0;
    let served = loop {
        let mut next = connect(running.addr);
        let _ = next.write_all(b"GET /n HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        let mut reply = Vec::new();
        let _ = next.read_to_end(&mut reply);
        if reply.starts_with(b"HTTP/1.1 200 ") {
            break true;
        }
        assert!(
            reply.is_empty() || reply.starts_with(b"HTTP/1.1 503 "),
            "{}",
            String::from_utf8_lossy(&reply)
        );
        refusals += 1;
        if Instant::now() >= deadline {
            break false;
        }
        thread::sleep(Duration::from_millis(20));
    };
    let took = started.elapsed();
    assert!(
        served,
        "the slot was still held after {took:?} ({refusals} refusals)"
    );
    assert!(took < Duration::from_secs(2), "slot freed after {took:?}");
    drop(stream);
    flood.join().unwrap();
}

#[test]
fn test_expect_continue_gets_100_before_the_body() {
    // RFC 9110 section 10.1.1: the server MUST answer the expectation
    // (with 100 or a final status) before the client sends the body.
    let running = start(Server::bind("127.0.0.1:0").unwrap(), echo);
    let mut stream = connect(running.addr);
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .write_all(
            b"POST /echo HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n\
              Content-Length: 5\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
    let mut interim = [0u8; 25];
    stream
        .read_exact(&mut interim)
        .expect("100 Continue before the body");
    assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
    stream.write_all(b"hello").unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).unwrap();
    assert!(reply.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(reply.ends_with(b"\r\n\r\nhello"));
}

#[test]
fn test_expect_continue_over_the_limit_gets_413_not_100() {
    let running = start(Server::bind("127.0.0.1:0").unwrap(), echo);
    let mut stream = connect(running.addr);
    stream
        .write_all(
            b"POST /echo HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n\
              Content-Length: 5000000\r\n\r\n",
        )
        .unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).unwrap();
    assert!(
        reply.starts_with(b"HTTP/1.1 413 "),
        "{}",
        String::from_utf8_lossy(&reply)
    );
}

#[test]
fn test_handler_misuse_is_answered_with_500() {
    // A handler that returns a streamed response (the Server only sends
    // full bodies) or an invalid one must not leave the client hanging.
    let running = start(Server::bind("127.0.0.1:0").unwrap(), |req, _| {
        match req.path() {
            "/stream" => Response::new(200).chunked(),
            "/length" => Response::new(200).content_length(10),
            _ => Response::new(200).header("content-length", "1"),
        }
    });
    for path in ["/stream", "/length", "/reserved"] {
        let mut stream = connect(running.addr);
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert!(
            reply.starts_with(b"HTTP/1.1 500 "),
            "{path}: {}",
            String::from_utf8_lossy(&reply)
        );
        assert!(reply.windows(17).any(|w| w == b"connection: close"));
    }

    // HEAD is the exception: announcing a length without a body is the
    // whole answer, and the connection stays usable.
    let mut stream = connect(running.addr);
    let mut conn = ClientConn::new();
    for _ in 0..2 {
        let mut out = Vec::new();
        conn.send_request(
            &Request::new("HEAD", "/length").header("host", "x"),
            &mut out,
        )
        .unwrap();
        stream.write_all(&out).unwrap();
        let (status, body, close) = read_response(&mut stream, &mut conn);
        assert_eq!((status, body.len(), close), (200, 0, false));
        assert!(matches!(conn.poll().unwrap(), ClientEvent::Idle));
    }
}

#[test]
fn test_upgraded_socket_does_not_inherit_the_request_deadline() {
    // The head arrives in two pieces, so the request deadline (1 s) is
    // running and shortens the socket's read timeout. The upgraded socket
    // must get the configured read timeout (10 s) back.
    let server = Server::bind("127.0.0.1:0")
        .unwrap()
        .with_config(
            ServerConfig::new()
                .with_read_timeout(Some(Duration::from_secs(10)))
                .with_request_timeout(Some(Duration::from_secs(1))),
        )
        .on_upgrade(|mut up| {
            let mut buf = [0u8; 16];
            if let Ok(n) = up.stream.read(&mut buf) {
                let _ = up.stream.write_all(&buf[..n]);
            }
        });
    let running = start(server, |req, _| {
        if req.is_upgrade() {
            Response::switching_protocols("echo")
        } else {
            Response::new(426)
        }
    });
    let mut stream = connect(running.addr);
    stream
        .write_all(b"GET /ws HTTP/1.1\r\nHost: x\r\n")
        .unwrap();
    thread::sleep(Duration::from_millis(150));
    stream
        .write_all(b"Connection: upgrade\r\nUpgrade: echo\r\n\r\n")
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 101 "));
    // Silent for longer than what was left of the request deadline.
    thread::sleep(Duration::from_millis(1500));
    stream.write_all(b"ping").unwrap();
    let mut echo = [0u8; 4];
    stream.read_exact(&mut echo).unwrap();
    assert_eq!(&echo, b"ping");
}

/// Checks the shape of an IMF-fixdate: `Sun, 06 Nov 1994 08:49:37 GMT`.
fn is_imf_fixdate(v: &[u8]) -> bool {
    const DAYS: [&[u8]; 7] = [b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat", b"Sun"];
    const MONTHS: [&[u8]; 12] = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
        b"Dec",
    ];
    let digits = |r: std::ops::Range<usize>| v[r].iter().all(u8::is_ascii_digit);
    v.len() == 29
        && DAYS.contains(&&v[0..3])
        && &v[3..5] == b", "
        && digits(5..7)
        && v[7] == b' '
        && MONTHS.contains(&&v[8..11])
        && v[11] == b' '
        && digits(12..16)
        && v[16] == b' '
        && digits(17..19)
        && v[19] == b':'
        && digits(20..22)
        && v[22] == b':'
        && digits(23..25)
        && &v[25..] == b" GMT"
}

/// FR-36: every response, the error answers included, carries a `date` in
/// IMF-fixdate form (RFC 9110 section 5.6.7), from the per-thread cache.
#[test]
fn test_every_response_date_is_an_imf_fixdate() {
    let running = start(Server::bind("127.0.0.1:0").unwrap(), echo);
    let resp = blocking::get(&format!("http://{}/", running.addr)).unwrap();
    let date = resp.header("date").expect("date");
    assert!(is_imf_fixdate(date), "{}", String::from_utf8_lossy(date));

    // A refused request: the answer comes from `Response::from_error`.
    let mut stream = connect(running.addr);
    stream.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).unwrap();
    let text = String::from_utf8_lossy(&reply);
    assert!(text.starts_with("HTTP/1.1 400 "), "{text}");
    let date = text
        .lines()
        .find_map(|l| l.strip_prefix("date: "))
        .expect("date on the error answer");
    assert!(is_imf_fixdate(date.as_bytes()), "{date}");
    assert!(is_imf_fixdate(blocking::now_date().as_bytes()));
}

/// T-26, E-196, FR-57: a client that reads a large streamed response one
/// byte every 100 ms holds the connection only until the response deadline,
/// not for as long as the response would take (or the 10 s write timeout
/// per write). A streamed body is used because it fills the socket buffers
/// on every platform (Windows takes a very large single write into the
/// kernel at once).
#[test]
fn test_connection_response_deadline_slow_reader_times_out() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stop_reading = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader = {
        let stop_reading = Arc::clone(&stop_reading);
        thread::spawn(move || {
            let mut s = connect(addr);
            s.write_all(b"GET /big HTTP/1.1\r\nHost: x\r\n\r\n")
                .unwrap();
            let mut byte = [0u8; 1];
            while !stop_reading.load(Ordering::SeqCst) {
                if s.read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        })
    };
    let (stream, _) = listener.accept().unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Connection::new(stream, Limits::new())
        .with_response_deadline(Some(Duration::from_millis(500)));
    assert!(conn.next_request().unwrap().is_some());
    let started = Instant::now();
    conn.respond(&Response::new(200).chunked()).unwrap();
    let chunk = vec![b'x'; 1 << 20];
    let mut outcome = Ok(());
    for _ in 0..1024 {
        outcome = conn.send_body(&chunk);
        if outcome.is_err() {
            break;
        }
    }
    let waited = started.elapsed();
    stop_reading.store(true, Ordering::SeqCst);
    drop(conn);
    reader.join().unwrap();
    assert!(
        matches!(&outcome, Err(blocking::Error::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut),
        "{outcome:?}"
    );
    assert!(
        waited >= Duration::from_millis(400) && waited < Duration::from_secs(3),
        "the response was cut after {waited:?}"
    );
}

/// T-26, A-241: the server applies its response deadline. A slow reader of
/// a large response does not hold the connection thread (and so shutdown)
/// for the 10 s write timeout. The read timeout is short so an idle
/// keep-alive read after a response the kernel accepted in full ends soon.
#[test]
fn test_server_response_deadline_slow_reader_is_cut_off() {
    let server = Server::bind("127.0.0.1:0").unwrap().with_config(
        ServerConfig::new()
            .with_read_timeout(Some(Duration::from_secs(1)))
            .with_write_timeout(Some(Duration::from_secs(10)))
            .with_response_deadline(Some(Duration::from_millis(500))),
    );
    // Larger than any loopback send and receive buffer, so the writes block.
    let running = start(server, |_, _| Response::new(200).body(vec![b'x'; 64 << 20]));
    let mut stream = connect(running.addr);
    stream
        .write_all(b"GET /big HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let stop_reading = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader = {
        let stop_reading = Arc::clone(&stop_reading);
        thread::spawn(move || {
            let mut byte = [0u8; 1];
            while !stop_reading.load(Ordering::SeqCst) {
                if stream.read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        })
    };
    thread::sleep(Duration::from_millis(200));
    // Shutdown waits for every connection thread: it returns only once the
    // deadline has cut the slow response off.
    let started = Instant::now();
    drop(running);
    let waited = started.elapsed();
    stop_reading.store(true, Ordering::SeqCst);
    reader.join().unwrap();
    assert!(
        waited < Duration::from_secs(5),
        "the connection was held for {waited:?}"
    );
}

/// FR-49, A-241: with a cap of three requests per connection, the third
/// response carries `connection: close` and the connection ends after it.
#[test]
fn test_max_requests_per_connection_third_response_closes() {
    let server = Server::bind("127.0.0.1:0")
        .unwrap()
        .with_config(ServerConfig::new().with_max_requests_per_connection(Some(3)));
    let running = start(server, echo);
    let mut stream = connect(running.addr);
    let one = b"GET /n HTTP/1.1\r\nHost: x\r\n\r\n";
    stream.write_all(&one.repeat(4)).unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).unwrap();
    let text = String::from_utf8_lossy(&reply);
    assert_eq!(text.matches("HTTP/1.1 200 OK").count(), 3, "{text}");
    assert_eq!(text.matches("connection: close").count(), 1, "{text}");
    let third = text.rfind("HTTP/1.1 200 OK").unwrap();
    assert!(text[third..].contains("connection: close"), "{text}");
}

/// FR-26, FR-57: an expectation other than `100-continue` is answered 417
/// before the body is read, without a `100 Continue`, and the connection
/// closes (RFC 9110 section 10.1.1).
#[test]
fn test_unknown_expectation_gets_417_without_reading_the_body() {
    let running = start(Server::bind("127.0.0.1:0").unwrap(), echo);
    let mut stream = connect(running.addr);
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    // The body is never sent: a server waiting for it would time out.
    stream
        .write_all(
            b"POST /echo HTTP/1.1\r\nHost: x\r\nExpect: x-unknown\r\nContent-Length: 5\r\n\r\n",
        )
        .unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).unwrap();
    let text = String::from_utf8_lossy(&reply);
    assert!(
        text.starts_with("HTTP/1.1 417 Expectation Failed\r\n"),
        "{text}"
    );
    assert!(!text.contains("100 Continue"), "{text}");
    assert!(text.contains("connection: close"), "{text}");
}

/// FR-34, A-247: `Connection::send_informational` writes a `103` before
/// the final response.
#[test]
fn test_connection_send_informational_writes_103_first() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let client = thread::spawn(move || {
        let mut s = connect(addr);
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut reply = Vec::new();
        s.read_to_end(&mut reply).unwrap();
        reply
    });
    let (stream, _) = listener.accept().unwrap();
    let mut conn = Connection::new(stream, Limits::new());
    assert!(conn.next_request().unwrap().is_some());
    conn.send_informational(&Response::new(103).header("link", "</a.css>; rel=preload"))
        .unwrap();
    conn.respond(&Response::text(200, "page")).unwrap();
    conn.close();
    let reply = client.join().unwrap();
    let text = String::from_utf8_lossy(&reply);
    assert!(
        text.starts_with(
            "HTTP/1.1 103 Early Hints\r\nlink: </a.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\n"
        ),
        "{text}"
    );
    assert!(text.ends_with("\r\n\r\npage"), "{text}");
}

/// FR-58, A-252: `Client::request` sends any method and body; the URL gives
/// the target and `host`.
#[test]
fn test_client_request_post_with_a_body_reaches_the_handler() {
    let running = start(Server::bind("127.0.0.1:0").unwrap(), echo);
    let request = Request::post("/")
        .header("content-type", "application/octet-stream")
        .body(&b"payload"[..]);
    let resp = blocking::Client::new()
        .request(&format!("http://{}/echo", running.addr), request)
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body(), b"payload");

    let resp = blocking::Client::new()
        .request(
            &format!("http://{}/x?y", running.addr),
            Request::delete("/"),
        )
        .unwrap();
    assert_eq!(resp.text(), Some("DELETE /x"));
}

/// A-255: the Tier-1 `post`.
#[test]
fn test_post_sends_the_body_and_content_type() {
    let running = start(Server::bind("127.0.0.1:0").unwrap(), |req, body| {
        let ct = req.header_str("content-type").unwrap_or("");
        Response::text(200, &format!("{ct} {}", body.len()))
    });
    let resp = blocking::post(
        &format!("http://{}/notes", running.addr),
        "text/plain",
        b"hello",
    )
    .unwrap();
    assert_eq!(resp.text(), Some("text/plain 5"));
}

/// FR-58, A-253: the total deadline stops a client waiting on a server that
/// accepts and never answers, well before the per-operation timeout.
#[test]
fn test_client_deadline_silent_server_times_out() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let holder = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        thread::sleep(Duration::from_secs(3));
        drop(stream);
    });
    let started = Instant::now();
    let err = blocking::Client::new()
        .with_timeout(Duration::from_secs(10))
        .with_deadline(Some(Duration::from_millis(500)))
        .get(&format!("http://{addr}/"))
        .unwrap_err();
    let waited = started.elapsed();
    assert!(
        matches!(&err, blocking::Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut),
        "{err}"
    );
    assert!(waited < Duration::from_secs(2), "waited {waited:?}");
    holder.join().unwrap();
}

fn large(req: &RequestHead<'_>, _body: &[u8]) -> Response {
    // Over the 4 KiB threshold: the head and this body leave in one
    // vectored write; a small body is copied after the head as before.
    let size = if req.path() == "/large" { 300_000 } else { 100 };
    let body: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    Response::new(200).body(body)
}

#[test]
fn test_large_full_body_is_written_with_the_head_and_keeps_alive() {
    let running = start(Server::bind("127.0.0.1:0").unwrap(), large);
    let mut stream = connect(running.addr);
    let mut conn = ClientConn::new();
    let expected = |size: usize| (0..size).map(|i| (i % 251) as u8).collect::<Vec<u8>>();
    for (method, path, size) in [
        ("GET", "/large", 300_000),
        ("HEAD", "/large", 0),
        ("GET", "/small", 100),
        ("GET", "/large", 300_000),
    ] {
        let mut out = Vec::new();
        conn.send_request(&Request::new(method, path).header("host", "x"), &mut out)
            .unwrap();
        stream.write_all(&out).unwrap();
        let (status, body, close) = read_response(&mut stream, &mut conn);
        assert_eq!((status, close), (200, false), "{method} {path}");
        assert_eq!(body, expected(size), "{method} {path}");
        assert!(matches!(conn.poll().unwrap(), ClientEvent::Idle));
    }
}
