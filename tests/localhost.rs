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
