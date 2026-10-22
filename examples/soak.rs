//! A soak run of the blocking server: a local server and several client
//! threads exchanging a mixed workload for a set time, one status line per
//! minute. Memory must stay flat: on Linux each line includes the process's
//! resident set from `/proc/self/statm`; elsewhere sample the process from
//! outside (the crate forbids the `unsafe` a portable in-process query
//! would need).
//!
//! The workload covers every server path: keep-alive runs on one
//! connection, pipelined requests in one write, uploads with
//! `Content-Length` and chunked bodies, large full bodies (the vectored
//! path), streamed chunked responses, and malformed requests answered with
//! an error and a close.
//!
//! ```sh
//! cargo run --release --example soak -- 8h 8     # duration, client threads
//! cargo run --release --example soak -- 90s 4
//! ```

use std::{
    error::Error,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use http_net::{
    ClientConn, ClientEvent, Request, RequestHead, Response,
    blocking::{self, Server},
};

/// Exchanges and failures, counted by every client thread.
#[derive(Default)]
struct Counts {
    exchanges: AtomicU64,
    refused: AtomicU64,
    failures: AtomicU64,
}

fn handler(req: &RequestHead<'_>, body: &[u8]) -> Response {
    match req.path() {
        "/echo" => Response::new(200)
            .header("content-type", "application/octet-stream")
            .body(body.to_vec()),
        // Over the 4 KiB threshold: written after the head in one vectored
        // write.
        "/large" => Response::new(200).body(vec![b'L'; 96 * 1024]),
        "/small" => Response::text(200, "ok"),
        _ => Response::new(204),
    }
}

/// Reads one response with `conn` and waits until the connection is idle
/// again; returns the status and the body length.
fn read_response(
    stream: &mut TcpStream,
    conn: &mut ClientConn,
) -> Result<(u16, usize), Box<dyn Error>> {
    let (mut status, mut len) = (0, 0);
    loop {
        match conn.poll()? {
            ClientEvent::Response(head) => status = head.status(),
            ClientEvent::Body(chunk) => len += chunk.len(),
            ClientEvent::Idle | ClientEvent::Closed => return Ok((status, len)),
            ClientEvent::NeedInput => {
                let n = stream.read(conn.read_buf())?;
                if n == 0 {
                    conn.feed_eof();
                } else {
                    conn.commit(n);
                }
            }
            _ => {}
        }
    }
}

/// One round of the mixed workload; returns the exchanges it completed.
///
/// Most of the work runs on one keep-alive connection, so a round opens
/// only a few connections: on Windows a closed client connection holds its
/// port for up to four minutes (TIME_WAIT), and churning through
/// connections would exhaust the ports long before memory says anything.
fn round(addr: SocketAddr, seed: u64) -> Result<u64, Box<dyn Error>> {
    let mut done = 0;

    // Keep-alive: a long run of mixed requests on one connection.
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut conn = ClientConn::new();
    for i in 0..400u64 {
        let mut out = Vec::new();
        let size = ((seed.wrapping_mul(31) + i * 977) % 20_000) as usize;
        let (path, expected) = match (seed + i) % 16 {
            0 => {
                // A chunked upload, echoed back.
                conn.send_request(
                    &Request::post("/echo").header("host", "soak").chunked(),
                    &mut out,
                )?;
                for _ in 0..8 {
                    conn.send_body(&[b'c'; 3000], &mut out)?;
                }
                conn.end_body(&mut out)?;
                ("/echo chunked", Some(24_000))
            }
            1..=4 => {
                conn.send_request(&Request::get("/large").header("host", "soak"), &mut out)?;
                ("/large", Some(96 * 1024))
            }
            5..=8 => {
                let body = vec![b'p'; size];
                conn.send_request(
                    &Request::post("/echo").header("host", "soak").body(body),
                    &mut out,
                )?;
                ("/echo", Some(size))
            }
            9..=12 => {
                conn.send_request(&Request::get("/small").header("host", "soak"), &mut out)?;
                ("/small", Some(2))
            }
            _ => {
                conn.send_request(&Request::get("/none").header("host", "soak"), &mut out)?;
                ("/none", Some(0))
            }
        };
        stream.write_all(&out)?;
        let (status, len) = read_response(&mut stream, &mut conn)?;
        if !(200..300).contains(&status) || expected.is_some_and(|e| e != len) {
            return Err(format!("{path}: status {status}, {len} bytes").into());
        }
        done += 1;
    }
    drop(stream);

    // Pipelined: ten requests in one write, the last one closing.
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut burst = Vec::new();
    for i in 0..10 {
        let close = if i == 9 { "Connection: close\r\n" } else { "" };
        burst.extend_from_slice(
            format!("GET /small HTTP/1.1\r\nHost: soak\r\n{close}\r\n").as_bytes(),
        );
    }
    stream.write_all(&burst)?;
    let mut all = Vec::new();
    stream.read_to_end(&mut all)?;
    let answered = all.windows(15).filter(|w| w == b"HTTP/1.1 200 OK").count();
    if answered != 10 {
        return Err(format!("pipelined: {answered} of 10 answered").into());
    }
    done += 10;

    // Now and then, a one-shot request through the blocking client.
    if seed % 8 == 0 {
        let response = blocking::get(&format!("http://{addr}/small"))?;
        if response.status() != 200 {
            return Err(format!("blocking get: {}", response.status()).into());
        }
        done += 1;
    }

    Ok(done)
}

/// A malformed request: answered with an error status, then closed.
fn refused(addr: SocketAddr) -> Result<bool, Box<dyn Error>> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream
        .write_all(b"GET / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n")?;
    let mut all = Vec::new();
    stream.read_to_end(&mut all)?;
    Ok(all.starts_with(b"HTTP/1.1 400"))
}

/// Resident set in KiB (Linux), if the platform reports it.
fn rss_kib() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages * 4)
}

fn parse_duration(s: &str) -> Option<Duration> {
    let (n, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit())?);
    let n: u64 = n.parse().ok()?;
    Some(Duration::from_secs(match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        _ => return None,
    }))
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let duration = args
        .next()
        .and_then(|s| parse_duration(&s))
        .unwrap_or(Duration::from_secs(60));
    let clients: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(4);

    let server = Server::bind("127.0.0.1:0")?;
    let addr = server.local_addr();
    let stop = server.shutdown_handle();
    let serving = thread::spawn(move || server.serve(handler));

    let counts = Arc::new(Counts::default());
    let running = Arc::new(AtomicBool::new(true));
    let workers: Vec<_> = (0..clients)
        .map(|id| {
            let (counts, running) = (Arc::clone(&counts), Arc::clone(&running));
            thread::spawn(move || {
                let mut seed = id * 7919;
                while running.load(Ordering::Relaxed) {
                    match round(addr, seed) {
                        Ok(n) => {
                            counts.exchanges.fetch_add(n, Ordering::Relaxed);
                        }
                        Err(e) => {
                            eprintln!("client {id}: {e}");
                            counts.failures.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    if matches!(refused(addr), Ok(true)) {
                        counts.refused.fetch_add(1, Ordering::Relaxed);
                    } else {
                        counts.failures.fetch_add(1, Ordering::Relaxed);
                    }
                    seed += 1;
                    // Keeps connection churn under what TIME_WAIT can hold.
                    thread::sleep(Duration::from_millis(200));
                }
            })
        })
        .collect();

    println!("soak: {clients} clients for {duration:?} against http://{addr}/");
    let started = Instant::now();
    while started.elapsed() < duration {
        thread::sleep(Duration::from_secs(60).min(duration.saturating_sub(started.elapsed())));
        let rss = rss_kib().map_or_else(|| "n/a".to_string(), |k| format!("{k} KiB"));
        println!(
            "{:>6}s  exchanges {:>10}  refused {:>8}  failures {:>4}  rss {rss}",
            started.elapsed().as_secs(),
            counts.exchanges.load(Ordering::Relaxed),
            counts.refused.load(Ordering::Relaxed),
            counts.failures.load(Ordering::Relaxed),
        );
    }
    running.store(false, Ordering::Relaxed);
    for worker in workers {
        let _ = worker.join();
    }
    stop.shutdown();
    let _ = serving.join();
    let failures = counts.failures.load(Ordering::Relaxed);
    println!("soak: done, {failures} failures");
    if failures > 0 {
        return Err(format!("{failures} failures").into());
    }
    Ok(())
}
