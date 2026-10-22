//! Allocation proofs, with a counting global allocator.
//!
//! The core claims that steady-state parsing allocates nothing (the input
//! buffer and the field index are reused across requests) and that memory
//! per connection is bounded by `Limits`, never by input. Both claims are
//! checked here by counting every allocation the test thread makes while a
//! measurement is running. The counters are per thread, so
//! allocations made by the test harness on other threads are not counted.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use http_net::{
    Asked, BodyPlan, ChunkStep, ChunkedDecoder, ClientConn, ClientEvent, FieldSpan, HttpDate,
    HttpError, Limits, OutgoingBody, Parsed, Request, Response, ResponseHeadRef, ServerConn,
    ServerEvent, parse_request_head, parse_response_head,
};

struct Counting;

/// Per-thread counters: tests run in parallel threads, and each measures
/// only its own allocations.
struct Counters {
    measuring: Cell<bool>,
    allocations: Cell<usize>,
    live: Cell<usize>,
    peak: Cell<usize>,
}

thread_local! {
    static COUNTERS: Counters = const {
        Counters {
            measuring: Cell::new(false),
            allocations: Cell::new(0),
            live: Cell::new(0),
            peak: Cell::new(0),
        }
    };
}

/// Records an allocation (or growth) of `grown` bytes and a release of
/// `shrunk` bytes, if this thread is measuring.
fn record(new_allocation: bool, grown: usize, shrunk: usize) {
    let _ = COUNTERS.try_with(|c| {
        if !c.measuring.get() {
            return;
        }
        if new_allocation {
            c.allocations.set(c.allocations.get() + 1);
        }
        // Frees of memory allocated before the measurement started are not
        // counted against it, so saturate rather than wrap.
        let live = (c.live.get() + grown).saturating_sub(shrunk);
        c.live.set(live);
        c.peak.set(c.peak.get().max(live));
    });
}

// SAFETY: every method forwards to `System` with the caller's arguments
// unchanged; the counters have no effect on the memory returned.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(true, layout.size(), 0);
        // SAFETY: forwarded unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(true, layout.size(), 0);
        // SAFETY: forwarded unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        record(false, 0, layout.size());
        // SAFETY: forwarded unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record(true, new_size, layout.size());
        // SAFETY: forwarded unchanged.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// What one measurement saw.
#[derive(Debug)]
struct Measured {
    allocations: usize,
    peak_bytes: usize,
}

/// Runs `f` with counting switched on for this thread.
fn measure<T>(f: impl FnOnce() -> T) -> (T, Measured) {
    COUNTERS.with(|c| {
        c.allocations.set(0);
        c.live.set(0);
        c.peak.set(0);
        c.measuring.set(true);
    });
    let value = f();
    let measured = COUNTERS.with(|c| {
        c.measuring.set(false);
        Measured {
            allocations: c.allocations.get(),
            peak_bytes: c.peak.get(),
        }
    });
    (value, measured)
}

#[test]
fn test_counter_sees_allocations_so_zero_is_not_vacuous() {
    let (v, m) = measure(|| {
        let mut conn = ServerConn::new();
        let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        let n = conn.poll().is_ok();
        (n, std::hint::black_box(Vec::<u8>::with_capacity(64)))
    });
    assert!(v.0);
    // At least the buffer, the field index, and the vector above.
    assert!(m.allocations >= 3, "{m:?}");
    assert!(m.peak_bytes >= 4096 + 64, "{m:?}");
}

/// The most the field index can hold: `max_headers` records of 16 bytes,
/// rounded up to the doubling growth of a `Vec`.
fn field_index_bytes(limits: &Limits) -> usize {
    limits.max_headers().next_power_of_two() * 16
}

/// A browser GET with twelve fields.
const BROWSER_GET: &[u8] = b"GET /assets/app.js?v=3 HTTP/1.1\r\n\
Host: app.example.com\r\n\
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36\r\n\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
Accept-Language: en-US,en;q=0.9\r\n\
Accept-Encoding: gzip, deflate, br\r\n\
Referer: https://app.example.com/\r\n\
Cookie: sid=0123456789abcdef; theme=dark\r\n\
Connection: keep-alive\r\n\
Sec-Fetch-Dest: script\r\n\
Sec-Fetch-Mode: no-cors\r\n\
Sec-Fetch-Site: same-origin\r\n\
Cache-Control: no-cache\r\n\r\n";

const POST_LENGTH: &[u8] =
    b"POST /api/notes HTTP/1.1\r\nHost: app.example.com\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nhello world";

const POST_CHUNKED: &[u8] = b"POST /api/upload HTTP/1.1\r\nHost: app.example.com\r\nTransfer-Encoding: chunked\r\n\r\n5;name=a\r\nhello\r\n6\r\n world\r\n0\r\nX-Checksum: 42\r\n\r\n";

/// Feeds one whole request and answers it. Allocation-free on its own: the
/// assertions only format on failure.
fn serve_one(conn: &mut ServerConn, request: &[u8], response: &Response, out: &mut Vec<u8>) {
    let mut fed = 0;
    let mut body = 0usize;
    loop {
        match conn.poll() {
            Ok(ServerEvent::NeedInput) => {
                assert!(
                    fed < request.len(),
                    "server wants input after a whole request"
                );
                fed += conn.feed(&request[fed..]);
            }
            Ok(ServerEvent::Request(_)) => {}
            Ok(ServerEvent::Body(b)) => body += b.len(),
            Ok(ServerEvent::RequestEnd) => {
                out.clear();
                conn.respond(response, out).expect("respond");
                assert!(fed == request.len() && body <= request.len());
                return;
            }
            Ok(other) => panic!("unexpected server event {other:?}"),
            Err(e) => panic!("server refused a valid request: {e:?}"),
        }
    }
}

#[test]
fn test_server_keep_alive_steady_state_allocates_nothing() {
    let mut conn = ServerConn::new();
    let response = Response::text(200, "ok").header("cache-control", "no-store");
    let mut out = Vec::with_capacity(4096);
    let requests = [BROWSER_GET, POST_LENGTH, POST_CHUNKED];

    // Warm-up: the buffer and the field index grow to their working size.
    for _ in 0..64 {
        for request in requests {
            serve_one(&mut conn, request, &response, &mut out);
        }
    }

    let ((), m) = measure(|| {
        for i in 0..10_000 {
            serve_one(&mut conn, requests[i % requests.len()], &response, &mut out);
        }
    });
    assert_eq!(
        m.allocations, 0,
        "10,000 keep-alive requests allocated {m:?}"
    );
}

#[test]
fn test_server_pipelined_steady_state_allocates_nothing() {
    // Three requests in one read: pipelined input waits in the same buffer.
    let mut batch = Vec::new();
    batch.extend_from_slice(BROWSER_GET);
    batch.extend_from_slice(POST_LENGTH);
    batch.extend_from_slice(POST_CHUNKED);
    let mut conn = ServerConn::new();
    let response = Response::new(204);
    let mut out = Vec::with_capacity(4096);

    let run = |conn: &mut ServerConn, out: &mut Vec<u8>| {
        let mut fed = 0;
        let mut served = 0;
        while served < 3 {
            match conn.poll() {
                Ok(ServerEvent::NeedInput) => {
                    assert!(fed < batch.len(), "server wants input after the batch");
                    fed += conn.feed(&batch[fed..]);
                }
                Ok(ServerEvent::Request(_) | ServerEvent::Body(_)) => {}
                Ok(ServerEvent::RequestEnd) => {
                    out.clear();
                    conn.respond(&response, out).expect("respond");
                    served += 1;
                }
                Ok(other) => panic!("unexpected server event {other:?}"),
                Err(e) => panic!("server refused a valid request: {e:?}"),
            }
        }
    };
    for _ in 0..64 {
        run(&mut conn, &mut out);
    }
    let ((), m) = measure(|| {
        for _ in 0..3_334 {
            run(&mut conn, &mut out);
        }
    });
    assert_eq!(m.allocations, 0, "pipelined requests allocated {m:?}");
}

const RESPONSE_JSON: &[u8] = b"HTTP/1.1 200 OK\r\n\
Content-Type: application/json\r\n\
Cache-Control: private, max-age=0\r\n\
Set-Cookie: sid=0123456789abcdef; HttpOnly\r\n\
Date: Wed, 21 Oct 2026 07:28:00 GMT\r\n\
Content-Length: 27\r\n\r\n\
{\"ok\":true,\"items\":[1,2,3]}";

const RESPONSE_CHUNKED: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";

const RESPONSE_INTERIM_THEN_204: &[u8] =
    b"HTTP/1.1 103 Early Hints\r\nLink: </app.css>; rel=preload\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n";

fn fetch_one(conn: &mut ClientConn, request: &Request, response: &[u8], out: &mut Vec<u8>) {
    out.clear();
    conn.send_request(request, out).expect("send");
    let mut fed = 0;
    let mut ended = false;
    loop {
        match conn.poll() {
            Ok(ClientEvent::NeedInput) => {
                assert!(
                    fed < response.len(),
                    "client wants input after a whole response"
                );
                fed += conn.feed(&response[fed..]);
            }
            Ok(ClientEvent::Response(_) | ClientEvent::Body(_)) => {}
            Ok(ClientEvent::ResponseEnd) => ended = true,
            Ok(ClientEvent::Idle) => {
                assert!(ended && fed == response.len());
                return;
            }
            Ok(other) => panic!("unexpected client event {other:?}"),
            Err(e) => panic!("client refused a valid response: {e:?}"),
        }
    }
}

#[test]
fn test_client_keep_alive_steady_state_allocates_nothing() {
    let mut conn = ClientConn::new();
    let request = Request::get("/api/items")
        .header("host", "api.example.com")
        .header("accept", "application/json")
        .header("authorization", "Bearer abc.def.ghi");
    let mut out = Vec::with_capacity(4096);
    let responses = [RESPONSE_JSON, RESPONSE_CHUNKED, RESPONSE_INTERIM_THEN_204];

    for _ in 0..64 {
        for response in responses {
            fetch_one(&mut conn, &request, response, &mut out);
        }
    }
    let ((), m) = measure(|| {
        for i in 0..10_000 {
            fetch_one(
                &mut conn,
                &request,
                responses[i % responses.len()],
                &mut out,
            );
        }
    });
    assert_eq!(
        m.allocations, 0,
        "10,000 keep-alive responses allocated {m:?}"
    );
}

/// Feeds `total` bytes of `head` followed by `filler` repeated, in 16 KiB
/// reads, to a connection created inside the measurement. Returns the error
/// the stream ended with (`None` if it was all accepted) and the peak bytes.
fn hostile_stream(
    limits: Limits,
    head: &[u8],
    filler: &[u8],
    total: usize,
) -> (Option<HttpError>, Measured) {
    // The read buffer is prepared before measuring, so only the connection's
    // own memory is counted.
    let mut read = Vec::with_capacity(16 * 1024 + filler.len());
    measure(|| {
        let mut conn = ServerConn::with_limits(limits);
        let mut sent = 0usize;
        let mut head_left = head;
        // Bytes of `read` not yet taken by the connection.
        let mut pending = 0..0;
        loop {
            match conn.poll() {
                Ok(ServerEvent::NeedInput) => {
                    if pending.is_empty() {
                        if sent >= total {
                            return None;
                        }
                        read.clear();
                        let take = head_left.len().min(16 * 1024);
                        read.extend_from_slice(&head_left[..take]);
                        head_left = &head_left[take..];
                        while read.len() + filler.len() <= 16 * 1024 {
                            read.extend_from_slice(filler);
                        }
                        pending = 0..read.len();
                    }
                    let n = conn.feed(&read[pending.clone()]);
                    assert!(n > 0, "buffer full while the parser waits for input");
                    pending.start += n;
                    sent += n;
                }
                Ok(ServerEvent::Request(_) | ServerEvent::Body(_)) => {}
                Ok(other) => panic!("unexpected server event {other:?}"),
                Err(e) => return Some(e),
            }
        }
    })
}

const TEN_MIB: usize = 10 * 1024 * 1024;

fn assert_bounded(limits: &Limits, m: &Measured) {
    // The bound: the buffer's hard capacity (`2 * (start line + header
    // bytes) + 16 KiB`), the field index, and a small
    // constant for the connection's other state (scanners, decoder).
    let bound = limits.buffer_capacity() + field_index_bytes(limits) + 4096;
    assert!(
        m.peak_bytes <= bound,
        "peak {} bytes over the bound {bound} ({m:?})",
        m.peak_bytes
    );
}

#[test]
fn test_endless_header_lines_stay_bounded_and_end_headers_too_large() {
    let limits = Limits::new();
    let line = [b"X-Filler: ".as_slice(), &[b'a'; 188], b"\r\n"].concat();
    let (err, m) = hostile_stream(limits, b"GET / HTTP/1.1\r\nHost: a\r\n", &line, TEN_MIB);
    assert_eq!(err, Some(HttpError::HeadersTooLarge));
    assert_bounded(&limits, &m);
}

#[test]
fn test_endless_start_line_stays_bounded_and_ends_start_line_too_long() {
    let limits = Limits::new();
    let (err, m) = hostile_stream(limits, b"GET /", b"aaaaaaaaaaaaaaaa", TEN_MIB);
    assert_eq!(err, Some(HttpError::StartLineTooLong));
    assert_bounded(&limits, &m);
}

#[test]
fn test_endless_chunk_extensions_stay_bounded_and_end_extensions_too_large() {
    let limits = Limits::new();
    let chunk = [b"1;".as_slice(), &[b'e'; 100], b"=v\r\nx\r\n"].concat();
    let (err, m) = hostile_stream(
        limits,
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n",
        &chunk,
        TEN_MIB,
    );
    assert_eq!(err, Some(HttpError::ChunkExtensionsTooLarge));
    assert_bounded(&limits, &m);
}

#[test]
fn test_huge_declared_body_is_refused_on_the_header_line() {
    let limits = Limits::new();
    let (err, m) = hostile_stream(
        limits,
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 10995116277760\r\n\r\n",
        b"zzzzzzzzzzzzzzzz",
        TEN_MIB,
    );
    assert_eq!(err, Some(HttpError::BodyTooLarge));
    assert_bounded(&limits, &m);
}

#[test]
fn test_huge_allowed_body_streams_ten_mib_without_growth() {
    // With an unlimited body budget the 10 MiB stream is accepted as body
    // events; memory still stays at the buffer's capacity.
    let limits = Limits::new().with_max_body(u64::MAX);
    let (err, m) = hostile_stream(
        limits,
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 10995116277760\r\n\r\n",
        b"zzzzzzzzzzzzzzzz",
        TEN_MIB,
    );
    assert_eq!(err, None);
    assert_bounded(&limits, &m);
}

#[test]
fn test_endless_chunks_stay_bounded_under_a_large_body_budget() {
    let limits = Limits::new().with_max_body(u64::MAX);
    let (err, m) = hostile_stream(
        limits,
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"10\r\n0123456789abcdef\r\n",
        TEN_MIB,
    );
    assert_eq!(err, None);
    assert_bounded(&limits, &m);
}

const POST_TRAILERS: &[u8] = b"POST /api/upload HTTP/1.1\r\nHost: app.example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nContent-Digest: sha-256=:x:\r\nX-Rows: 1\r\n\r\n";

/// NFR-4 with trailers reported (FR-19): the trailer index is reused like
/// the field index, so 10,000 requests with trailers allocate nothing after
/// warm-up.
#[test]
fn test_server_reported_trailers_steady_state_allocates_nothing() {
    let mut conn = ServerConn::new();
    conn.set_report_trailers(true);
    let response = Response::new(204);
    let mut out = Vec::with_capacity(4096);
    let mut run = |conn: &mut ServerConn| {
        let mut fed = 0;
        let mut trailers = 0;
        loop {
            match conn.poll() {
                Ok(ServerEvent::NeedInput) => {
                    assert!(
                        fed < POST_TRAILERS.len(),
                        "server wants input after the request"
                    );
                    fed += conn.feed(&POST_TRAILERS[fed..]);
                }
                Ok(ServerEvent::Request(_) | ServerEvent::Body(_)) => {}
                Ok(ServerEvent::Trailers(t)) => trailers += t.len(),
                Ok(ServerEvent::RequestEnd) => {
                    out.clear();
                    conn.respond(&response, &mut out).expect("respond");
                    assert!(trailers == 2, "trailers not reported");
                    return;
                }
                Ok(other) => panic!("unexpected server event {other:?}"),
                Err(e) => panic!("server refused a valid request: {e:?}"),
            }
        }
    };
    for _ in 0..64 {
        run(&mut conn);
    }
    let ((), m) = measure(|| {
        for _ in 0..10_000 {
            run(&mut conn);
        }
    });
    assert_eq!(m.allocations, 0, "requests with trailers allocated {m:?}");
}

/// The Tier-3 writer (A-210): a head of five borrowed fields written into a
/// reused `Vec` allocates nothing, request after request.
#[test]
fn test_write_head_into_reused_vec_allocates_nothing() {
    let mut conn = ServerConn::new();
    let fields: [(&str, &[u8]); 5] = [
        ("content-type", b"application/json"),
        ("cache-control", b"no-store"),
        ("server", b"http-net"),
        ("x-request-id", b"0123456789abcdef"),
        ("vary", b"accept-encoding"),
    ];
    let head = ResponseHeadRef::new(200, &fields, OutgoingBody::Full(13));
    let date = HttpDate::from_unix_seconds(1_700_000_000);
    let mut out = Vec::with_capacity(4096);
    let mut run = |conn: &mut ServerConn| {
        let mut fed = 0;
        loop {
            match conn.poll() {
                Ok(ServerEvent::NeedInput) => {
                    assert!(fed < BROWSER_GET.len(), "server wants more input");
                    fed += conn.feed(&BROWSER_GET[fed..]);
                }
                Ok(ServerEvent::Request(_)) => {}
                Ok(ServerEvent::RequestEnd) => {
                    out.clear();
                    let plan = conn.write_head(&head, Some(&date), &mut out);
                    assert!(plan == Ok(BodyPlan::Raw), "write_head failed");
                    out.extend_from_slice(b"{\"ok\":true}\r\n");
                    return;
                }
                Ok(other) => panic!("unexpected server event {other:?}"),
                Err(e) => panic!("server refused a valid request: {e:?}"),
            }
        }
    };
    for _ in 0..64 {
        run(&mut conn);
    }
    let ((), m) = measure(|| {
        for _ in 0..10_000 {
            run(&mut conn);
        }
    });
    assert_eq!(m.allocations, 0, "write_head allocated {m:?}");
}

/// A-224: writing only the head of a prebuilt full-body response, for a
/// vectored send, allocates nothing and never copies the body.
#[test]
fn test_respond_head_only_allocates_nothing() {
    let mut conn = ServerConn::new();
    let response = Response::new(200)
        .header("content-type", "application/octet-stream")
        .body(vec![b'x'; 64 * 1024]);
    let mut out = Vec::with_capacity(4096);
    let mut run = |conn: &mut ServerConn| {
        let mut fed = 0;
        loop {
            match conn.poll() {
                Ok(ServerEvent::NeedInput) => fed += conn.feed(&BROWSER_GET[fed..]),
                Ok(ServerEvent::Request(_)) => {}
                Ok(ServerEvent::RequestEnd) => {
                    out.clear();
                    let plan = conn.respond_head_only(&response, &mut out);
                    assert!(plan == Ok(BodyPlan::Raw), "respond_head_only failed");
                    assert!(out.len() < 4096, "the body was copied");
                    return;
                }
                Ok(other) => panic!("unexpected server event {other:?}"),
                Err(e) => panic!("server refused a valid request: {e:?}"),
            }
        }
    };
    for _ in 0..64 {
        run(&mut conn);
    }
    let ((), m) = measure(|| {
        for _ in 0..10_000 {
            run(&mut conn);
        }
    });
    assert_eq!(m.allocations, 0, "respond_head_only allocated {m:?}");
}

/// The standalone decoder (A-220): building one and decoding a body with
/// extensions and trailers allocates nothing, the decoder included.
#[test]
fn test_chunked_decoder_allocates_nothing() {
    const WIRE: &[u8] =
        b"5;name=a\r\nhello\r\n6\r\n world\r\n0\r\nX-Checksum: 42\r\nX-Trace: 1\r\n\r\nNEXT";
    let limits = Limits::new();
    let ((), m) = measure(|| {
        for _ in 0..10_000 {
            let mut decoder = ChunkedDecoder::new(&limits);
            let (mut pos, mut body) = (0, 0);
            loop {
                match decoder.decode(&WIRE[pos..], false) {
                    Ok(ChunkStep::Data { skip, len }) => {
                        body += len;
                        pos += skip + len;
                    }
                    Ok(ChunkStep::Trailers { skip, len }) => pos += skip + len,
                    Ok(ChunkStep::Done { consumed }) => {
                        pos += consumed;
                        break;
                    }
                    Ok(other) => panic!("unexpected step {other:?}"),
                    Err(e) => panic!("decoder refused a valid body: {e:?}"),
                }
            }
            assert!(body == 11 && &WIRE[pos..] == b"NEXT");
        }
    });
    assert_eq!(m.allocations, 0, "ChunkedDecoder allocated {m:?}");
}

const RESPONSE_HINTS_TRAILERS: &[u8] = b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </b.js>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nServer-Timing: db;dur=5\r\n\r\n";

/// NFR-4 on the client with interim responses and trailers reported
/// (FR-39, FR-19): nothing is allocated per response after warm-up.
#[test]
fn test_client_reported_interim_and_trailers_steady_state_allocates_nothing() {
    let mut conn = ClientConn::new();
    conn.set_report_informational(true);
    conn.set_report_trailers(true);
    let request = Request::get("/page").header("host", "app.example.com");
    let mut out = Vec::with_capacity(4096);
    let mut run = |conn: &mut ClientConn| {
        out.clear();
        conn.send_request(&request, &mut out).expect("send");
        let mut fed = 0;
        let (mut hints, mut trailers, mut ended) = (0, 0, false);
        loop {
            match conn.poll() {
                Ok(ClientEvent::NeedInput) => {
                    assert!(
                        fed < RESPONSE_HINTS_TRAILERS.len(),
                        "client wants more input"
                    );
                    fed += conn.feed(&RESPONSE_HINTS_TRAILERS[fed..]);
                }
                Ok(ClientEvent::Informational(_)) => hints += 1,
                Ok(ClientEvent::Trailers(t)) => trailers += t.len(),
                Ok(ClientEvent::Response(_) | ClientEvent::Body(_)) => {}
                Ok(ClientEvent::ResponseEnd) => ended = true,
                Ok(ClientEvent::Idle) => {
                    assert!(ended && hints == 2 && trailers == 1);
                    return;
                }
                Ok(other) => panic!("unexpected client event {other:?}"),
                Err(e) => panic!("client refused a valid response: {e:?}"),
            }
        }
    };
    for _ in 0..64 {
        run(&mut conn);
    }
    let ((), m) = measure(|| {
        for _ in 0..10_000 {
            run(&mut conn);
        }
    });
    assert_eq!(
        m.allocations, 0,
        "responses with hints and trailers allocated {m:?}"
    );
}

/// FR-42: the pipelining queue is a fixed array, so eight requests in
/// flight at a time allocate nothing after warm-up.
#[test]
fn test_client_pipelined_steady_state_allocates_nothing() {
    let mut conn = ClientConn::with_limits(Limits::new().with_pipeline_depth(8));
    let request = Request::get("/api/items").header("host", "api.example.com");
    let mut out = Vec::with_capacity(8 * 64);
    let wire = RESPONSE_JSON.repeat(8);
    let round = |conn: &mut ClientConn, out: &mut Vec<u8>| {
        out.clear();
        for _ in 0..8 {
            conn.send_request(&request, out).expect("send");
        }
        let mut fed = 0;
        let mut ended = 0;
        loop {
            match conn.poll() {
                Ok(ClientEvent::NeedInput) => fed += conn.feed(&wire[fed..]),
                Ok(ClientEvent::ResponseEnd) => ended += 1,
                Ok(ClientEvent::Idle) => break,
                Ok(_) => {}
                Err(e) => panic!("{e:?}"),
            }
        }
        assert_eq!(ended, 8);
    };
    for _ in 0..16 {
        round(&mut conn, &mut out);
    }
    let ((), m) = measure(|| {
        for _ in 0..1250 {
            round(&mut conn, &mut out);
        }
    });
    assert_eq!(
        m.allocations, 0,
        "10,000 pipelined responses allocated {m:?}"
    );
}

/// FR-59: wiping consumed input costs a memset, never an allocation.
#[test]
fn test_server_wipe_steady_state_allocates_nothing() {
    let mut conn = ServerConn::new();
    conn.set_wipe(true);
    let response = Response::new(204);
    let mut out = Vec::with_capacity(4096);
    for _ in 0..64 {
        serve_one(&mut conn, BROWSER_GET, &response, &mut out);
    }
    let ((), m) = measure(|| {
        for _ in 0..10_000 {
            serve_one(&mut conn, BROWSER_GET, &response, &mut out);
        }
    });
    assert_eq!(m.allocations, 0, "10,000 wiped requests allocated {m:?}");
}

/// FR-48: a connection reset for a new peer keeps its allocations.
#[test]
fn test_server_reset_reuse_allocates_nothing() {
    let mut conn = ServerConn::new();
    let response = Response::new(204);
    let mut out = Vec::with_capacity(4096);
    serve_one(&mut conn, BROWSER_GET, &response, &mut out);
    conn.reset();
    serve_one(&mut conn, BROWSER_GET, &response, &mut out);
    let ((), m) = measure(|| {
        for _ in 0..1000 {
            conn.reset();
            serve_one(&mut conn, BROWSER_GET, &response, &mut out);
        }
    });
    assert_eq!(m.allocations, 0, "1,000 reset connections allocated {m:?}");
}

/// NFR-5: the stateless parsers allocate nothing at all, not even on the
/// first call: the field records go into the caller's array.
#[test]
fn test_stateless_parsers_allocate_nothing_ever() {
    let limits = Limits::new();
    let mut fields = [FieldSpan::default(); 32];
    let ((), m) = measure(|| {
        for _ in 0..10_000 {
            for request in [BROWSER_GET, POST_LENGTH, POST_CHUNKED] {
                let parsed = parse_request_head(request, &limits, &mut fields);
                assert!(matches!(parsed, Ok(Parsed::Complete { .. })));
            }
            let parsed =
                parse_request_head(b"GET / HTTP/1.1\r\nHost: a\r\nX: 1", &limits, &mut fields);
            assert!(matches!(parsed, Ok(Parsed::Partial)));
            let refused = parse_request_head(b"GET / HTTP/1.1\r\n\r\n", &limits, &mut fields);
            assert_eq!(refused.err(), Some(HttpError::MissingHost));
            let response =
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok";
            let parsed = parse_response_head(response, &limits, Asked::default(), &mut fields);
            assert!(matches!(parsed, Ok(Parsed::Complete { .. })));
        }
    });
    assert_eq!(m.allocations, 0, "stateless parsing allocated {m:?}");
}

/// FR-43: copying heads out into a passport's reused vectors allocates
/// nothing once the vectors have grown to the largest head.
#[test]
fn test_copy_into_reused_vectors_allocates_nothing() {
    let mut conn = ServerConn::new();
    let response = Response::new(204);
    let mut out = Vec::with_capacity(4096);
    let mut bytes = Vec::new();
    let mut fields: Vec<FieldSpan> = Vec::new();
    let mut copy_one = |conn: &mut ServerConn, out: &mut Vec<u8>, request: &[u8]| {
        let mut fed = conn.feed(request);
        loop {
            match conn.poll() {
                Ok(ServerEvent::Request(head)) => {
                    let facts = head.copy_into(&mut bytes, &mut fields);
                    assert!(facts.is_ok());
                }
                Ok(ServerEvent::NeedInput) => fed += conn.feed(&request[fed..]),
                Ok(ServerEvent::Body(_)) => {}
                Ok(ServerEvent::RequestEnd) => {
                    out.clear();
                    assert!(conn.respond(&response, out).is_ok());
                    return;
                }
                other => panic!("unexpected {other:?}"),
            }
        }
    };
    for _ in 0..64 {
        for request in [BROWSER_GET, POST_LENGTH, POST_CHUNKED] {
            copy_one(&mut conn, &mut out, request);
        }
    }
    let ((), m) = measure(|| {
        for _ in 0..10_000 {
            for request in [BROWSER_GET, POST_LENGTH, POST_CHUNKED] {
                copy_one(&mut conn, &mut out, request);
            }
        }
    });
    assert_eq!(m.allocations, 0, "copying heads out allocated {m:?}");
}
