//! Criterion benchmarks for the sans-IO core at realistic scale.
//!
//! - `request_head`: one browser-like GET (12 fields, ~500 bytes) parsed
//!   and answered on a reused connection.
//! - `pipelined_100k`: 100,000 small requests in 16 KiB reads.
//! - `body_1mib`: a 1 MiB body, `Content-Length` and chunked (4 KiB
//!   chunks), fed in 16 KiB reads.
//! - `response_write`: serializing a response with five fields and a
//!   1 KiB body, with `respond` and with `write_head` (borrowed fields).
//! - `response_parse`: a client parsing a response with a 1 KiB body.
//! - `linearity`: 4, 16, and 32 KiB heads fed whole and one byte at a time.

use std::hint::black_box;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use http_net::{
    BodyPlan, ClientConn, ClientEvent, Limits, OutgoingBody, Request, Response, ResponseHeadRef,
    ServerConn, ServerEvent,
};

const BROWSER_GET: &[u8] = b"GET /assets/app.3f9a1c.js?v=2 HTTP/1.1\r\n\
Host: 127.0.0.1:53817\r\n\
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36\r\n\
Accept: */*\r\n\
Accept-Encoding: gzip, deflate, br, zstd\r\n\
Accept-Language: en-US,en;q=0.9\r\n\
Cache-Control: no-cache\r\n\
Connection: keep-alive\r\n\
Pragma: no-cache\r\n\
Referer: http://127.0.0.1:53817/\r\n\
Sec-Fetch-Dest: script\r\n\
Sec-Fetch-Mode: no-cors\r\n\
Sec-Fetch-Site: same-origin\r\n\r\n";

/// Drives a server connection over `input` in `read`-sized pieces,
/// answering every request with `response`. Returns the request count.
fn serve_all(conn: &mut ServerConn, input: &[u8], read: usize, response: &Response) -> usize {
    let mut out = Vec::with_capacity(256);
    let mut pending = input;
    let mut requests = 0;
    loop {
        match conn.poll() {
            Ok(ServerEvent::Request(r)) => {
                black_box(r.path());
            }
            Ok(ServerEvent::Body(b)) => {
                black_box(b);
            }
            Ok(ServerEvent::RequestEnd) => {
                requests += 1;
                out.clear();
                conn.respond(response, &mut out).unwrap_or_default();
            }
            Ok(ServerEvent::NeedInput) => {
                if pending.is_empty() {
                    return requests;
                }
                let take = pending.len().min(read);
                let n = conn.feed(&pending[..take]);
                pending = &pending[n..];
            }
            _ => return requests,
        }
    }
}

fn bench_request_head(c: &mut Criterion) {
    let mut group = c.benchmark_group("request_head");
    group.throughput(Throughput::Bytes(BROWSER_GET.len() as u64));
    let response = Response::new(204);
    let mut conn = ServerConn::new();
    group.bench_function("browser_get", |b| {
        b.iter(|| serve_all(&mut conn, black_box(BROWSER_GET), 16 * 1024, &response))
    });
    group.finish();
}

fn bench_pipelined(c: &mut Criterion) {
    let one = b"GET /item/42 HTTP/1.1\r\nHost: a\r\nAccept: */*\r\n\r\n";
    let input = one.repeat(100_000);
    let response = Response::new(204);
    let mut group = c.benchmark_group("pipelined_100k");
    group.sample_size(20);
    group.throughput(Throughput::Elements(100_000));
    group.bench_function("small_gets", |b| {
        b.iter_batched(
            ServerConn::new,
            |mut conn| assert_eq!(serve_all(&mut conn, &input, 16 * 1024, &response), 100_000),
            BatchSize::LargeInput,
        )
    });
    group.finish();
}

fn bench_body(c: &mut Criterion) {
    let body = vec![0x5au8; 1024 * 1024];
    let mut length = b"POST /up HTTP/1.1\r\nHost: a\r\nContent-Length: 1048576\r\n\r\n".to_vec();
    length.extend_from_slice(&body);
    let mut chunked =
        b"POST /up HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for piece in body.chunks(4096) {
        chunked.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        chunked.extend_from_slice(piece);
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    let response = Response::new(204);
    let limits = Limits::new().with_max_body(2 << 20);
    let mut group = c.benchmark_group("body_1mib");
    group.throughput(Throughput::Bytes(body.len() as u64));
    group.bench_function("content_length", |b| {
        b.iter_batched(
            || ServerConn::with_limits(limits),
            |mut conn| serve_all(&mut conn, &length, 16 * 1024, &response),
            BatchSize::SmallInput,
        )
    });
    group.bench_function("chunked_4k", |b| {
        b.iter_batched(
            || ServerConn::with_limits(limits),
            |mut conn| serve_all(&mut conn, &chunked, 16 * 1024, &response),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn bench_response_write(c: &mut Criterion) {
    let body: Vec<u8> = vec![b'x'; 1024];
    let response = Response::new(200)
        .header("content-type", "application/javascript")
        .header("cache-control", "max-age=31536000, immutable")
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "no-referrer")
        .header("cross-origin-resource-policy", "same-origin")
        .body(body);
    let mut group = c.benchmark_group("response_write");
    group.bench_function("five_fields_1k_body", |b| {
        let mut conn = ServerConn::new();
        let mut out = Vec::with_capacity(4096);
        b.iter(|| {
            let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
            while !matches!(conn.poll(), Ok(ServerEvent::RequestEnd)) {}
            out.clear();
            conn.respond(&response, &mut out).unwrap_or_default();
            black_box(out.len())
        })
    });
    // The same response through the Tier-3 writer: borrowed fields, the
    // body appended by the caller after a `Raw` plan.
    let body = vec![b'x'; 1024];
    let fields: [(&str, &[u8]); 5] = [
        ("content-type", b"application/javascript"),
        ("cache-control", b"max-age=31536000, immutable"),
        ("x-content-type-options", b"nosniff"),
        ("referrer-policy", b"no-referrer"),
        ("cross-origin-resource-policy", b"same-origin"),
    ];
    let head = ResponseHeadRef::new(200, &fields, OutgoingBody::Full(body.len() as u64));
    group.bench_function("write_head_five_fields_1k_body", |b| {
        let mut conn = ServerConn::new();
        let mut out = Vec::with_capacity(4096);
        b.iter(|| {
            let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
            while !matches!(conn.poll(), Ok(ServerEvent::RequestEnd)) {}
            out.clear();
            if conn.write_head(&head, None, &mut out) == Ok(BodyPlan::Raw) {
                out.extend_from_slice(&body);
            }
            black_box(out.len())
        })
    });
    // What `write_head` replaces when the fields change per response: a
    // `Response` built for each one (the body borrowed, so only the field
    // block allocates).
    static BODY: [u8; 1024] = [b'x'; 1024];
    group.bench_function("build_and_respond_five_fields_1k_body", |b| {
        let mut conn = ServerConn::new();
        let mut out = Vec::with_capacity(4096);
        b.iter(|| {
            let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
            while !matches!(conn.poll(), Ok(ServerEvent::RequestEnd)) {}
            out.clear();
            let mut response = Response::new(200);
            for (name, value) in fields {
                response = response.header(name, value);
            }
            conn.respond(&response.body(&BODY[..]), &mut out)
                .unwrap_or_default();
            black_box(out.len())
        })
    });
    group.finish();
}

fn bench_response_parse(c: &mut Criterion) {
    let mut wire = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nDate: Sun, 04 Oct 2026 00:00:00 GMT\r\nContent-Length: 1024\r\n\r\n".to_vec();
    wire.extend(std::iter::repeat_n(b'{', 1024));
    let request = Request::get("/api").header("host", "a");
    let mut group = c.benchmark_group("response_parse");
    group.throughput(Throughput::Bytes(wire.len() as u64));
    group.bench_function("json_1k", |b| {
        let mut conn = ClientConn::new();
        let mut out = Vec::with_capacity(256);
        b.iter(|| {
            out.clear();
            conn.send_request(&request, &mut out).unwrap_or_default();
            let _ = conn.feed(&wire);
            loop {
                match conn.poll() {
                    Ok(ClientEvent::Body(b)) => {
                        black_box(b);
                    }
                    Ok(ClientEvent::ResponseEnd) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            black_box(conn.poll().is_ok())
        })
    });
    group.finish();
}

/// A request head of about `size` bytes: the request line, `Host`, and
/// 60-byte fields.
fn large_head(size: usize) -> Vec<u8> {
    let mut head = b"GET /linear HTTP/1.1\r\nHost: a\r\n".to_vec();
    let mut i = 0;
    while head.len() + 64 < size {
        head.extend_from_slice(format!("X-Field-{i:04}: {:045}\r\n", i).as_bytes());
        i += 1;
    }
    head.extend_from_slice(b"\r\n");
    head
}

/// Parses `head` on `conn`, fed `step` bytes at a time.
fn parse_fed(conn: &mut ServerConn, head: &[u8], step: usize, response: &Response) {
    let mut fed = 0;
    let mut out = Vec::with_capacity(256);
    loop {
        match conn.poll() {
            Ok(ServerEvent::NeedInput) => {
                let end = (fed + step).min(head.len());
                fed += conn.feed(&head[fed..end]);
            }
            Ok(ServerEvent::RequestEnd) => {
                out.clear();
                conn.respond(response, &mut out).unwrap_or_default();
                return;
            }
            Ok(_) => {}
            Err(e) => panic!("{e:?}"),
        }
    }
}

/// The linearity guard (spec section 11.2): a head fed one byte at a time
/// costs a bounded multiple of the same head fed whole, at every size, so
/// the scanner never re-reads what it has seen.
fn bench_linearity(c: &mut Criterion) {
    let limits = Limits::new()
        .with_max_header_bytes(64 * 1024)
        .with_max_headers(1024);
    let response = Response::new(204);
    let mut group = c.benchmark_group("linearity");
    for size in [4 * 1024, 16 * 1024, 32 * 1024] {
        let head = large_head(size);
        group.throughput(Throughput::Bytes(head.len() as u64));
        let mut conn = ServerConn::with_limits(limits);
        group.bench_function(format!("whole_{}k", size / 1024), |b| {
            b.iter(|| parse_fed(&mut conn, black_box(&head), usize::MAX, &response))
        });
        let mut conn = ServerConn::with_limits(limits);
        group.bench_function(format!("byte_at_a_time_{}k", size / 1024), |b| {
            b.iter(|| parse_fed(&mut conn, black_box(&head), 1, &response))
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_request_head,
    bench_pipelined,
    bench_body,
    bench_response_write,
    bench_response_parse,
    bench_linearity
);
criterion_main!(benches);
