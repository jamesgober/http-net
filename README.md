<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>http-net</b>
    <br>
    <sub><sup>HTTP/1.1, SANS-IO</sup></sub>
</h1>

<div align="center">
    <a href="https://crates.io/crates/http-net"><img alt="Crates.io" src="https://img.shields.io/crates/v/http-net"></a>
    <a href="https://crates.io/crates/http-net"><img alt="Downloads" src="https://img.shields.io/crates/d/http-net?color=%230099ff"></a>
    <a href="https://docs.rs/http-net"><img alt="docs.rs" src="https://img.shields.io/docsrs/http-net"></a>
    <a href="https://github.com/jamesgober/http-net/actions"><img alt="CI" src="https://github.com/jamesgober/http-net/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</div>

<br>

<div align="left">
    <p>
        <strong>http-net</strong> is an HTTP/1.1 engine that does no I/O itself: feed it bytes, get requests or responses back as borrowed views of those bytes, and hand it responses to serialize. The caller owns sockets, threads, and timers, so the same core runs under a blocking loop, an event loop, or a test that never opens a socket.
    </p>
    <p>
        Parsing follows RFC 9112 strictly. A message that two implementations could frame differently is refused, not repaired: conflicting <code>Content-Length</code> and <code>Transfer-Encoding</code>, duplicate lengths, obsolete line folding, bare CR or LF, whitespace before a colon, and control bytes in field values each have their own error. Every buffer is bounded, and each limit is checked before the bytes it governs are buffered. Keep-alive, pipelined requests, chunked bodies both ways, and the protocol-upgrade hand-off for WebSocket are built in; a small blocking adapter over <code>std::net</code> serves a handler and fetches a URL.
    </p>
    <br>
    <hr>
    <p>
        <strong>MSRV is 1.85+</strong> (Rust 2024 edition). <code>no_std</code>-compatible core (needs only <code>alloc</code>), <code>#![forbid(unsafe_code)]</code>, no third-party dependencies (one first-party: <code>parse-net</code>, the shared field grammar).
    </p>
    <blockquote>
        <strong>Status: pre-1.0 (<code>0.7.0</code>).</strong> The 1.0 feature set is in place: the core, the extended protocol features (trailers, interim responses, <code>Expect: 100-continue</code> both ways, driver controls), client pipelining, connection reuse and pooling, and the allocation-free Tier-3 surface. The 1.0 surface is designed (<a href="./docs/API.md"><code>docs/API.md</code></a> marks the version each item ships in); the public API may still change in the 0.x series and is frozen at <code>1.0.0</code>, after LexerSketch Studio has used it end to end. See <a href="./CHANGELOG.md"><code>CHANGELOG.md</code></a>, <a href="./docs/MIGRATION.md"><code>docs/MIGRATION.md</code></a>, and <a href="./dev/ROADMAP.md"><code>dev/ROADMAP.md</code></a>.
    </blockquote>
</div>

<hr>
<br>

## The model

- A **[`ServerConn`](./docs/API.md#serverconn)** is the server side of one connection. Bytes go in with `feed` (or `read_buf` + `commit`); `poll` reports a **[`ServerEvent`](./docs/API.md#serverevent)**: a request head, body runs, the end of the request, or what it needs next. `respond` writes a **[`Response`](./docs/API.md#response)** into your output buffer; [`respond_head_only`](./docs/API.md#serverconnrespond_head_only) writes just the head, so a large body goes out with it in one vectored write, uncopied.
- A **[`ClientConn`](./docs/API.md#clientconn)** is the mirror image: `send_request` writes a **[`Request`](./docs/API.md#request)**, `poll` reports the response as **[`ClientEvent`](./docs/API.md#clientevent)**s.
- **[`RequestHead`](./docs/API.md#requesthead)** and **[`ResponseHead`](./docs/API.md#responsehead)** are zero-copy views of a parsed head.
- **[`Limits`](./docs/API.md#limits)** bounds every buffer; **[`HttpError`](./docs/API.md#httperror)** says exactly what was refused and which status to answer with, and [`Response::from_error`](./docs/API.md#responsefrom_error) builds that answer.
- Both connections carry **trailers** (reported on request, sent with `end_body_with_trailers`) and **interim responses** (`send_informational` for `103 Early Hints`; reported to the client on request), and the client can send **`Expect: 100-continue`** and hold its body back. **[`Progress`](./docs/API.md#progress)**, `set_keep_alive`, and `requests_served` give drivers what they need for deadlines and load shedding; **[`DateCache`](./docs/API.md#httpdate-and-datecache)** formats `Date` once per second.
- **[`Method`](./docs/API.md#method)** and **[`MethodSet`](./docs/API.md#methodset)** classify methods (safe, idempotent, a bit set for routers and `Allow`); [`reason_phrase`](./docs/API.md#reason_phrase) and the [`status`](./docs/API.md#status-constants) constants cover the whole IANA status registry.
- The client **pipelines** idempotent requests up to a configured depth; both connections can be **reset, pooled, and shrunk** while idle, and the server can **wipe** consumed input so credentials do not linger.
- **Tier 3** for gateways and proxies, all allocation-free: [spans and copied heads](./docs/API.md#spans-raw-heads-owned-heads) for passing a head to another thread, [stateless head parsers](./docs/API.md#stateless-head-parsers), a standalone [`ChunkedDecoder`](./docs/API.md#chunkeddecoder), the [`Output` writer](./docs/API.md#output-and-the-borrowed-writer) with borrowed fields, [`forward_from`](./docs/API.md#requestforward_from) with hop-by-hop removal, and [HTTP/2 preface detection](./docs/API.md#is_h2_preface).
- The **[`blocking`](./docs/API.md#blocking-adapter)** module (feature `std`) drives both over `std::net`: a bounded thread-per-connection `Server`, a per-connection `Connection`, and `get`.

<br>

What it guarantees, and how each guarantee is checked:

| Guarantee | How it is held |
|---|---|
| Parsing follows RFC 9112; malformed messages get a precise error, never a guess. | 17 request accept cases, 66 request reject cases, and 18 response cases as data (`tests/rfc_cases.rs`), each run whole and one byte at a time; a differential test against an independent whole-buffer reference parser over every single-byte mutation of eight seed requests plus 8,192 random multi-byte mutations (`tests/prop_reference.rs`). |
| Request smuggling vectors are refused. | 25 CL.TE / TE.CL / TE.TE / line-ending vectors and 7 chunk-extension line-end vectors (the Funky Chunks classes), each at every split point (`tests/smuggling.rs`); after an error the connection never parses another request; outgoing messages cannot carry framing headers or CR/LF. An adversarial suite (`tests/adversarial.rs`) adds target forms and the authority, `Host` escapes, `Expect: 100-continue` and `Expect`-based desync shapes, 0.CL desync, `h2c` and unoffered upgrades, chunk and trailer edges, cumulative chunk-extension and interim-response budgets, and integer edges. |
| Limits are enforced before allocation. | Boundary tests at the limit and one past it for line length, header bytes, header count, and body; declared lengths and chunk sizes are checked before their data is read; the input buffer never exceeds `2 * (line + headers) + 16 KiB`, and the test drivers assert the parser never waits for input with a full buffer. |
| Nothing panics on hostile bytes. | Property tests feed arbitrary bytes and dictionary-built near-HTTP to both connections, from the first byte and behind valid heads (so body, chunk, and trailer states are reached), whole and split, with default and tiny limits. |
| The parse does not depend on how input is split. | Property tests compare whole, split, and byte-at-a-time feeding. |
| Serialize and parse round-trip. | Property tests: requests from `ClientConn` parsed by `ServerConn`, responses the other way, with full, chunked, and fixed-length streamed bodies; absolute-form targets; keep-alive intent. |
| Slow or stuck peers cannot pin the server. | Socket tests: a head or body trickled inside the read timeout is cut off by the request timeout with `408`; a refused client that keeps sending cannot stall the accept loop; lingering close ends after 1 s however the peer behaves. |
| Credentials never reach logs through `Debug`. | `authorization`, `proxy-authorization`, `cookie`, and `set-cookie` values print as `<redacted N bytes>` in every `Debug` output of the crate; `tests/redaction.rs` checks every type that prints fields, in every case spelling of the names. |
| Steady-state parsing allocates nothing. | A counting allocator (`tests/alloc.rs`): 10,000 keep-alive requests on one `ServerConn`, and 10,000 responses (also pipelined) on one `ClientConn`, allocate nothing after warm-up; the stateless parsers, the `Output` writer, and the `ChunkedDecoder` allocate nothing at all; 10 MiB hostile streams never grow a connection past its buffer capacity. |
| It agrees with other parsers where it accepts. | A differential test against `httparse` (`tests/prop_httparse.rs`): on every request head both accept, the length, method, target, version, and fields match; every head only `httparse` accepts is one of the documented stricter refusals. An RFC 9112 / 9110 conformance table (`tests/conformance.rs`) checks one statement per row. |
| It survives fuzzing. | Eight cargo-fuzz targets (`fuzz/`): both connections under fuzzer-chosen splits, limits, and options (client fold leniency included), the chunk-line grammar, the builders, the stateless parsers and the `ChunkedDecoder` against the connections, and differential oracles against the reference parser and `httparse`, each run in CI on every push. |
| It works over real sockets. | `tests/localhost.rs`: the Tier-1 server and client, keep-alive, pipelining, a 200 KB chunked upload echoed back, streamed responses, error answers, `Expect: 100-continue`, the connection cap, the upgrade hand-off, and shutdown. |

<hr>
<br>

## Installation

```toml
[dependencies]
http-net = "0.7"
```

Without the standard library (the sans-IO core only):

```toml
[dependencies]
http-net = { version = "0.7", default-features = false }
```

<hr>
<br>

## Quick start

Serve a handler on localhost and fetch from it:

```rust
use http_net::{blocking, Response};

let server = blocking::Server::bind("127.0.0.1:0")?;
let addr = server.local_addr();
let stop = server.shutdown_handle();
let thread = std::thread::spawn(move || {
    server.serve(|req, _body| Response::text(200, &format!("you asked for {}", req.path())))
});

let resp = blocking::get(&format!("http://{addr}/hello"))?;
assert_eq!(resp.status(), 200);
assert_eq!(resp.text(), Some("you asked for /hello"));

stop.shutdown();
thread.join().unwrap()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The server runs one thread per connection, at most 64 at once (the next is answered `503`), with a 10 s read timeout and a 30 s deadline per request (first byte to end of body; a late request gets `408`), answers `Expect: 100-continue` itself, and adds a `date` header to every response. Requests that fail to parse are answered with the matching status (`400`, `413`, `414`, `431`, `501`, `505`) and closed; the handler never sees them. A handler that returns a streamed or invalid response gets a `500` instead of a hung client.

### The sans-IO core

The same kind of exchange with no socket at all:

```rust
use http_net::{Response, ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let mut out = Vec::new();
let _ = conn.feed(b"POST /notes HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello");
let mut body = Vec::new();
loop {
    match conn.poll()? {
        ServerEvent::Request(req) => assert_eq!(req.path(), "/notes"),
        ServerEvent::Body(chunk) => body.extend_from_slice(chunk),
        ServerEvent::RequestEnd => conn.respond(&Response::text(201, "saved"), &mut out)?,
        _ => break, // NeedInput: read more from the socket and feed it
    }
}
assert_eq!(body, b"hello");
assert!(out.starts_with(b"HTTP/1.1 201 Created\r\n"));
# Ok::<(), http_net::HttpError>(())
```

### Handing a connection to WebSocket

```rust
use http_net::{Response, ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET /rpc HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n\x81\x85");
let ServerEvent::Request(req) = conn.poll()? else { unreachable!() };
assert!(req.is_upgrade());
assert!(matches!(conn.poll()?, ServerEvent::RequestEnd));

let mut out = Vec::new();
let accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="; // computed by the WebSocket engine
conn.respond(&Response::switching_protocols("websocket").header("sec-websocket-accept", accept), &mut out)?;
assert!(matches!(conn.poll()?, ServerEvent::Upgraded));
assert_eq!(conn.remaining_input(), b"\x81\x85"); // the first bytes of the first frame
# Ok::<(), http_net::HttpError>(())
```

<br>

## Limits

| Budget | Default | Error when exceeded |
|---|---|---|
| request line, status line, chunk-size line | 8 KiB | `StartLineTooLong` (414) / `ChunkLineTooLong` (400) |
| header section | 16 KiB | `HeadersTooLarge` (431) |
| one field line (headers and trailers) | 8 KiB | `FieldLineTooLong` (431) |
| header fields | 100 | `TooManyHeaders` (431) |
| trailer section and trailer fields | the header budgets, unless set | `HeadersTooLarge` / `TooManyHeaders` |
| body | 1 MiB | `BodyTooLarge` (413) |
| chunk extensions, summed over one message | 16 KiB (the header budget) | `ChunkExtensionsTooLarge` (400) |
| interim 1xx responses before a final one (client) | 16, and 16 KiB of heads together | `TooManyInterim` / `HeadersTooLarge` |

These are the budgets of LexerSketch Studio's localhost server. Change them with [`Limits`](./docs/API.md#limits). The blocking server adds time budgets in [`ServerConfig`](./docs/API.md#blockingserverconfig): 10 s per read, 30 s per request, 10 s per write, 60 s to write a whole response, at most 1 s of lingering close.

<br>

## Examples

```bash
cargo run --example localhost   # serve, fetch, shut down
cargo run --example sans_io     # the core with no socket
cargo run --example early_hints # 103 Early Hints, server to client, in memory
cargo run --example trailers    # trailer fields both ways, in memory
cargo run --example pipelined_client # four requests in flight, answered in order
cargo run --example passport    # copy heads out and hand them to a worker thread
cargo run --example proxy_forward    # forward a request upstream without hop-by-hop fields
cargo run --example serve -- 127.0.0.1:8080
cargo run --example get -- http://127.0.0.1:8080/
```

<br>

## What is not here yet

- TLS: plain `http://` only.
- Integration with the first consumers (serve-net, the WASP gateway, fetch-net, LexerSketch Studio), and HTTP Garden differential runs in CI: v0.8.0. See the [roadmap](./dev/ROADMAP.md).
- An async runtime or adapter: never; drive the sans-IO core from any loop.
- Content codings (gzip and others): a body is delivered as sent, and a `Transfer-Encoding` other than `chunked` is refused with 501.

<hr>
<br>

## Performance

Criterion medians for 0.6.0 in WSL Ubuntu on a Windows x86_64 machine (AMD Ryzen 9 9950X3D, Rust stable, release profile), from `cargo bench` pinned to one core, run alternately with a 0.5.0 build so machine load falls on both. Method, Windows numbers, and every decision behind them: [`docs/PERFORMANCE.md`](./docs/PERFORMANCE.md).

| Benchmark | 0.6.0 | vs 0.5.0 |
|---|---:|---:|
| 12-field browser GET, parsed and answered | ~234 ns | -23% |
| 100,000 pipelined GETs in 16 KiB reads | ~8.8 ms (11.4 M requests/s) | -13% |
| 1 MiB body, `Content-Length`, 16 KiB reads | ~13.5 µs | -3% |
| 1 MiB body, chunked in 4 KiB chunks | ~17.0 µs | -3% |
| response with five fields and a 1 KiB body, serialized | ~74 ns | -17% |
| client parsing a 1 KiB response | ~100 ns | -11% |

Against other libraries, on identical bytes ([`http-net-bench`](https://github.com/jamesgober/http-net-bench)): a full server exchange takes ~250 ns against hyper's ~1.4 µs (3.4 to 5.5x faster), 100,000 pipelined requests 7.3 ms against hyper's 23.6 ms, and a client exchange 95 ns against hyper's 1.24 µs. Parsing a head alone is level with httparse (~177 ns against ~172 ns with httparse's SIMD) while also validating the `Host` value, the target, every value byte, and the framing rules, with no `unsafe` code.

These are library-only numbers: no sockets are involved. Body events borrow the input buffer, so the 1 MiB cases measure one copy into the buffer plus framing.

<hr>
<br>

## Contributing

See <a href="./dev/DIRECTIVES.md"><code>dev/DIRECTIVES.md</code></a> for engineering standards and the definition of done. Before a PR: `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features` must be clean.

<br>

<div id="license">
    <h2>License</h2>
    <p>Licensed under either of</p>
    <ul>
        <li><b>Apache License, Version 2.0</b>: <a href="./LICENSE-APACHE">LICENSE-APACHE</a></li>
        <li><b>MIT License</b>: <a href="./LICENSE-MIT">LICENSE-MIT</a></li>
    </ul>
    <p>at your option.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
