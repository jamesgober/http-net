<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>http-net</b>
    <br>
    <sub>
        <sup>SANS-IO HTTP/1.1</sup>
    </sub>
</h1>

<p align="center">
    <a href="https://crates.io/crates/http-net"><img src="https://img.shields.io/crates/v/http-net.svg" alt="Crates.io"></a>
    <a href="https://crates.io/crates/http-net" alt="Download"><img alt="Crates.io Downloads" src="https://img.shields.io/crates/d/http-net?color=%230099ff"></a>
    <a href="https://docs.rs/http-net"><img src="https://docs.rs/http-net/badge.svg" alt="Documentation"></a>
    <a href="https://github.com/jamesgober/http-net/actions"><img alt="GitHub CI" src="https://github.com/jamesgober/http-net/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md" title="MSRV"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85-blue"></a>
    <a href="#license"><img src="https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg" alt="License"></a>
</p>

<p align="center">
    <b>A strict HTTP/1.1 server and client engine that does no I/O.</b>
    <br>
    <i>You own the sockets, threads and timers; http-net parses, frames and serializes.</i>
</p>

<br>

<p>
    <strong>http-net</strong> is an HTTP/1.1 engine that does no I/O itself. You feed it bytes and get requests or responses back as borrowed views of those bytes, and you hand it responses to serialize. The caller owns sockets, threads and timers, so the same core runs under a blocking loop, an event loop, or a test that never opens a socket. A small blocking adapter over <code>std::net</code> serves a handler and fetches a URL when you want that without writing a loop.
</p>

<p>
    Parsing follows RFC 9112 strictly. A message that two implementations could frame differently is refused, not repaired: conflicting <code>Content-Length</code> and <code>Transfer-Encoding</code>, duplicate lengths, obsolete line folding, bare CR or LF, whitespace before a colon, and control bytes in field values each have their own error. Every buffer is bounded, and each limit is checked before the bytes it governs are buffered.
</p>

<p>
    Keep-alive, pipelined requests, chunked bodies in both directions, trailers, interim responses, <code>Expect: 100-continue</code> and the protocol-upgrade hand-off for WebSocket are built in. The core is <code>no_std</code> (it needs only <code>alloc</code>), uses <code>#![forbid(unsafe_code)]</code>, and has one dependency, the first-party <code>parse-net</code> field grammar crate.
</p>

---

## Features

### **Parsing and framing**
- **Strict RFC 9112** - ambiguous messages are refused with a precise error; request smuggling vectors (CL.TE, TE.CL, TE.TE, line endings, chunk extensions) are rejected, and after an error the connection parses nothing further.
- **Zero-copy views** - `RequestHead` and `ResponseHead` borrow the input buffer.
- **Bounded buffers** - `Limits` caps every line, section, count and body, and each cap is checked before the data is buffered.
- **Split-independent** - the parse is the same whether input arrives whole, in pieces, or one byte at a time.

### **Connections**
- **ServerConn and ClientConn** - mirror-image state machines: `feed` or `read_buf` + `commit`, then `poll` for events.
- **Keep-alive and pipelining** - the client pipelines idempotent requests up to a set depth; both sides can be reset, pooled and shrunk while idle.
- **Bodies** - fixed-length and chunked, streamed both ways, with trailers and `Expect: 100-continue`.
- **Interim responses** - `103 Early Hints` from the server, reported to the client.
- **Upgrades** - the hand-off for WebSocket, including the bytes already read after the head.
- **Driver controls** - `Progress`, `set_keep_alive` and `requests_served` for deadlines and load shedding; `DateCache` formats `Date` once per second.

### **For gateways and proxies**
- **Allocation-free Tier 3** - stateless head parsers, a standalone `ChunkedDecoder`, the `Output` writer, and copying a head into reused buffers allocate nothing.
- **Passports** - spans and owned heads for handing a head to another thread.
- **Forwarding** - `Request::forward_from` with hop-by-hop removal, and HTTP/2 preface detection.

### **Reliability and safety**
- **No unsafe code** - `#![forbid(unsafe_code)]`.
- **Credentials stay out of logs** - `Debug` output redacts `authorization`, `cookie`, `set-cookie` and fields with names like `token` or `secret`.
- **Tested hard** - RFC case tables, differential tests against a reference parser and `httparse`, property tests, a counting-allocator test, socket tests, and eight fuzz targets. See [How each guarantee is checked](#how-each-guarantee-is-checked).

---

## **Why Choose http-net?**

### **No I/O to fight**
The core never touches a socket, a clock or a thread. You decide how bytes arrive and when to give up on a peer, so it fits a blocking server, an event loop, or a unit test equally well.

### **Strict where it matters**
Lenient parsers are where request smuggling comes from. http-net refuses a message that could be framed two ways, names exactly what was wrong, and tells you which status to answer with. What that costs is measured in [Performance](#performance).

### **Small and self-contained**
No third-party runtime dependencies and no `unsafe`. The one dependency is `parse-net`, the shared field grammar, pinned to an exact version so that what is accepted on the wire only changes in an http-net release.

### **Developer Experience First**
The common cases are short: `blocking::Server::bind` plus `serve` for a handler, `blocking::get` for a fetch, `Response::text` to build an answer, and plain `?` throughout. The driver-level API has the same shape on both sides.

### **Built for the edges**
Tier 3 exists for gateways and proxies: parse without allocating, copy a head to another thread, forward a request without hop-by-hop fields, and detect an HTTP/2 preface.

---

<br>

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
http-net = "0.10"
```

Without the standard library (the sans-IO core only):

```toml
[dependencies]
http-net = { version = "0.10", default-features = false }
```

| Feature | Enables | Default |
|---|---|---|
| `std` | The `blocking` adapter over `std::net` (`Server`, `Connection`, `Client`, `get`). Without it the crate is `no_std` and needs only `alloc`. | yes |

**Feature Recommendations**:
- **Application or local tool**: the defaults, for `blocking::Server` and `blocking::get`.
- **Driver, gateway or proxy on `no_std`**: `default-features = false`.

---

<br>

## Quick Start

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

The server runs one thread per connection, at most 64 at once (the next is answered `503`), with a 10 s read timeout and a 30 s deadline per request (first byte to end of body; a late request gets `408`), answers `Expect: 100-continue` itself, and adds a `date` header to every response except that fixed `503`. Requests that fail to parse are answered with the matching status (`400`, `413`, `414`, `431`, `501`, `505`) and closed; the handler never sees them. A handler that returns a streamed or invalid response gets a `500` instead of a hung client. It is for local, development, and trusted-network use: 64 slow connections fill it, so an internet-facing server drives the sans-IO core below from an event loop with per-peer limits.

### **The sans-IO core**

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

### **Handing a connection to WebSocket**

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

### **The model**

- A **[`ServerConn`](./docs/API.md#serverconn)** is the server side of one connection. Bytes go in with `feed` (or `read_buf` + `commit`); `poll` reports a **[`ServerEvent`](./docs/API.md#serverevent)**: a request head, body runs, the end of the request, or what it needs next. `respond` writes a **[`Response`](./docs/API.md#response)** into your output buffer; [`respond_head_only`](./docs/API.md#serverconnrespond_head_only) writes just the head, so a large body goes out with it in one vectored write, uncopied.
- A **[`ClientConn`](./docs/API.md#clientconn)** is the mirror image: `send_request` writes a **[`Request`](./docs/API.md#request)**, `poll` reports the response as **[`ClientEvent`](./docs/API.md#clientevent)**s.
- **[`RequestHead`](./docs/API.md#requesthead)** and **[`ResponseHead`](./docs/API.md#responsehead)** are zero-copy views of a parsed head.
- **[`Limits`](./docs/API.md#limits)** bounds every buffer; **[`HttpError`](./docs/API.md#httperror)** says exactly what was refused and which status to answer with, and [`Response::from_error`](./docs/API.md#responsefrom_error) builds that answer.
- Both connections carry **trailers** (reported on request, sent with `end_body_with_trailers`) and **interim responses** (`send_informational` for `103 Early Hints`; reported to the client on request), and the client can send **`Expect: 100-continue`** and hold its body back. **[`Progress`](./docs/API.md#progress)**, `set_keep_alive`, and `requests_served` give drivers what they need for deadlines and load shedding; **[`DateCache`](./docs/API.md#httpdate-and-datecache)** formats `Date` once per second.
- **[`Method`](./docs/API.md#method)** and **[`MethodSet`](./docs/API.md#methodset)** classify methods (safe, idempotent, a bit set for routers and `Allow`); [`reason_phrase`](./docs/API.md#reason_phrase) and the [`status`](./docs/API.md#status-constants) constants cover the whole IANA status registry.
- The client **pipelines** idempotent requests up to a configured depth; both connections can be **reset, pooled, and shrunk** while idle, and **wipe** consumed input so credentials do not linger.
- **Tier 3** for gateways and proxies (the parsers, the decoder, the writer, and copying a head into reused buffers allocate nothing): [spans and copied heads](./docs/API.md#spans-raw-heads-owned-heads) for passing a head to another thread, [stateless head parsers](./docs/API.md#stateless-head-parsers), a standalone [`ChunkedDecoder`](./docs/API.md#chunkeddecoder), the [`Output` writer](./docs/API.md#output-and-the-borrowed-writer) with borrowed fields, [`forward_from`](./docs/API.md#requestforward_from) with hop-by-hop removal, and [HTTP/2 preface detection](./docs/API.md#is_h2_preface).
- The **[`blocking`](./docs/API.md#blocking-adapter)** module (feature `std`) drives both over `std::net`: a bounded thread-per-connection `Server`, a per-connection `Connection`, and `get`. The server is for local, development, and trusted-network use: its connection cap is its only admission control, so an internet-facing server drives `ServerConn` from an event loop with per-peer limits (serve-net).

<br>

### **Limits**

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

These are the defaults. Change them with [`Limits`](./docs/API.md#limits). The blocking server adds time budgets in [`ServerConfig`](./docs/API.md#blockingserverconfig): 10 s per read, 30 s per request, 10 s per write, 60 s to write a whole response, at most 1 s of lingering close.

### **Examples**

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
cargo run --release --example soak -- 90s 4  # mixed workload for a set time, client threads
```

### **How each guarantee is checked**

| Guarantee | How it is held |
|---|---|
| Parsing follows RFC 9112; malformed messages get a precise error, never a guess. | 17 request accept cases, 67 request reject cases, and 18 response cases as data (`tests/rfc_cases.rs`), each run whole and one byte at a time; a differential test against an independent whole-buffer reference parser over every insertion or substitution of 23 boundary bytes and every deletion, at every position of eight seed requests, plus 8,192 random mutations of one to three edits (`tests/prop_reference.rs`). |
| Request smuggling vectors are refused. | 25 CL.TE / TE.CL / TE.TE / line-ending vectors and 7 chunk-extension line-end vectors (the Funky Chunks classes), each at every split point (`tests/smuggling.rs`); after an error the connection never parses another request; outgoing messages cannot carry framing headers or CR/LF. An adversarial suite (`tests/adversarial.rs`) adds target forms and the authority, `Host` escapes, `Expect: 100-continue` and `Expect`-based desync shapes, 0.CL desync, `h2c` and unoffered upgrades, chunk and trailer edges, cumulative chunk-extension and interim-response budgets, and integer edges. |
| Limits are enforced before allocation. | Boundary tests at the limit and one past it for line length, header bytes, header count, and body; declared lengths and chunk sizes are checked before their data is read; the input buffer never exceeds `Limits::buffer_capacity()`: `head + max(head, max_trailer_bytes) + 16 KiB`, where `head = max_start_line + max_header_bytes` (64 KiB with the defaults), and the test drivers assert the parser never waits for input with a full buffer. |
| Nothing panics on hostile bytes. | Property tests feed arbitrary bytes and dictionary-built near-HTTP to both connections, from the first byte and behind valid heads (so body, chunk, and trailer states are reached), whole and split, with default and tiny limits. |
| The parse does not depend on how input is split. | Property tests compare whole, split, and byte-at-a-time feeding. |
| Serialize and parse round-trip. | Property tests: requests from `ClientConn` parsed by `ServerConn`, responses the other way, with full, chunked, and fixed-length streamed bodies; absolute-form targets; keep-alive intent. |
| Slow or stuck peers cannot pin the server. | Socket tests: a head or body trickled inside the read timeout is cut off by the request timeout with `408`; a refused client that keeps sending cannot stall the accept loop; lingering close ends after 1 s however the peer behaves. |
| Credentials never reach logs through `Debug`. | `authorization`, `proxy-authorization`, `cookie`, and `set-cookie` values, and those of any field whose name contains `auth`, `token`, `key`, `secret`, `session`, `password`, `csrf`, or `signature`, print as `<redacted N bytes>` in every `Debug` output of the crate; a target's query, body bytes, and tunnel bytes print as their length; `tests/redaction.rs` checks every type that prints fields, in every case spelling of the names. Other field values print as received. |
| Steady-state parsing allocates nothing. | A counting allocator (`tests/alloc.rs`): 10,000 keep-alive requests on one `ServerConn`, and 10,000 responses (also pipelined) on one `ClientConn`, allocate nothing after warm-up; the stateless parsers and the `ChunkedDecoder` allocate nothing at all, and the `Output` writer allocates nothing into a reused buffer; 10 MiB hostile streams never grow a connection past its buffer capacity. |
| It agrees with other parsers where it accepts. | A differential test against `httparse` (`tests/prop_httparse.rs`): on every request head both accept, the length, method, target, version, and fields match; every head only `httparse` accepts is one of the documented stricter refusals. An RFC 9112 / 9110 conformance table (`tests/conformance.rs`) checks one statement per row. |
| It survives fuzzing. | Eight cargo-fuzz targets (`fuzz/`): both connections under fuzzer-chosen splits, limits, and options (client fold leniency included), the chunk-line grammar, the builders, the stateless parsers and the `ChunkedDecoder` against the connections, and differential oracles against the reference parser and `httparse`, each run for 60 seconds in CI on every push and pull request to `main` and `dev`. |
| It works over real sockets. | `tests/localhost.rs`: the Tier-1 server and client, keep-alive, pipelining, a 200 KB chunked upload echoed back, streamed responses, error answers, `Expect: 100-continue`, the connection cap, the upgrade hand-off, and shutdown. |

---

## Performance

Criterion medians for 0.6.0 in WSL Ubuntu on a Windows x86_64 machine (AMD Ryzen 9 9950X3D, Rust stable, release profile), from `cargo bench` pinned to one core, run alternately with a 0.5.0 build so machine load falls on both. Method, Windows numbers, and every decision behind them: [`docs/PERFORMANCE.md`](./docs/PERFORMANCE.md). 0.7.0 and 0.8.0 were measured against their predecessors with no measurable difference ([`docs/release/v0.8.0.md`](./docs/release/v0.8.0.md)), and 0.9.1 against every release from 0.6.0 with no regression, so these 0.6.0 numbers stand.

| Benchmark | 0.6.0 | vs 0.5.0 |
|---|---:|---:|
| 12-field browser GET, parsed and answered | ~234 ns | -23% |
| 100,000 pipelined GETs in 16 KiB reads | ~8.8 ms (11.4 M requests/s) | -13% |
| 1 MiB body, `Content-Length`, 16 KiB reads | ~13.5 µs | -4% |
| 1 MiB body, chunked in 4 KiB chunks | ~17.0 µs | -3% |
| response with five fields and a 1 KiB body, serialized (after reading the one-field request it answers, about 62 ns of it) | ~74 ns | -17% |
| client parsing a 1 KiB response | ~100 ns | -11% |

Against other libraries, on identical bytes ([`http-net-bench`](https://github.com/jamesgober/http-net-bench)): a full server exchange takes ~250 ns against hyper's ~1.4 µs (3.4 to 5.5x faster), 100,000 pipelined requests 7.3 ms against hyper's 23.6 ms, and a client exchange 95 ns against hyper's 1.24 µs. Parsing a head alone is level with httparse (~177 ns against ~172 ns with httparse's SIMD) while also validating the `Host` value, the target, every value byte, and the framing rules, with no `unsafe` code.

Feature by feature against hyper, httparse, h11, llhttp, picohttpparser, and the `http` crate, each cell checked: [`docs/PARITY.md`](./docs/PARITY.md).

These are library-only numbers: no sockets are involved. Body events borrow the input buffer, so the 1 MiB cases measure one copy into the buffer plus framing.

---

## **Status: Pre-1.0**

**Current Version:** `0.10.0`. The 1.0 feature set is in place: the core, trailers, interim responses, `Expect: 100-continue` both ways, driver controls, client pipelining, connection reuse and pooling, and the allocation-free Tier 3 surface. [`docs/API.md`](./docs/API.md) marks the version each item ships in.

**Target:** `1.0.0`, after the audit in [`docs/STABILITY-1.0.md`](./docs/STABILITY-1.0.md). Only fixes land before it.

**What is not here**:
- TLS: plain `http://` only.
- An async runtime or adapter: never. Drive the sans-IO core from any loop.
- Content codings (gzip and others): a body is delivered as sent. A transfer coding before `chunked` is refused with 501 (`UnsupportedTransferEncoding`); a `Transfer-Encoding` that does not end in a single `chunked` is refused with 400 (`InvalidTransferEncoding`).

**Note on API stability**: the API is frozen as the 1.0 candidate. See [`CHANGELOG.md`](./CHANGELOG.md) and [`docs/MIGRATION.md`](./docs/MIGRATION.md) for what changed between releases.

---

## **Documentation & Resources**

### **Documentation**
- **[Documentation Index](docs/README.md)** - the documentation hub
- **[API Reference](docs/API.md)** - every public item, with examples
- **[Architecture](docs/ARCHITECTURE.md)** - modules, state machines, framing, and how memory is bounded
- **[Security](docs/SECURITY.md)** - the threat model, each threat with its defence and its test
- **[Performance](docs/PERFORMANCE.md)** - benchmark method and the decisions behind the numbers
- **[Parity](docs/PARITY.md)** - feature-by-feature comparison with hyper, httparse, h11, llhttp, picohttpparser and the `http` crate
- **[Platform Notes](docs/PLATFORM-NOTES.md)** - what differs between operating systems
- **[Stability](docs/STABILITY-1.0.md)** - what 1.0 commits to
- **[Migration](docs/MIGRATION.md)** - moving between versions

### **External Resources**
- **[API Documentation](https://docs.rs/http-net)** - rustdoc on docs.rs
- **[Crate Registry](https://crates.io/crates/http-net)** - crates.io
- **[Examples Directory](examples/)** - runnable examples, listed above
- **[Benchmarks](benches/)** - the Criterion benchmarks
- **[http-net-bench](https://github.com/jamesgober/http-net-bench)** - the comparison against other libraries

### **Common Use Cases**
- **Serve a handler locally or on a trusted network**: `blocking::Server`
- **Fetch a URL**: `blocking::get`
- **Run on your own event loop**: `ServerConn` and `ClientConn`
- **Gateway or proxy**: the Tier 3 parsers, `ChunkedDecoder`, `Output` and `forward_from`
- **Hand a connection to WebSocket**: `ServerEvent::Upgraded` and `remaining_input`

---

### **Troubleshooting**

<details>
  <summary><b>My request never reaches the handler?</b></summary>
    <p>A request that fails to parse is answered with the matching status (<code>400</code>, <code>413</code>, <code>414</code>, <code>431</code>, <code>501</code> or <code>505</code>) and the connection is closed. The handler never sees it. The <code>HttpError</code> variant says what was refused.</p>
</details>

<details>
  <summary><b>The server answers 503?</b></summary>
    <p>The blocking server runs one thread per connection, at most 64 at once, and answers the next one <code>503</code>. It is meant for local, development and trusted-network use. For anything internet-facing, drive <code>ServerConn</code> from an event loop with per-peer limits.</p>
</details>

<details>
  <summary><b>A slow client gets 408?</b></summary>
    <p>The blocking server allows 10 s per read and 30 s per request, from the first byte to the end of the body. Both are set in <code>ServerConfig</code>.</p>
</details>

<details>
  <summary><b>A message another parser accepts is refused?</b></summary>
    <p>http-net is deliberately stricter in a few places, such as obsolete line folding, bare CR or LF, and whitespace before a colon. <a href="docs/SECURITY.md">docs/SECURITY.md</a> lists where, and why.</p>
</details>

<details>
  <summary><b>Compile error about <code>blocking</code>?</b></summary>
    <p>The <code>blocking</code> module needs the <code>std</code> feature, which is on by default. With <code>default-features = false</code> you have the sans-IO core only.</p>
</details>

---

### **Version Compatibility**
- **Rust**: 1.85+ (edition 2024), checked in CI on stable and 1.85
- **Edition**: 2024
- **`no_std`**: the core needs only `alloc`; CI builds it for `thumbv7em-none-eabihf`
- **API Stability**: pre-1.0. The API is frozen as the 1.0 candidate; only fixes are planned before `1.0.0`
- **Feature Flags**: `std` is the only one

### **Development Setup**
```bash
git clone https://github.com/jamesgober/http-net.git
cd http-net
cargo test --all-features                                 # unit, integration and doc tests
cargo bench                                               # Criterion benchmarks
cargo clippy --all-targets --all-features -- -D warnings  # lints (should be clean)
```

## **Contributing**

Before a PR, `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings` and `cargo test --all-features` must be clean.

<hr>

<!-- LICENSE
############################################# -->
<div id="license">
    <h2>License</h2>
    <p><b>http-net</b> is dual-licensed under either of:</p>
    <ul>
        <li><b>Apache License, Version 2.0</b> - see <a href="./LICENSE-APACHE" title="Apache-2.0 License">LICENSE-APACHE</a> or <a href="http://www.apache.org/licenses/LICENSE-2.0" title="Apache-2.0 License" target="_blank">apache.org/licenses/LICENSE-2.0</a></li>
        <li><b>MIT License</b> - see <a href="./LICENSE-MIT" title="MIT License">LICENSE-MIT</a> or <a href="https://opensource.org/licenses/MIT" title="MIT License" target="_blank">opensource.org/licenses/MIT</a></li>
    </ul>
    <p>at your option.</p>
    <h3>Contribution</h3>
    <p>Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in <b>http-net</b> by you, as defined in the Apache-2.0 license, shall be dual-licensed as above, without any additional terms or conditions.</p>
    <p>Unless required by applicable law or agreed to in writing, software distributed under the Licenses is distributed on an <b>"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND</b>, either express or implied.</p>
</div>


<!-- FOOT COPYRIGHT
################################################# -->
<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>JAMES GOBER.</strong></sup>
</div>
