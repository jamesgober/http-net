# http-net - API Reference

> Every public item of `http-net`: what it does, its parameters, its errors,
> and examples. **Status: pre-1.0 (`0.7.0`).** This file is the approved
> design of the 1.0 surface: each item says the version it ships in. Items
> marked **exists**, **0.3**, **0.4**, **0.5**, **0.6**, or **0.7** are in this build; items marked
> with a later version are the plan and are not in the crate yet. The
> surface may still change in the 0.x series and is frozen at `1.0.0`.

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Table of contents

- [Overview](#overview)
  - [Tiers](#tiers)
  - [Reading the entries](#reading-the-entries)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Concepts](#concepts)
  - [The sans-IO loop](#the-sans-io-loop)
  - [Keep-alive and pipelining](#keep-alive-and-pipelining)
  - [Body framing](#body-framing)
  - [What is refused, and why](#what-is-refused-and-why)
  - [Request targets and the authority](#request-targets-and-the-authority)
  - [`Expect: 100-continue`](#expect-100-continue)
  - [Upgrades and `h2c`](#upgrades-and-h2c)
  - [Credentials in `Debug` output](#credentials-in-debug-output)
- [Crate root](#crate-root)
  - [`VERSION`](#version)
  - [Feature flags](#feature-flags)
- [`HttpError`](#httperror)
  - [`HttpError::status`](#httperrorstatus)
  - [`HttpError::is_peer_error`](#httperroris_peer_error)
  - [`HttpError::is_usage_error`](#httperroris_usage_error)
  - [Variants](#variants)
- [`Limits`](#limits)
  - [`Limits::buffer_capacity`](#limitsbuffer_capacity)
  - [`Limits::with_pipeline_depth`](#limitswith_pipeline_depth)
- [`ServerConn`](#serverconn)
  - [Input: `feed`, `read_buf`, `commit`, `feed_eof`](#input-feed-read_buf-commit-feed_eof)
  - [`ServerConn::poll`](#serverconnpoll)
  - [`ServerConn::request`](#serverconnrequest)
  - [`ServerConn::respond`](#serverconnrespond)
  - [`ServerConn::send_continue`](#serverconnsend_continue)
  - [`ServerConn::send_body` and `end_body`](#serverconnsend_body-and-end_body)
  - [`ServerConn::end_body_with_trailers`](#serverconnend_body_with_trailers)
  - [`ServerConn::send_informational`](#serverconnsend_informational)
  - [`ServerConn::respond_with_date`](#serverconnrespond_with_date)
  - [Keep-alive control and progress](#keep-alive-control-and-progress)
  - [Upgrades: `is_upgraded`, `remaining_input`](#upgrades-is_upgraded-remaining_input)
  - [Tier-3 `ServerConn` methods](#tier-3-serverconn-methods)
- [`ServerEvent`](#serverevent)
- [`Progress`](#progress)
- [`RequestHead`](#requesthead)
  - [Method and target](#method-and-target)
  - [Fields](#fields)
  - [Framing and connection facts](#framing-and-connection-facts)
- [`ResponseHead`](#responsehead)
- [`Headers`](#headers)
- [`HeaderValues` and `ListElements`](#headervalues-and-listelements)
- [Spans, raw heads, owned heads](#spans-raw-heads-owned-heads)
- [Stateless head parsers](#stateless-head-parsers)
- [`Method`](#method)
- [`MethodSet`](#methodset)
- [`Version`](#version-1)
- [`BodyFraming`](#bodyframing)
- [`TargetForm`](#targetform)
- [Status codes](#status-codes)
  - [`reason_phrase`](#reason_phrase)
  - [`StatusClass` and `status_class`](#statusclass-and-status_class)
  - [`status` constants](#status-constants)
  - [`status_allows_body`](#status_allows_body)
- [`HttpDate` and `DateCache`](#httpdate-and-datecache)
- [`Response`](#response)
  - [`Response::from_error`](#responsefrom_error)
  - [`Response::switching_protocols`](#responseswitching_protocols)
- [`Request`](#request)
  - [`Request::upgrade`](#requestupgrade)
  - [`Request::forward_from`](#requestforward_from)
  - [`Request::expect_continue`](#requestexpect_continue)
- [`ClientConn`](#clientconn)
  - [`ClientConn::send_request`](#clientconnsend_request)
  - [Interim responses, `Expect`, trailers, and reuse](#interim-responses-expect-trailers-and-reuse)
  - [`ClientConn::set_leniency` and `ClientLeniency`](#clientconnset_leniency-and-clientleniency)
  - [`ClientConn` methods added in 0.5](#clientconn-methods-added-in-05)
- [`ClientEvent`](#clientevent)
- [Tier 3: stateless parsers, chunked decoder, output](#tier-3-stateless-parsers-chunked-decoder-output)
  - [`is_hop_by_hop`](#is_hop_by_hop)
  - [`is_h2_preface`](#is_h2_preface)
  - [`ChunkedDecoder`](#chunkeddecoder)
  - [`Output` and the borrowed writer](#output-and-the-borrowed-writer)
  - [`ServerConn::write_head` and `respond_into`](#serverconnwrite_head-and-respond_into)
  - [`ServerConn::respond_head_only`](#serverconnrespond_head_only)
- [Blocking adapter](#blocking-adapter)
  - [`blocking::Server`](#blockingserver)
  - [`blocking::serve`](#blockingserve)
  - [`blocking::now_date`](#blockingnow_date)
  - [`blocking::ServerConfig`](#blockingserverconfig)
  - [`blocking::ShutdownHandle`](#blockingshutdownhandle)
  - [`blocking::Connection`](#blockingconnection)
  - [`blocking::Incoming`](#blockingincoming)
  - [`blocking::Upgraded`](#blockingupgraded)
  - [`blocking::get`](#blockingget)
  - [`blocking::post`](#blockingpost)
  - [`blocking::Client`](#blockingclient)
  - [`blocking::ClientResponse`](#blockingclientresponse)
  - [`blocking::Error`](#blockingerror)
- [Not provided, on purpose](#not-provided-on-purpose)
- [Limits and guarantees](#limits-and-guarantees)

## Overview

`http-net` is an HTTP/1.1 engine without I/O. A connection object owns a
bounded input buffer; the caller moves bytes between it and a socket, and
the connection reports parsed messages as events and serializes outgoing
messages into a caller-owned `Vec<u8>`.

| Item | Kind | Purpose |
|---|---|---|
| [`ServerConn`](#serverconn) | struct | Server side of one connection: parses requests, writes responses. |
| [`ServerEvent`](#serverevent) | enum | What `ServerConn::poll` reports. |
| [`ClientConn`](#clientconn) | struct | Client side of one connection: writes requests, parses responses. |
| [`ClientEvent`](#clientevent) | enum | What `ClientConn::poll` reports. |
| [`RequestHead`](#requesthead) | struct | Zero-copy view of a parsed request head. |
| [`ResponseHead`](#responsehead) | struct | Zero-copy view of a parsed response head. |
| [`Headers`](#headers), [`HeaderValues`](#headervalues-and-listelements) | structs | Iterators over a head's fields. |
| [`Span`, `RawHead`, `OwnedRequestHead`](#spans-raw-heads-owned-heads) | structs | A head's bytes and the offsets of its parts; copied and owned heads. |
| [`parse_request_head`, `parse_response_head`](#stateless-head-parsers) | fns | One head from a slice, without a connection. |
| [`Response`](#response), [`Request`](#request) | structs | Outgoing messages (builders). |
| [`Method`](#method), [`MethodSet`](#methodset) | enum, struct | Request methods and sets of them. |
| [`Version`](#version-1), [`BodyFraming`](#bodyframing), [`TargetForm`](#targetform) | enums | Facts about a message. |
| [`Limits`](#limits) | struct | Budgets on incoming messages. |
| [`HttpError`](#httperror) | enum | Why a message was refused or a call was out of order. |
| [`reason_phrase`](#reason_phrase), [`status_class`](#statusclass-and-status_class), [`status`](#status-constants) | fn, fn, module | The status code registry. |
| [`VERSION`](#version) | const | The crate version. |
| [`blocking`](#blocking-adapter) | module | `std::net` adapter: `Server`, `Connection`, `Client`, `get` (feature `std`). |

### Tiers

| Tier | Who | Items |
|---|---|---|
| 1 | application authors: serve a handler, fetch a URL, build a message | `blocking::Server::bind` + `serve`, `blocking::get`, `Response::text`, `Response::new`, `Response::from_error`, `Request::get`, `Request::post`, `reason_phrase`, `blocking::serve`, `blocking::post` |
| 2 | driver authors (`serve-net`, `fetch-net`, WASP, LexerSketch): own the socket, drive the state machine | `ServerConn`, `ClientConn`, their events, `Progress`, `Limits`, the builders, the views, `HttpDate` and `DateCache`, `blocking::Connection`, `ServerConfig`, `blocking::Client` |
| 3 | engine-level users: passports, proxies, differential tests, other engines | `MethodSet`, `Method::index`; from 0.5 spans and raw heads, owned heads, stateless parsers, `ChunkedDecoder`, the `Output` trait and borrowed writer, hop-by-hop helpers, HTTP/2 preface detection |

### Reading the entries

Each entry gives the signature, what it does, its errors, and an example.
**Ships** says when it is available:

| Ships | Meaning |
|---|---|
| exists | in 0.2.0 and unchanged |
| exists; 0.3 | in 0.2.0, changed in 0.3.0 as described |
| 0.3 | new in 0.3.0 |
| 0.4 | new in 0.4.0 |
| 0.5 | new in 0.5.0 |
| 0.6 | new in 0.6.0 |
| after 1.0 | planned; not in this build. Signatures are the approved design and may still be adjusted before they ship. |

## Installation

```toml
[dependencies]
http-net = "0.7"
```

`no_std` (the core needs `alloc` only):

```toml
[dependencies]
http-net = { version = "0.7", default-features = false }
```

## Quick start

```rust
use http_net::{blocking, Response};

let server = blocking::Server::bind("127.0.0.1:0")?;
let addr = server.local_addr();
let stop = server.shutdown_handle();
let t = std::thread::spawn(move || server.serve(|req, _body| Response::text(200, req.path())));

let resp = blocking::get(&format!("http://{addr}/hi"))?;
assert_eq!(resp.text(), Some("/hi"));

stop.shutdown();
t.join().unwrap()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The same exchange with no socket:

```rust
use http_net::{Response, ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let mut out = Vec::new();
let _ = conn.feed(b"GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n");
loop {
    match conn.poll()? {
        ServerEvent::Request(req) => assert_eq!(req.path(), "/status"),
        ServerEvent::Body(_) => {}
        ServerEvent::RequestEnd => conn.respond(&Response::text(200, "up"), &mut out)?,
        _ => break, // NeedInput: read more from the socket
    }
}
assert!(out.starts_with(b"HTTP/1.1 200 OK\r\n"));
# Ok::<(), http_net::HttpError>(())
```

## Concepts

### The sans-IO loop

Every driver runs the same loop:

1. `poll()` until it returns `NeedInput` (or `AwaitingResponse`,
   `Upgraded`, `Closed`).
2. On `NeedInput`, read from the socket into `read_buf` and `commit` the
   count, or `feed` a slice; on EOF call `feed_eof`.
3. Write whatever `respond` / `send_body` appended to your output buffer.

`read_buf` is never empty while the connection is waiting for input: the
buffer capacity ([`Limits::buffer_capacity`](#limitsbuffer_capacity))
always covers what the parser is waiting to complete.

### Keep-alive and pipelining

A server connection handles one request at a time. After the response is
finished, the next `poll` starts the next request; if the client pipelined
it, it is already in the buffer. The connection closes (reports `Closed`)
when the client sent `Connection: close`, when an HTTP/1.0 client did not
ask for keep-alive, when the response asked to close, when a response was
sent while request body bytes were still unread (a request without a body
can be answered at `Request` and stays keep-alive), or after a parse error.

A client connection has one request outstanding at a time by default and
returns to `Idle` when the response allows reuse. With a pipeline depth
above 1 (0.5) it accepts more idempotent requests before the first response
arrives and matches the responses to them in order: see
[Pipelining](#pipelining).

### Body framing

Incoming bodies follow RFC 9112 section 6.3:

| Situation | Framing |
|---|---|
| request with `Transfer-Encoding: chunked` | chunked |
| request with `Content-Length: n` | exactly `n` bytes |
| request with neither | no body |
| response to `HEAD`, or status 1xx, 204, 304 | no body, whatever the fields say |
| 2xx response to `CONNECT` | tunnel (`Upgraded`) |
| response with `chunked` / `Content-Length` | as for requests |
| response with neither | until the server closes (bounded by `max_body`) |

`Content-Length: 0` reports `BodyFraming::None` (there is no body);
[`content_length()`](#framing-and-connection-facts) reports the declared
value, so `Some(0)` and an absent field can be told apart.

Outgoing bodies: a full body is sent with `content-length`; a streamed body
with chunked encoding or a declared `content-length`. HTTP/1.0 peers never
receive chunked encoding: the server falls back to closing the connection.

### What is refused, and why

Anything recipients have been known to disagree about is an error, never a
guess. Each row is refused in requests and responses alike unless noted.

| Refused | Error | Why (RFC 9112 / 9110) |
|---|---|---|
| `Content-Length` together with `Transfer-Encoding` | `ConflictingFraming` | CL.TE / TE.CL smuggling; 9112 section 6.1 allows rejecting. |
| a second `Content-Length`, even an equal one; a list `5, 5`; signs, spaces, hex | `DuplicateContentLength` / `InvalidContentLength` | 9112 section 6.3 item 5: a recipient may reject; accepting invites a hop to pick another value. |
| `Transfer-Encoding` that is not exactly one final `chunked` (`chunked, chunked`, `chunked;x=1`, `xchunked`, empty) | `InvalidTransferEncoding` | TE.TE obfuscation. Responses too: RFC 9112 would read such a response until close; this crate refuses it. |
| a transfer coding other than `chunked` (`gzip, chunked`) | `UnsupportedTransferEncoding` (501) | No codings are implemented. |
| `Transfer-Encoding` in HTTP/1.0 | `TransferEncodingInHttp10` | 9112 section 6.1: framing is faulty. |
| obsolete line folding; whitespace before the first field | `ObsFold` | 9112 section 5.2 allows rejecting; folding hides fields from some hops. |
| a bare CR anywhere in the head; a bare LF as a line end | `BareCr` / `BareLf` | 9112 section 2.2 permits accepting a bare LF; refusing it keeps every hop agreeing on line ends. |
| whitespace between a field name and its colon | `WhitespaceBeforeColon` | 9112 section 5.1: MUST reject. |
| control bytes (NUL, VT, FF, DEL, ...) in a value; non-token names | `InvalidHeaderValue` / `InvalidHeaderName` | 9110 section 5.5. |
| a missing `Host` in HTTP/1.1; two `Host` fields (any case); a `Host` that is not `host[:port]`, has an empty host before a port (`:80`), or a bad `%XX` escape (0.3) | `MissingHost` / `InvalidHost` | 9112 section 3.2: MUST answer 400. |
| a target with characters outside RFC 3986 or bad `%` escapes; `*` outside `OPTIONS`; authority form outside `CONNECT`; an absolute form without `//authority`, with userinfo, or with an empty host | `InvalidTarget` | 9112 section 3.2; 9110 sections 4.2.1 and 4.2.4. |
| chunk sizes over 16 hex digits or overflowing 64 bits, malformed extensions (a CR or LF inside one included), data not followed by CRLF | `InvalidChunkSize` / `InvalidChunkExtension` / `BareLf` / `InvalidChunkTerminator` | Each is a known desync (the Funky Chunks TERM.EXT and EXT.TERM classes among them). |
| more than `max_header_bytes` of chunk extensions in one message | `ChunkExtensionsTooLarge` | Unbounded extensions make a small body cost unbounded input (CVE-2024-22019). |

Accepted on purpose: `HTTP/1.2` to `HTTP/1.9` (processed as 1.1), empty
lines before a request line (counted against `max_start_line`), obs-text
(bytes 0x80 to 0xFF) in field values, header names in any case, a status
line without the space after the code (`HTTP/1.1 200`, client side, 0.3),
and `Expect` values other than `100-continue` (ignored for framing; 9110
section 10.1.1 allows 417 but does not require it). `Expect` never changes
how a body is framed. Trailer fields are validated, counted, and discarded,
so a `Content-Length` or `Transfer-Encoding` in a trailer cannot reframe
anything.

After a parse error the connection is finished: nothing after the bad
message is parsed, and a server may send one error response, marked
`connection: close` ([`Response::from_error`](#responsefrom_error) builds
it).

### Request targets and the authority

| Form ([`TargetForm`](#targetform)) | Example | `path()` | `host()` |
|---|---|---|---|
| `Origin` | `/a/b?q` | `/a/b` | the `Host` field |
| `Absolute` | `http://example.com:8080/a?q` | `/a` (`/` when empty) | `example.com:8080`; `Host` is ignored (9112 section 3.2.2) but must still be present and valid |
| `Authority` (`CONNECT` only) | `example.com:443` | the whole target | the `Host` field |
| `Asterisk` (`OPTIONS` only) | `*` | `*` | the `Host` field |

`target()` always returns the target exactly as received, and
`header("host")` the raw field. The absolute form accepts any scheme by
syntax (`ftp://h/` is well formed); whether to serve it is the
application's decision.

### `Expect: 100-continue`

A client that sends `Expect: 100-continue` waits for the server before
sending the body. RFC 9110 section 10.1.1 requires the server to answer the
expectation, either with `100 Continue` or with a final status, before it
waits for the body. [`RequestHead::expects_continue`](#framing-and-connection-facts)
reports the expectation (HTTP/1.1 requests with a body only) and
[`ServerConn::send_continue`](#serverconnsend_continue) writes the interim
response. The blocking adapter does this itself. A final response sent
instead closes the connection afterwards, since the body was not read.

The expectation is matched as a list element, case-insensitively, after
whitespace trimming (`100-Continue` and ` 100-continue` count;
`100-continuex` does not). It never changes framing: the body is framed by
`Content-Length` or `Transfer-Encoding` whatever `Expect` says, so an
obfuscated `Expect` cannot make two hops disagree about where the next
request starts.

### Upgrades and `h2c`

A request whose `Connection` lists `upgrade` and whose `Upgrade` field
offers at least one protocol other than `h2c` reports
[`RequestHead::is_upgrade`](#framing-and-connection-facts). Answer it with
[`Response::switching_protocols`](#responseswitching_protocols) once the
request is complete; the connection then reports `Upgraded`, and
[`remaining_input`](#upgrades-is_upgraded-remaining_input) holds any bytes
of the new protocol that arrived with the request.

From 0.3 a `101` must name a protocol the request offered (RFC 9110 section
7.8: a server MUST NOT switch to a protocol the client did not ask for);
anything else is [`UpgradeNotOffered`](#variants). Protocol names are
compared ASCII case-insensitively; a `101` naming only a protocol name
(`websocket`) matches an offer of that name with or without a version
(`websocket/13`).

`h2c` is never treated as an upgrade offer (RFC 9113 section 3.1 deprecates
it, and blind forwarding of `Upgrade: h2c` through proxies is the h2c
smuggling attack): a request offering only `h2c` is served as plain
HTTP/1.1, `Response::switching_protocols("h2c")` and
`Request::upgrade("h2c")` are refused with `UpgradeNotOffered`.

On the client side, [`Request::upgrade`](#requestupgrade) asks to switch,
and a `101` reply carrying `Upgrade` yields `Response` then `Upgraded`.

### Credentials in `Debug` output

From 0.3, every `Debug` implementation in the crate replaces the values of
`authorization`, `proxy-authorization`, `cookie`, and `set-cookie` with
`<redacted N bytes>` (the length only). This covers [`RequestHead`](#requesthead),
[`ResponseHead`](#responsehead), [`Headers`](#headers), the events that
carry them, [`Request`](#request), [`Response`](#response), and
[`blocking::ClientResponse`](#blockingclientresponse), so `{:?}` of a
request in a log line never prints a session cookie or a bearer token.
Field names are matched ASCII case-insensitively. The accessors
(`header`, `headers`, `header_value`) still return the real bytes. The list
is fixed in 0.3; a caller-extensible list (for custom credential fields
such as an API key header) is evaluated in 0.5. `Display` of an error never
includes input bytes at all.

```rust
use http_net::{ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nCookie: session=s3cr3t\r\n\r\n");
let ServerEvent::Request(req) = conn.poll()? else { unreachable!() };
let shown = format!("{req:?}");
assert!(!shown.contains("s3cr3t"));
assert!(shown.contains("<redacted 14 bytes>"));
assert_eq!(req.header("cookie"), Some(&b"session=s3cr3t"[..]));
# Ok::<(), http_net::HttpError>(())
```

---

## Crate root

### `VERSION`

```rust,ignore
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
```

The crate version, for diagnostics and `server` fields. **Ships:** 0.3.

```rust
assert!(!http_net::VERSION.is_empty());
assert_eq!(http_net::VERSION.split('.').count(), 3);
```

### Feature flags

| Feature | Default | Description | Ships |
|---|---|---|---|
| `std` | yes | The `blocking` module. Without it the crate is `no_std` + `alloc`, built in CI for `thumbv7em-none-eabihf`. | exists |
| `http-types` | no | `From`/`TryFrom` between the views and builders and the `http` crate's types; the only optional third-party dependency, never default. | after 1.0 |

## `HttpError`

```rust,ignore
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HttpError { /* see Variants */ }

impl core::fmt::Display for HttpError;
impl core::error::Error for HttpError;
```

One variant per refusal. `Copy`; 16 bytes (the `InvalidState(&'static str)`
variant carries its rule). Two kinds:

- **Peer errors** come from parsing bytes the peer sent. They are final for
  the connection: HTTP/1.1 framing cannot be resynchronised after a
  malformed message without risking request smuggling. A server may send
  one error response, then the connection closes.
- **Usage errors** are the caller's mistake (builder misuse, a call in the
  wrong state). Nothing was written and the connection is unchanged.

Some variants are both: `InvalidTarget` comes from a bad request line
(peer) or from `Request::new` with a bad target (usage). The call that
returned the error decides which it was: `poll` returns only peer errors;
`respond`, `send_request`, `send_*`, `end_body`, and the builders return
only usage errors.

`Display` gives one actionable line naming the rule broken. It never
includes input bytes, so error text cannot reflect attacker data into a
response or a log.

### `HttpError::status`

```rust,ignore
pub const fn status(&self) -> Option<u16>
```

The status a server should answer with when this error came from parsing
a request; `None` for errors that are not about a request (response
parsing, usage). **Ships:** exists.

```rust
use http_net::HttpError;

assert_eq!(HttpError::BodyTooLarge.status(), Some(413));
assert_eq!(HttpError::TooManyHeaders.status(), Some(431));
assert_eq!(HttpError::UnsupportedVersion.status(), Some(505));
assert_eq!(HttpError::InvalidState("x").status(), None);
```

### `HttpError::is_peer_error`

```rust,ignore
pub const fn is_peer_error(&self) -> bool
```

True for every variant that parsing peer bytes can produce (the
**peer** and **peer / usage** rows of the table below). After such an
error from `poll`, the connection is finished. **Ships:** 0.3.

```rust
use http_net::HttpError;

assert!(HttpError::ConflictingFraming.is_peer_error());
assert!(!HttpError::ReservedHeader.is_peer_error());
```

### `HttpError::is_usage_error`

```rust,ignore
pub const fn is_usage_error(&self) -> bool
```

True for every variant a caller mistake can produce (the **usage** and
**peer / usage** rows). **Ships:** 0.3.

```rust
use http_net::HttpError;

assert!(HttpError::ReservedHeader.is_usage_error());
assert!(HttpError::InvalidState("x").is_usage_error());
assert!(!HttpError::BareLf.is_usage_error());
// Raised by parsing or by a builder: both.
assert!(HttpError::InvalidTarget.is_peer_error() && HttpError::InvalidTarget.is_usage_error());
```

### Variants

| Variant | Kind | Raised when | `status()` | What the caller should do | Ships |
|---|---|---|---|---|---|
| `InvalidStartLine` | peer | request line not `method SP target SP version`; status line shorter than `HTTP/x.y NNN` or with wrong separators; invalid reason bytes; empty line before a status line | 400 | answer 400 (server) or drop the connection (client) | exists |
| `InvalidMethod` | peer / usage | method is not a token (parse, or `Request::new`) | 400 | answer 400 / fix the method | exists |
| `InvalidTarget` | peer / usage | target bytes outside RFC 3986, bad `%XX`, a form the method does not allow, absolute form without `//authority`, with userinfo, or with an empty host; an authority with an empty host before a port or a bad `%XX` (0.3) | 400 | answer 400 / fix the target | exists; 0.3 |
| `InvalidVersion` | peer | version not `HTTP/DIGIT.DIGIT` | 400 | answer 400 | exists |
| `UnsupportedVersion` | peer | major version other than 1 (includes an `HTTP/2.0` request line; the HTTP/2 connection preface at the start of a connection is `Http2Preface` from 0.5) | 505 | answer 505 | exists |
| `InvalidStatus` | peer / usage | status not three digits in 100..=599 (parse); outside 100..=599, or a 1xx other than 101 (respond) | None | drop the connection / fix the status | exists |
| `StartLineTooLong` | peer | request or status line (including skipped empty lines) over `max_start_line` | 414 | answer 414 | exists |
| `HeadersTooLarge` | peer | header or trailer section over `max_header_bytes`; client: interim heads over the same budget | 431 | answer 431 | exists |
| `TooManyHeaders` | peer | more fields than `max_headers` | 431 | answer 431 | exists |
| `FieldLineTooLong` | peer | one field line over `max_field_line` | 431 | answer 431 | 0.4 |
| `BareCr` | peer / usage | CR not followed by LF anywhere in a head, chunk line, or outgoing field | 400 | answer 400 / remove CR from the value | exists |
| `BareLf` | peer | LF not preceded by CR | 400 | answer 400 | exists |
| `ObsFold` | peer | field line starting with SP or HTAB (fold, or whitespace before the first field) | 400 | answer 400 | exists |
| `InvalidHeaderName` | peer / usage | empty or non-token name, or no colon | 400 | answer 400 / fix the name | exists |
| `WhitespaceBeforeColon` | peer | SP or HTAB between name and colon | 400 | answer 400 | exists |
| `InvalidHeaderValue` | peer / usage | control byte other than HTAB in a value; outgoing value with leading or trailing whitespace; an upgrade protocol that is not a token | 400 | answer 400 / fix the value | exists |
| `MissingHost` | peer / usage | HTTP/1.1 request without `Host`; `send_request` without a `host` field | 400 | answer 400 / add `host` | exists |
| `InvalidHost` | peer / usage | more than one `Host`; a value that is not `uri-host [":" port]`; from 0.3 also an empty host with a port (`:80`) and a bad `%XX`; a second `host` on a `Request` | 400 | answer 400 / fix the host | exists; 0.3 |
| `InvalidContentLength` | peer | CL not `1*DIGIT` fitting `u64` (signs, lists, spaces, hex, empty) | 400 | answer 400 | exists |
| `DuplicateContentLength` | peer | CL field more than once, even with equal values | 400 | answer 400 | exists |
| `ConflictingFraming` | peer | CL and TE both present | 400 | answer 400 | exists |
| `InvalidTransferEncoding` | peer | TE empty, `chunked` repeated, `chunked` with parameters, not ending in `chunked`, an invalid coding token | 400 | answer 400 | exists |
| `UnsupportedTransferEncoding` | peer | a transfer coding other than `chunked` | 501 | answer 501 | exists |
| `TransferEncodingInHttp10` | peer | TE in an HTTP/1.0 message | 400 | answer 400 | exists |
| `InvalidChunkSize` | peer | no hex digit, more than 16 digits, overflow, junk after the size | 400 | answer 400 | exists |
| `InvalidChunkExtension` | peer | extension not `*( BWS ";" BWS name [ BWS "=" BWS (token / quoted-string) ] )`, trailing whitespace, a CR inside it | 400 | answer 400 | exists |
| `InvalidChunkTerminator` | peer | chunk data not followed by CRLF | 400 | answer 400 | exists |
| `ChunkLineTooLong` | peer | chunk-size line over `max_start_line` | 400 | answer 400 | exists |
| `ChunkExtensionsTooLarge` | peer | sum of extension bytes in one message over `max_header_bytes` | 400 | answer 400 | exists |
| `BodyTooLarge` | peer | declared CL, cumulative chunk sizes, or until-close bytes over `max_body` | 413 | answer 413 | exists |
| `UnexpectedEof` | peer | EOF inside a head or a body with a known end | None | close | exists |
| `UnexpectedData` | peer / usage | client: bytes with no request outstanding; `send_request` with unread input | None | close | exists |
| `UnexpectedUpgrade` | peer | client: `101` to a request that did not ask, or without `Upgrade` | None | close | exists |
| `TooManyInterim` | peer | client: more interim responses than `max_interim` for one request | None | close | 0.4 |
| `Http2Preface` | peer | the connection starts with the HTTP/2 preface `PRI * HTTP/2.0` | 505 | route to `h2-net` if the listener allows prior knowledge, else answer 505 and close | 0.5 |
| `ReservedHeader` | usage | outgoing message sets `content-length`, `transfer-encoding`, `connection`, or `upgrade` (from 0.4 also `trailer`, `te` on responses, `keep-alive`, `proxy-connection`) | None | use the builder method | exists; 0.4 |
| `BodyNotAllowed` | usage | a body on 1xx, 204, 304, 101, or 2xx to CONNECT | None | drop the body | exists |
| `BodyLengthMismatch` | usage | streamed bytes differ from the declared `content_length` | None | send exactly the declared length; the connection must close if bytes were already written | exists |
| `UpgradeNotOffered` | usage | a `101` naming a protocol absent from the request's `Upgrade` list; `h2c` in `switching_protocols` or `Request::upgrade` | None | answer with a protocol the client offered, or a normal response | 0.3 |
| `InterimNotAllowed` | usage | a 1xx (other than 101) to an HTTP/1.0 request, after the final response started, or a 100 after the body began | None | skip the interim response | 0.4 |
| `TrailerNotAllowed` | usage | an outgoing trailer field RFC 9110 section 6.5.1 keeps out of trailers, or trailers on a body that is not chunked | None | send the field in the header section | 0.4 |
| `InvalidState(&'static str)` | usage | a call in the wrong state; the text names the rule | None | follow the rule in the text | exists |

```rust
use http_net::{HttpError, ServerConn};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n");
let err = conn.poll().unwrap_err();
assert_eq!(err, HttpError::ConflictingFraming);
assert_eq!(err.status(), Some(400));
assert!(err.is_peer_error());
```

## `Limits`

```rust,ignore
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Limits { /* private */ }
impl Default for Limits;
```

The budgets a connection enforces on incoming messages. Every limit is
checked before the bytes it governs are buffered: a declared
`Content-Length` above `max_body` is refused on the header line, and a
chunk size is checked against the remaining body budget before its data is
read. The defaults are LexerSketch Studio's localhost budgets.

| Setter | Getter | Default | Range | Ships |
|---|---|---|---|---|
| `const fn new() -> Limits` | | the defaults below | | exists |
| `with_max_start_line(usize)` | `max_start_line()` | 8 KiB | clamped to `16..=16 MiB` | exists |
| `with_max_header_bytes(usize)` | `max_header_bytes()` | 16 KiB | clamped to `2..=16 MiB` | exists |
| `with_max_headers(usize)` | `max_headers()` | 100 | clamped to `0..=65536` | exists |
| `with_max_body(u64)` | `max_body()` | 1 MiB | any | exists |
| `with_max_field_line(usize)` | `max_field_line()` | 8 KiB | clamped to `4..=16 MiB` | 0.4 |
| `with_max_trailer_bytes(usize)` | `max_trailer_bytes()` | follows `max_header_bytes` | clamped to `2..=16 MiB` | 0.4 |
| `with_max_trailer_fields(usize)` | `max_trailer_fields()` | follows `max_headers` | clamped to `0..=65536` | 0.4 |
| `with_max_interim(u16)` | `max_interim()` | 16 | any | 0.4 |
| | `buffer_capacity()` | 64 KiB | derived | 0.3; 0.4 |

`max_start_line` also bounds each chunk-size line; `max_header_bytes`
counts every field line plus the blank line that ends the section.
`max_field_line` bounds one field line, in headers and trailers, CRLF
included: a longer line is `FieldLineTooLong` (431), refused before the
rest of it is buffered. **The 8 KiB default is new in 0.4** (OD-21; in 0.3
one line could use the whole 16 KiB section). Trailer sections have their
own budgets, which follow the header budgets until they are set.
`max_header_bytes` also caps, per message, the total of all chunk
extensions and (on the client) of all interim 1xx heads, which are also
counted against `max_interim` (`TooManyInterim`). A
read-until-close response body is delivered up to `max_body` and refused
at the first byte past it. `max_headers = 0` means "no fields": an HTTP/1.0
request without fields is still accepted, and an HTTP/1.1 request then
fails with `TooManyHeaders` on its `Host`.

```rust
use http_net::Limits;

let limits = Limits::new().with_max_body(64 * 1024).with_max_headers(32);
assert_eq!(limits.max_body(), 64 * 1024);
assert_eq!(limits.max_start_line(), 8 * 1024);
assert_eq!(Limits::new().with_max_start_line(0).max_start_line(), 16);
```

### `Limits::buffer_capacity`

```rust,ignore
pub const fn buffer_capacity(&self) -> usize
```

The input buffer's hard capacity, `head + max(head, max_trailer_bytes) +
16 KiB` with `head = max_start_line + max_header_bytes` (64 KiB with the
defaults, the same as `2 * head + 16 KiB` while trailer budgets follow the
header budgets), so a driver can plan memory per connection. The current
head stays pinned while its body streams, and the decoder may need a whole
chunk-size line or trailer section on top of it; this capacity always fits
what the parser is waiting to complete. Memory per connection is this plus
`max_headers` field records of 16 bytes (and as many for trailers when
they are reported). **Ships:** 0.3; 0.4 (trailer budgets).

```rust
use http_net::Limits;

assert_eq!(Limits::new().buffer_capacity(), 64 * 1024);
let small = Limits::new().with_max_start_line(1024).with_max_header_bytes(4096);
assert_eq!(small.buffer_capacity(), 2 * (1024 + 4096) + 16 * 1024);
let big_trailers = Limits::new().with_max_trailer_bytes(100 * 1024);
assert_eq!(big_trailers.buffer_capacity(), 24 * 1024 + 100 * 1024 + 16 * 1024);
```

### `Limits::with_pipeline_depth`

```rust,ignore
pub const fn with_pipeline_depth(self, depth: u8) -> Limits
pub const fn pipeline_depth(&self) -> u8
```

How many requests a client may have outstanding at once (pipelining, RFC
9112 section 9.3.2), clamped to `1..=32`. The default, 1, means one request
at a time. See [`ClientConn::can_send`](#pipelining) for what may be
pipelined. **Ships:** 0.5.

```rust
let l = http_net::Limits::new().with_pipeline_depth(8);
assert_eq!(l.pipeline_depth(), 8);
assert_eq!(http_net::Limits::new().with_pipeline_depth(0).pipeline_depth(), 1);
```

## `ServerConn`

```rust,ignore
pub struct ServerConn { /* private */ }
impl Default for ServerConn;
impl core::fmt::Debug for ServerConn; // state, buffered length, limits; never bytes
```

The server side of one HTTP/1.1 connection: a sans-IO state machine.
`Send + Sync`. Steady state allocates nothing: the input buffer and the
field index are reused across requests (proven by a counting-allocator
test). The buffer grows lazily from 4 KiB up to
[`buffer_capacity`](#limitsbuffer_capacity); `new` allocates nothing.

| Method | Signature | Ships |
|---|---|---|
| `new` | `fn new() -> ServerConn` | exists |
| `with_limits` | `fn with_limits(limits: Limits) -> ServerConn` | exists |
| `limits` | `fn limits(&self) -> &Limits` | exists |

```rust
use http_net::{HttpError, Limits, ServerConn};

let mut conn = ServerConn::with_limits(Limits::new().with_max_body(4));
let _ = conn.feed(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n");
assert_eq!(conn.poll().unwrap_err(), HttpError::BodyTooLarge);
```

### Input: `feed`, `read_buf`, `commit`, `feed_eof`

```rust,ignore
#[must_use] pub fn feed(&mut self, bytes: &[u8]) -> usize
pub fn read_buf(&mut self) -> &mut [u8]
pub fn commit(&mut self, n: usize)
pub fn feed_eof(&mut self)
```

- `feed` copies as much of `bytes` as fits and returns the count taken. A
  short count means the buffer is full: poll until `NeedInput`, then feed
  the rest. Never fails.
- `read_buf` is the spare space at the end of the buffer, for reading from
  a socket without an intermediate copy; `commit(n)` records that `n`
  bytes were written there (clamped to the spare length). It is empty only
  when the buffer is full of input the parser has not been asked to
  process; poll first.
- `feed_eof` records that the peer closed its sending side: between
  requests the connection then reports `Closed`; in the middle of one,
  `HttpError::UnexpectedEof`.

**Ships:** exists.

```rust
let mut conn = http_net::ServerConn::new();
let msg = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
conn.read_buf()[..msg.len()].copy_from_slice(msg);
conn.commit(msg.len());
assert!(matches!(conn.poll(), Ok(http_net::ServerEvent::Request(_))));

let mut idle = http_net::ServerConn::new();
idle.feed_eof();
assert!(matches!(idle.poll(), Ok(http_net::ServerEvent::Closed)));
```

### `ServerConn::poll`

```rust,ignore
pub fn poll(&mut self) -> Result<ServerEvent<'_>, HttpError>
```

Advances the parser one step and reports one event. Call it until it
returns `NeedInput`, `AwaitingResponse`, `Upgraded`, or `Closed`.
**Errors:** every peer variant of [`HttpError`](#variants); the connection
is then finished: one error response may be sent with `respond`, then it
reports `Closed`. **Cost:** about 280 ns to parse and answer a 12-field
browser GET (measured 0.2.0). **Ships:** exists.

```rust
use http_net::{HttpError, ServerConn};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n");
assert_eq!(conn.poll().unwrap_err(), HttpError::ObsFold);
```

### `ServerConn::request`

```rust,ignore
pub fn request(&self) -> Option<RequestHead<'_>>
```

The current request's head, from its arrival until the next request begins
(still available after an upgrade). **Ships:** exists.

```rust
use http_net::{ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let _ = conn.feed(b"PUT /f HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\nz");
while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
assert_eq!(conn.request().unwrap().path(), "/f");
```

### `ServerConn::respond`

```rust,ignore
pub fn respond(&mut self, response: &Response, out: &mut Vec<u8>) -> Result<(), HttpError>
```

Writes `response` for the current request into `out`: the status line, the
framing field (`content-length` or `transfer-encoding: chunked`),
`connection: close` whenever the connection will close (or
`connection: keep-alive` for an HTTP/1.0 keep-alive client), the caller's
fields, and a full body (or the start of a streamed one). A `HEAD` request
gets the framing field without body bytes; an HTTP/1.0 client gets a
close-delimited body instead of chunked. After a parse error, one response
may still be sent; it is marked `connection: close`. An unregistered status
is written with an empty reason and the space RFC 9112 section 4 requires
(`HTTP/1.1 299 ` CRLF).

**Errors:**

- the first error recorded by the [`Response`](#response) builder;
- `InvalidStatus`: outside `100..=599`, or a 1xx other than 101;
- `BodyNotAllowed`: a body on 1xx, 204, 304, 101, or 2xx to `CONNECT`;
- `UpgradeNotOffered` (0.3): a `101` whose protocol the request did not
  offer, or `h2c`;
- `InvalidState`: no request to answer, a response already started, the
  connection closed or upgraded, or a `101` (or 2xx to `CONNECT`) that does
  not answer a complete upgrade request.

**Cost:** about 75 ns for five fields and a 1 KiB body (measured 0.2.0).
**Ships:** exists; 0.3 (offered-protocol check).

```rust
use http_net::{Response, ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let _ = conn.feed(b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n");
while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
let mut out = Vec::new();
conn.respond(&Response::text(200, "hello"), &mut out).unwrap();
// HEAD: the length is announced, the body is not sent.
assert!(out.windows(17).any(|w| w == b"content-length: 5"));
assert!(out.ends_with(b"\r\n\r\n"));
```

Answering a parse error:

```rust
use http_net::{Response, ServerConn};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET / HTTP/1.1\r\n\r\n");
let err = conn.poll().unwrap_err();
let mut out = Vec::new();
conn.respond(&Response::from_error(&err), &mut out).unwrap();
assert!(out.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
assert!(out.windows(17).any(|w| w == b"connection: close"));
```

### `ServerConn::send_continue`

```rust,ignore
pub fn send_continue(&mut self, out: &mut Vec<u8>) -> Result<(), HttpError>
```

Writes `HTTP/1.1 100 Continue` CRLF CRLF, telling a client that sent
`Expect: 100-continue` to send the body. **Errors:** `InterimNotAllowed`
for an HTTP/1.0 request (RFC 9110 section 15.2 forbids 1xx responses to
HTTP/1.0 clients), once a body byte has been read or the whole body has
arrived, once a response has started, or when `100 Continue` was already
sent for this request; `InvalidState` when no request is waiting for its
body. **Ships:** exists; 0.4 (`InterimNotAllowed`, which replaced
`InvalidState` for the HTTP/1.0 and ordering cases).

```rust
use http_net::{ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let _ = conn.feed(b"PUT /f HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n");
let ServerEvent::Request(req) = conn.poll()? else { unreachable!() };
assert!(req.expects_continue());
let mut out = Vec::new();
conn.send_continue(&mut out)?;
assert_eq!(out, b"HTTP/1.1 100 Continue\r\n\r\n");
# Ok::<(), http_net::HttpError>(())
```

### `ServerConn::send_body` and `end_body`

```rust,ignore
pub fn send_body(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), HttpError>
pub fn end_body(&mut self, out: &mut Vec<u8>) -> Result<(), HttpError>
```

Body bytes of a streamed response (`Response::chunked` or
`Response::content_length`), then its end (`0` CRLF CRLF for chunked).
Dropped for `HEAD`. An empty `send_body` writes nothing (an empty chunk
would end the body). **Errors:** `BodyLengthMismatch` past the declared
length, or at `end_body` when fewer bytes were sent; `InvalidState` with no
streamed response in progress. **Ships:** exists.

```rust
use http_net::{HttpError, Response, ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET /log HTTP/1.1\r\nHost: a\r\n\r\n");
while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
let mut out = Vec::new();
conn.respond(&Response::new(200).chunked(), &mut out).unwrap();
conn.send_body(b"line 1\n", &mut out).unwrap();
conn.end_body(&mut out).unwrap();
assert!(out.ends_with(b"7\r\nline 1\n\r\n0\r\n\r\n"));

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
let mut out = Vec::new();
conn.respond(&Response::new(200).content_length(3), &mut out).unwrap();
conn.send_body(b"ab", &mut out).unwrap();
assert_eq!(conn.end_body(&mut out), Err(HttpError::BodyLengthMismatch));
```

### `ServerConn::end_body_with_trailers`

```rust,ignore
pub fn end_body_with_trailers(&mut self, trailers: &[(&str, &[u8])], out: &mut Vec<u8>) -> Result<(), HttpError>
```

Ends a streamed chunked body with a trailer section (the last chunk, the
fields, the blank line). Every field is validated before anything is
written. Trailers are optional metadata a recipient may discard (RFC 9110
section 6.5), so when an HTTP/1.0 client forced a close-delimited body, or
the request was `HEAD`, they are dropped with the body and the call still
succeeds (they are validated all the same). **Errors:** `TrailerNotAllowed`
for a field RFC 9110 section 6.5.1 keeps out of trailers (the list below)
or for a body declared with `content_length`; the field errors of
`Response::header`; otherwise as `end_body`. **Ships:** 0.4.

Fields refused in trailers: `content-length`, `transfer-encoding`, `host`,
`connection`, `keep-alive`, `te`, `trailer`, `upgrade`, `proxy-connection`,
`expect`, `max-forwards`, `range`, `if-match`, `if-none-match`,
`if-modified-since`, `if-unmodified-since`, `if-range`, `authorization`,
`proxy-authorization`, `www-authenticate`, `proxy-authenticate`, `cookie`,
`set-cookie`, `content-type`, `content-encoding`, `content-range`,
`cache-control`, `expires`, `date`, `location`, `retry-after`, `vary`, `age`.

```rust
use http_net::{HttpError, Response, ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET /data HTTP/1.1\r\nHost: a\r\nTE: trailers\r\n\r\n");
while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
let mut out = Vec::new();
conn.respond(&Response::new(200).chunked(), &mut out)?;
conn.send_body(b"rows", &mut out)?;
assert_eq!(
    conn.end_body_with_trailers(&[("set-cookie", b"a=1")], &mut out),
    Err(HttpError::TrailerNotAllowed)
);
conn.end_body_with_trailers(&[("server-timing", b"db;dur=53")], &mut out)?;
assert!(out.ends_with(b"0\r\nserver-timing: db;dur=53\r\n\r\n"));
# Ok::<(), http_net::HttpError>(())
```

### `ServerConn::send_informational`

```rust,ignore
pub fn send_informational(&mut self, interim: &Response, out: &mut Vec<u8>) -> Result<(), HttpError>
```

Writes an interim response other than `100` and `101` (for example `103
Early Hints` with `link` fields) before the final response: any number of
times, for any method, until the final response starts, never to HTTP/1.0
(RFC 9110 section 15.2). Only the status line and fields are written; the
connection's state does not change. **Errors:** the builder's first error;
`InvalidStatus` outside `102..=199`; `BodyNotAllowed` for a body;
`InterimNotAllowed` for HTTP/1.0 or after the final response started;
`InvalidState` with no request to answer. **Ships:** 0.4.

```rust
use http_net::{HttpError, Response, ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
let mut out = Vec::new();
let hints = Response::new(103).header("link", "</app.css>; rel=preload; as=style");
conn.send_informational(&hints, &mut out)?;
conn.respond(&Response::text(200, "page"), &mut out)?;
assert!(out.starts_with(b"HTTP/1.1 103 Early Hints\r\nlink: </app.css>"));
assert_eq!(conn.send_informational(&hints, &mut out), Err(HttpError::InterimNotAllowed));
# Ok::<(), http_net::HttpError>(())
```

### `ServerConn::respond_with_date`

```rust,ignore
pub fn respond_with_date(&mut self, response: &Response, date: &HttpDate, out: &mut Vec<u8>) -> Result<(), HttpError>
```

As `respond`, adding `date: <date>` unless the response set its own. Pair
it with a per-thread [`DateCache`](#httpdate-and-datecache) so the value is
formatted once per second. **Errors:** as `respond`. **Ships:** 0.4.

```rust
use http_net::{DateCache, Response, ServerConn, ServerEvent};

let mut dates = DateCache::new();
let mut conn = ServerConn::new();
let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
let mut out = Vec::new();
conn.respond_with_date(&Response::new(204), dates.update(784_111_777), &mut out)?;
assert!(out.windows(35).any(|w| w == b"date: Sun, 06 Nov 1994 08:49:37 GMT"));
# Ok::<(), http_net::HttpError>(())
```

### Keep-alive control and progress

```rust,ignore
pub fn set_keep_alive(&mut self, keep: bool)
pub fn keep_alive(&self) -> bool
pub fn requests_served(&self) -> u64
pub fn progress(&self) -> Progress
pub fn set_report_trailers(&mut self, report: bool)
```

- `set_keep_alive(false)` makes the current response (or the next, if it
  has not started) carry `connection: close` and ends the connection after
  it: the gentlest load-shedding step. `true` cannot keep open a
  connection the protocol requires to close. `keep_alive()` says whether
  the connection can stay open after the current exchange, as far as is
  known now.
- `requests_served()` counts completed responses (full bodies when written,
  streamed ones at `end_body`), so a driver can cap requests per
  connection.
- `progress()` reports the phase for deadlines (see [`Progress`](#progress)).
- `set_report_trailers(true)` keeps a request's trailer fields and reports
  them as `ServerEvent::Trailers` before `RequestEnd`; by default they are
  validated and discarded.

**Ships:** 0.4.

```rust
use http_net::{Progress, Response, ServerConn, ServerEvent};

let mut conn = ServerConn::new();
conn.set_report_trailers(true);
let _ = conn.feed(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nDigest: sha-256=x\r\n\r\n");
let mut trailer = None;
loop {
    match conn.poll()? {
        ServerEvent::Trailers(t) => trailer = t.clone().next().map(|(n, v)| (n.to_string(), v.to_vec())),
        ServerEvent::RequestEnd => break,
        _ => {}
    }
}
assert_eq!(trailer, Some(("Digest".to_string(), b"sha-256=x".to_vec())));
assert_eq!(conn.progress(), Progress::AwaitingResponse);
conn.set_keep_alive(false);
let mut out = Vec::new();
conn.respond(&Response::new(204), &mut out)?;
assert!(out.windows(17).any(|w| w == b"connection: close"));
assert_eq!(conn.requests_served(), 1);
assert!(matches!(conn.poll()?, ServerEvent::Closed));
# Ok::<(), http_net::HttpError>(())
```

### Upgrades: `is_upgraded`, `remaining_input`

```rust,ignore
pub fn is_upgraded(&self) -> bool
pub fn remaining_input(&self) -> &[u8]
```

Whether a `101` (or a 2xx to `CONNECT`) was sent, and the unread input:
after `Upgraded`, the first bytes of the new protocol. **Ships:** exists.

```rust
use http_net::{Response, ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: x\r\n\r\n\x81\x00");
assert!(matches!(conn.poll().unwrap(), ServerEvent::Request(_)));
assert!(matches!(conn.poll().unwrap(), ServerEvent::RequestEnd));
conn.respond(&Response::switching_protocols("x"), &mut Vec::new()).unwrap();
assert!(matches!(conn.poll().unwrap(), ServerEvent::Upgraded));
assert!(conn.is_upgraded());
assert_eq!(conn.remaining_input(), b"\x81\x00");
```

### Reuse, pooling, and wiping

```rust,ignore
pub fn reset(&mut self)
pub fn with_buffer(storage: Vec<u8>, limits: Limits) -> ServerConn
pub fn into_buffer(self) -> Vec<u8>
pub fn shrink_idle(&mut self) -> bool
pub fn set_wipe(&mut self, wipe: bool)
```

- `reset()` returns the connection to its initial state for a new socket,
  keeping the buffer and field-index allocations and the limits, trailer
  reporting, and wipe settings. Everything per connection starts over:
  buffered input, the request in progress, keep-alive (allowed again), the
  request count.
- `with_buffer(storage, limits)` adopts pooled storage (its capacity used up
  to `Limits::buffer_capacity`, its contents ignored); `into_buffer()` gives
  it back.
- `shrink_idle()` frees the buffer and field indexes while the connection is
  idle with nothing buffered, so idle keep-alive connections cost only their
  struct; it returns whether memory was released, and the next input
  allocates again.
- `set_wipe(true)` zeroes the bytes of every finished request (head, body,
  framing) before the buffer is reused, zeroes the stale copies compaction
  leaves behind, and zeroes the whole buffer on `reset`, `into_buffer`, and
  drop, so credentials do not linger between requests (threat T-36). It
  costs a `memset` of each request's bytes, about 30 to 60 ns per 2 KiB (an
  estimate), and no allocation.

**Ships:** 0.5.

```rust
use http_net::{Limits, Response, ServerConn, ServerEvent};

let pooled = Vec::with_capacity(16 * 1024);
let mut conn = ServerConn::with_buffer(pooled, Limits::new());
conn.set_wipe(true);
let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nCookie: sid=secret\r\n\r\n");
while !matches!(conn.poll()?, ServerEvent::RequestEnd) {}
conn.respond(&Response::new(204), &mut Vec::new())?;
assert!(matches!(conn.poll()?, ServerEvent::NeedInput)); // the request's bytes are zeroed
assert!(conn.shrink_idle());
conn.reset(); // a new socket
let back = conn.into_buffer(); // back to the pool, zeroed
assert!(back.iter().all(|&b| b == 0));
# Ok::<(), http_net::HttpError>(())
```

### Tier-3 `ServerConn` methods

| Method | Behaviour | Errors | Ships |
|---|---|---|---|
| `write_head<O: Output>(&mut self, head: &ResponseHeadRef<'_>, date, out: &mut O) -> Result<BodyPlan, HttpError>` | allocation-free head writer from borrowed fields; see [`write_head`](#serverconnwrite_head-and-respond_into) | as `respond` | 0.5 |
| `respond_into<O: Output>(&mut self, response, date, out: &mut O)`, `send_body_into`, `end_body_into` | `respond`, `send_body`, `end_body_with_trailers` over any `Output` | as `respond` | 0.5 |
| `respond_head_only(&mut self, response, out) -> Result<BodyPlan, HttpError>` | writes only the head of a full-body response, so the driver can send head and body with one vectored write; see [`respond_head_only`](#serverconnrespond_head_only) | as `respond` | 0.6 |

## `ServerEvent`

```rust,ignore
#[non_exhaustive]
#[derive(Debug)]
pub enum ServerEvent<'a> {
    Request(RequestHead<'a>),
    Body(&'a [u8]),
    RequestEnd,
    NeedInput,
    AwaitingResponse,
    Upgraded,
    Closed,
    Trailers(Headers<'a>), // only with set_report_trailers(true)
}
```

| Variant | Meaning | What to do | Ships |
|---|---|---|---|
| `Request` | A request head arrived, after the whole head. | Inspect it; answer `expects_continue()`; you may respond now (closing afterwards if body bytes are unread). | exists |
| `Body` | A run of body bytes (chunked encoding removed), valid until the next `&mut` call. | Consume it. | exists |
| `Trailers` | The request's trailer fields, just before `RequestEnd`; only with `set_report_trailers(true)` and a non-empty trailer section. They never change framing. | Read them. | 0.4 |
| `RequestEnd` | The request is complete. | Respond if you have not. | exists |
| `NeedInput` | More input is needed. | Read and feed, or `feed_eof`. | exists |
| `AwaitingResponse` | The request is done; its response is not. Pipelined input waits. | Finish the response. | exists |
| `Upgraded` | The connection now speaks another protocol. | Take `remaining_input` and the socket. | exists |
| `Closed` | The connection is finished. | Flush output, close the socket. | exists |

The `Debug` output of `Request` redacts credential fields.

## `Progress`

```rust,ignore
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Progress { Idle, Head, Body, AwaitingResponse, WritingBody, Upgraded, Closed }
```

The phase of a connection, for drivers that run header-read, request, and
response deadlines. Returned by `ServerConn::progress` and
`ClientConn::progress`. **Ships:** 0.4.

| Phase | Server | Client |
|---|---|---|
| `Idle` | between requests, no byte of the next one seen (idle keep-alive time) | no request outstanding |
| `Head` | some bytes of a request head seen | some bytes of a response head seen |
| `Body` | head done, body bytes outstanding | response body in progress |
| `AwaitingResponse` | request complete (or nothing left to read), response not finished | request sent, nothing of the response yet |
| `WritingBody` | a streamed response is being written | a streamed request body is being written |
| `Upgraded` | the connection belongs to another protocol | as for the server |
| `Closed` | finished, or will be once the last response is written | finished |

```rust
use http_net::{Progress, ServerConn, ServerEvent};

let mut conn = ServerConn::new();
assert_eq!(conn.progress(), Progress::Idle);
let _ = conn.feed(b"GET / HTTP/1.1\r\n");
assert!(matches!(conn.poll(), Ok(ServerEvent::NeedInput)));
assert_eq!(conn.progress(), Progress::Head); // start the header deadline here
```

## `RequestHead`

```rust,ignore
#[derive(Clone, Copy)]
pub struct RequestHead<'a> { /* private */ }
impl core::fmt::Debug for RequestHead<'_>; // credential values redacted (0.3)
```

A parsed request head borrowed from the connection's buffer. Every accessor
is a slice of the bytes that arrived; nothing is copied. Valid until the
next `&mut` call on the connection; read it again with
[`ServerConn::request`](#serverconnrequest). Three references, 24 bytes.

```rust
use http_net::{Method, ServerConn, ServerEvent, TargetForm, Version};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET /search?q=rust HTTP/1.1\r\nHost: example.com\r\n\r\n");
let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
assert_eq!(req.method(), Method::Get);
assert_eq!(req.target_form(), TargetForm::Origin);
assert_eq!(req.path(), "/search");
assert_eq!(req.query(), Some("q=rust"));
assert_eq!(req.version(), Version::Http11);
assert_eq!(req.host(), Some("example.com"));
assert!(req.keep_alive());
```

### Method and target

| Method | Returns | Notes | Ships |
|---|---|---|---|
| `method()` | `Method` | Classified, case-sensitive (`get` is `Other`). | exists |
| `method_str()` | `&'a str` | Exactly as received. | exists |
| `target()` | `&'a str` | Exactly as received. | exists |
| `target_form()` | `TargetForm` | `Origin`, `Absolute`, `Authority`, `Asterisk`. | 0.3 |
| `path()` | `&'a str` | Target up to the first `?`, percent-encoding kept; absolute form: the path after the authority, `/` when empty; `*` and authority form: the whole target. | exists |
| `query()` | `Option<&'a str>` | After the first `?` (`Some("")` for `/a?`). | exists |
| `version()` | `Version` | | exists |

```rust
use http_net::{ServerConn, ServerEvent, TargetForm};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET http://a.test/files/b.txt?v=2 HTTP/1.1\r\nHost: b.test\r\n\r\n");
let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
assert_eq!(req.target_form(), TargetForm::Absolute);
assert_eq!(req.path(), "/files/b.txt");
assert_eq!(req.query(), Some("v=2"));
assert_eq!(req.host(), Some("a.test"));
assert_eq!(req.header("host"), Some(&b"b.test"[..]));
```

### Fields

| Method | Returns | Notes | Ships |
|---|---|---|---|
| `headers()` | `Headers<'a>` | All fields in arrival order; names as received, values OWS-trimmed bytes. | exists |
| `header(name)` | `Option<&'a [u8]>` | First field with this name, ASCII case-insensitive. | exists |
| `header_str(name)` | `Option<&'a str>` | Same, when UTF-8. | exists |
| `header_all(name)` | `HeaderValues<'a, '_>` | Every field with this name, in order (repeated `cookie` lines, `forwarded`, `via`). The values borrow the head, not the name. | 0.3 |
| `header_list(name)` | `ListElements<'a, '_>` | The elements of a `#list` field across all its lines (RFC 9110 section 5.6.1), trimmed, empty ones skipped; a comma inside a quoted string does not split an element. | 0.4 |
| `host()` | `Option<&'a str>` | Absolute-form authority if present, else the `Host` value (`Some("")` for an empty `Host`), `None` for HTTP/1.0 without `Host`. | exists |

Lookups are a linear scan of the field index: at most `max_headers`
comparisons, no hash map keyed by attacker data.

```rust
use http_net::{ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nAccept: text/html\r\nVia: 1.1 p1\r\nVia: 1.1 p2\r\n\r\n");
let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
assert_eq!(req.header("ACCEPT"), Some(&b"text/html"[..]));
assert_eq!(req.header("via"), Some(&b"1.1 p1"[..]));
let vias: Vec<&[u8]> = req.header_all("via").collect();
assert_eq!(vias, [&b"1.1 p1"[..], &b"1.1 p2"[..]]);
assert_eq!(req.header_all("cookie").count(), 0);

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nAccept: text/html, ,\r\nAccept: x/y;q=\"0.5,1\"\r\n\r\n");
let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
let accept: Vec<&[u8]> = req.header_list("accept").collect();
assert_eq!(accept, [&b"text/html"[..], b"x/y;q=\"0.5,1\""]);
```

### Framing and connection facts

| Method | Returns | Notes | Ships |
|---|---|---|---|
| `framing()` | `BodyFraming` | `None`, `Length(n)`, or `Chunked` (requests are never `UntilClose`). | exists |
| `content_length()` | `Option<u64>` | The parsed `Content-Length`; `Some(0)` is distinct from absent. | 0.3 |
| `keep_alive()` | `bool` | What the client allows (HTTP/1.1 unless `close`; HTTP/1.0 only with `keep-alive`). | exists |
| `expects_continue()` | `bool` | `100-continue` on an HTTP/1.1 request with a body. | exists |
| `has_unknown_expectation()` | `bool` | Any other `Expect` element (any version), so the caller can answer 417 (the blocking server does). Never changes framing. | 0.4 |
| `is_upgrade()` | `bool` | HTTP/1.1, `Connection: upgrade`, and an `Upgrade` offering at least one protocol other than `h2c`. | exists; 0.3 |
| `upgrade_protocols()` | `ListElements<'a, 'static>` | The offered protocols as product tokens, across every `Upgrade` line, `h2c` omitted; empty unless `is_upgrade()`. | 0.4 |
| `connection_options()` | `ListElements<'a, 'static>` | The `Connection` field's options across every line, in order; compare ASCII case-insensitively; pass to [`is_hop_by_hop`](#is_hop_by_hop). | 0.5 |

```rust
use http_net::{BodyFraming, ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let _ = conn.feed(b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n");
let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
assert_eq!(req.framing(), BodyFraming::None);
assert_eq!(req.content_length(), Some(0));

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAoAAA\r\n\r\n");
let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
assert!(!req.is_upgrade()); // h2c alone is not an upgrade offer

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: h2c, websocket/13\r\nExpect: x-fast\r\n\r\n");
let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
assert_eq!(req.upgrade_protocols().collect::<Vec<_>>(), [&b"websocket/13"[..]]);
assert!(req.has_unknown_expectation());
```

## `ResponseHead`

```rust,ignore
#[derive(Clone, Copy)]
pub struct ResponseHead<'a> { /* private */ }
impl core::fmt::Debug for ResponseHead<'_>; // set-cookie values redacted (0.3)
```

A parsed response head borrowed from the client connection's buffer.

| Method | Returns | Notes | Ships |
|---|---|---|---|
| `status()` | `u16` | `100..=599` | exists |
| `reason()` | `&'a str` | UTF-8 reason phrase or `""`; carries no meaning (RFC 9112 section 4). `""` also for a status line without the space after the code. | exists |
| `version()` | `Version` | | exists |
| `headers()`, `header(name)`, `header_str(name)` | as on `RequestHead` | | exists |
| `header_all(name)` | `HeaderValues<'a, '_>` | Each `Set-Cookie` is one field, never comma-joined: this is the cookie path. | 0.3 |
| `header_list(name)` | `ListElements<'a, '_>` | as on `RequestHead` | 0.4 |
| `framing()` | `BodyFraming` | after the `HEAD`, 1xx, 204, 304, and `CONNECT` rules | exists |
| `content_length()` | `Option<u64>` | the raw parsed `Content-Length` (also for a `HEAD` response, whose `framing()` is `None`) | 0.3 |
| `keep_alive()` | `bool` | whether the connection can carry another request after this response | exists |
| `is_informational()` | `bool` | whether this is a 1xx head (as reported by `ClientEvent::Informational`) | 0.4 |

```rust
use http_net::{ClientConn, ClientEvent, Request};

let mut conn = ClientConn::new();
conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new()).unwrap();
let _ = conn.feed(b"HTTP/1.1 200\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: 0\r\n\r\n");
let ClientEvent::Response(resp) = conn.poll().unwrap() else { panic!() };
assert_eq!(resp.status(), 200);
assert_eq!(resp.reason(), "");
let cookies: Vec<&[u8]> = resp.header_all("set-cookie").collect();
assert_eq!(cookies, [&b"a=1"[..], &b"b=2"[..]]);
assert!(!format!("{resp:?}").contains("a=1"));
```

## `Headers`

```rust,ignore
#[derive(Clone)]
pub struct Headers<'a> { /* private */ }
impl<'a> Iterator for Headers<'a> { type Item = (&'a str, &'a [u8]); }
impl ExactSizeIterator for Headers<'_> {}
impl core::fmt::Debug for Headers<'_>; // credential values redacted (0.3)
```

`(name, value)` in arrival order. Names as received (compare with
`eq_ignore_ascii_case`); values trimmed of surrounding whitespace, as bytes
(they may contain obs-text). **Ships:** exists; redacted `Debug` 0.3.

```rust
use http_net::{ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nX-One: 1\r\n\r\n");
let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
let names: Vec<&str> = req.headers().map(|(n, _)| n).collect();
assert_eq!(names, ["Host", "X-One"]);
assert_eq!(req.headers().len(), 2);
```

## `HeaderValues` and `ListElements`

```rust,ignore
#[derive(Clone)]
pub struct HeaderValues<'a, 'n> { /* private */ }
impl<'a> Iterator for HeaderValues<'a, '_> { type Item = &'a [u8]; }

#[derive(Clone)]
pub struct ListElements<'a, 'n> { /* private */ }
impl<'a> Iterator for ListElements<'a, '_> { type Item = &'a [u8]; }
```

`HeaderValues` yields the value of every field with one name, in arrival
order (`header_all`). The values borrow the head (`'a`), not the name
(`'n`), so a lookup with a temporary name keeps its values. **Ships:** 0.3.

`ListElements` yields the elements of a `#list` field across every line
with one name (`header_list`, `upgrade_protocols`, later
`connection_options`): trimmed of whitespace, empty elements skipped, and a
comma inside a quoted string (with backslash escapes) does not end an
element. **Ships:** 0.4.

The same quote-aware walk now splits the framing fields the crate reads
itself (`Connection`, `Transfer-Encoding`, `Expect`, `Upgrade`), as the
shared grammar crate `parse-net` will. In 0.3 a comma inside quotes split
an element; no message 0.3 accepted reads differently (the only list that
could hold quotes, `Transfer-Encoding: chunked;x="a,b"`, is refused either
way for its parameters).

```rust
use http_net::{ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive, X-Trace\r\n\r\n");
let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
let options: Vec<&[u8]> = req.header_list("connection").collect();
assert_eq!(options, [&b"keep-alive"[..], b"X-Trace"]);
```

## Spans, raw heads, owned heads

Tier 3: the zero-copy passport path for WASP and proxies. A view's head
bytes and the offsets of its parts are public, so the head can be copied
(or moved) somewhere else and read there without parsing it again. The
example `passport` runs the whole path across two threads.

```rust,ignore
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Span { pub start: u32, pub end: u32 }
impl Span {
    pub fn get<'b>(&self, head: &'b [u8]) -> &'b [u8];
    pub const fn len(&self) -> u32;
    pub const fn is_empty(&self) -> bool;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FieldSpan { pub name: Span, pub value: Span }

impl<'a> RequestHead<'a> { pub fn raw(&self) -> RawHead<'a>; }
impl<'a> ResponseHead<'a> { pub fn raw(&self) -> RawHead<'a>; }
#[derive(Clone, Copy)]
pub struct RawHead<'a> { /* private */ }
impl<'a> RawHead<'a> {
    pub fn bytes(&self) -> &'a [u8];
    pub fn start_line(&self) -> Span;
    pub fn method(&self) -> Span;   // request heads; empty for responses
    pub fn target(&self) -> Span;   // request heads; empty for responses
    pub fn version(&self) -> Span;
    pub fn status(&self) -> Span;   // response heads; empty for requests
    pub fn fields(&self) -> &'a [FieldSpan];
}

impl RequestHead<'_> {
    pub fn copy_into(&self, bytes: &mut Vec<u8>, fields: &mut Vec<FieldSpan>) -> Result<HeadFacts, HttpError>;
    pub fn to_owned(&self) -> OwnedRequestHead;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadFacts { /* private */ }

#[derive(Clone, PartialEq, Eq)]
pub struct OwnedRequestHead { /* private */ }
impl OwnedRequestHead {
    pub fn view(&self) -> RequestHead<'_>;
    pub fn from_parts(bytes: Vec<u8>, fields: Vec<FieldSpan>, facts: HeadFacts) -> Result<Self, HttpError>;
    pub fn into_parts(self) -> (Vec<u8>, Vec<FieldSpan>, HeadFacts);
}
```

| Item | Behaviour | Ships |
|---|---|---|
| `Span`, `FieldSpan` | `u32` offsets relative to `RawHead::bytes()`; `get` returns an empty slice for an out-of-range span and never panics; a field's value span is OWS-trimmed | 0.5 |
| `raw`, `RawHead` | the head bytes and spans behind a view; the bytes can be moved and the spans stay valid | 0.5 |
| `copy_into`, `HeadFacts` | copies the head (one copy) and spans into caller-owned reused vectors, cleared first, and returns the interpreted facts, so a passport rebuilds a view without re-parsing (decision OD-12); no allocation once the vectors have grown | 0.5 |
| `to_owned`, `OwnedRequestHead`, `view`, `from_parts`, `into_parts` | an owned copy; `from_parts` re-validates every span and the line structure and refuses a tampered passport buffer with `InvalidState`; `into_parts` hands the vectors back for reuse | 0.5 |
| `KnownField`, `known` | constant-time lookup of frequent fields through an index filled while parsing; kept only if it costs at most 2% on the head benchmark | after 1.0 |

`RawHead::bytes()` runs from the first byte the connection kept for this
head to the end of the blank line. A request may be preceded by empty
lines (RFC 9112 section 2.2 lets a server ignore them); they stay in
`bytes()` and `start_line()` begins after them, so every span is relative
to the same slice. A copy keeps them too, and `from_parts` accepts them.

```rust
use http_net::{ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET /a?b HTTP/1.1\r\nHost: example.com\r\nAccept:  */* \r\n\r\n");
let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
let raw = req.raw();
let head = raw.bytes();
assert_eq!(raw.method().get(head), b"GET");
assert_eq!(raw.target().get(head), b"/a?b");
assert_eq!(raw.version().get(head), b"HTTP/1.1");
let accept = raw.fields()[1];
assert_eq!(accept.name.get(head), b"Accept");
assert_eq!(accept.value.get(head), b"*/*"); // trimmed
assert_eq!(head.len(), 55);
```

The passport path: copy into reused vectors, rebuild a view anywhere,
give the vectors back.

```rust
use http_net::{OwnedRequestHead, ServerConn, ServerEvent};

let (mut bytes, mut fields) = (Vec::with_capacity(4096), Vec::with_capacity(64));
let mut conn = ServerConn::new();
let _ = conn.feed(b"GET /x HTTP/1.1\r\nHost: a\r\nX-Trace: 7\r\n\r\n");
let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
let facts = req.copy_into(&mut bytes, &mut fields)?;

let owned = OwnedRequestHead::from_parts(bytes, fields, facts)?;
assert_eq!(owned.view().header_str("x-trace"), Some("7"));
let (bytes, fields, _) = owned.into_parts(); // back to the pool
assert!(bytes.capacity() >= 4096 && fields.capacity() >= 64);
# Ok::<(), http_net::HttpError>(())
```

A changed buffer is refused, never read:

```rust
use http_net::{HttpError, OwnedRequestHead, ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
let (mut bytes, mut fields) = (Vec::new(), Vec::new());
let facts = req.copy_into(&mut bytes, &mut fields)?;
fields[0].value.end += 4; // the value now runs past its line
assert!(matches!(
    OwnedRequestHead::from_parts(bytes, fields, facts),
    Err(HttpError::InvalidState(_))
));
# Ok::<(), http_net::HttpError>(())
```

`from_parts` checks structure, not meaning: it does not recompute the
framing facts (body length, keep-alive), which come from the same copy.
A head built by hand from bytes the parser never saw should go through
[`parse_request_head`](#stateless-head-parsers) instead.

## Stateless head parsers

Tier 3. One complete head from a caller slice, with the connection's exact
rules (the same scanner and checks, not a copy of them), into a caller
array of field spans. No state, no allocation, no buffer: for proxies,
differential tests, and engines that frame messages themselves.

```rust,ignore
pub fn parse_request_head<'a>(input: &'a [u8], limits: &Limits, fields: &'a mut [FieldSpan])
    -> Result<Parsed<ParsedRequest<'a>>, HttpError>;
pub fn parse_response_head<'a>(input: &'a [u8], limits: &Limits, asked: Asked, fields: &'a mut [FieldSpan])
    -> Result<Parsed<ParsedResponse<'a>>, HttpError>;

#[non_exhaustive]
#[derive(Debug)]
pub enum Parsed<T> { Complete { head: T, len: usize }, Partial }

pub struct ParsedRequest<'a> { /* private */ }
impl ParsedRequest<'_> {
    pub fn view(&self) -> RequestHead<'_>;
    pub fn facts(&self) -> HeadFacts;
}
pub struct ParsedResponse<'a> { /* private */ }
impl ParsedResponse<'_> { pub fn view(&self) -> ResponseHead<'_>; }

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Asked { pub head: bool, pub connect: bool }
```

| Item | Behaviour | Errors | Ships |
|---|---|---|---|
| `parse_request_head` | `Complete` with the view and the head's length (`input[len..]` is the body or the next head) once the blank line is in; `Partial` while it is not, where a connection would ask for more input | the connection's head errors; `TooManyHeaders` also when the head has more fields than `fields.len()` | 0.5 |
| `parse_response_head` | as above for a response; `asked` says what the request was, which decides the framing (`HEAD` and a `2xx` to `CONNECT` have no body); interim (`1xx`) heads are returned like any other | the connection's head errors | 0.5 |
| `Parsed`, `ParsedRequest`, `ParsedResponse` | the outcome and the parsed heads; `view()` gives the same accessors a connection's head has | none | 0.5 |
| `Asked` | the request facts a response parser needs; `Asked::default()` is a plain request | none | 0.5 |

The field array bounds the head as well as `Limits::max_headers`: with a
smaller array, a head with more fields is `TooManyHeaders` rather than
cut short.

```rust
use http_net::{FieldSpan, HttpError, Limits, Parsed, parse_request_head};

let input = b"POST /api HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhi";
let mut fields = [FieldSpan::default(); 32];
let Parsed::Complete { head, len } = parse_request_head(input, &Limits::default(), &mut fields)?
else {
    panic!("the head is complete");
};
assert_eq!(head.view().content_length(), Some(2));
assert_eq!(&input[len..], b"hi");

// Not all there yet.
let mut fields = [FieldSpan::default(); 32];
assert!(matches!(
    parse_request_head(&input[..20], &Limits::default(), &mut fields)?,
    Parsed::Partial
));

// Two fields, one slot.
let mut one = [FieldSpan::default(); 1];
assert_eq!(
    parse_request_head(input, &Limits::default(), &mut one).unwrap_err(),
    HttpError::TooManyHeaders
);
# Ok::<(), HttpError>(())
```

```rust
use http_net::{Asked, BodyFraming, FieldSpan, Limits, Parsed, parse_response_head};

let input = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
let mut fields = [FieldSpan::default(); 8];
let asked = Asked { head: true, ..Asked::default() };
let Parsed::Complete { head, .. } = parse_response_head(input, &Limits::default(), asked, &mut fields)?
else {
    panic!("the head is complete");
};
// The response to HEAD has no body, whatever Content-Length says.
assert_eq!(head.view().framing(), BodyFraming::None);
assert_eq!(head.view().content_length(), Some(5));
# Ok::<(), http_net::HttpError>(())
```

## `Method`

```rust,ignore
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Method { Get, Head, Post, Put, Delete, Connect, Options, Trace, Patch, Other }
```

The RFC 9110 methods plus `PATCH` (RFC 5789); anything else is `Other`, with
the text in `RequestHead::method_str`. A variant is added only when an RFC
registers the method (OD-10).

| Method | Returns | Notes | Ships |
|---|---|---|---|
| `from_bytes(token: &[u8])` | `Method` | case-sensitive classification | exists |
| `as_str(&self)` | `Option<&'static str>` | `None` for `Other` | exists |
| `is_safe(&self)` | `bool` | GET, HEAD, OPTIONS, TRACE (RFC 9110 section 9.2.1); `Other` is not (the caller decides from `method_str`) | 0.3 |
| `is_idempotent(&self)` | `bool` | the safe methods plus PUT and DELETE (section 9.2.2) | 0.3 |
| `index(&self)` | `u8` | dense `0..=9` in declaration order (`Other` = 9), for bit sets and tables | 0.3 |

```rust
use http_net::Method;

assert_eq!(Method::from_bytes(b"GET"), Method::Get);
assert_eq!(Method::from_bytes(b"get"), Method::Other);
assert_eq!(Method::Post.as_str(), Some("POST"));
assert!(Method::Head.is_safe());
assert!(Method::Put.is_idempotent() && !Method::Put.is_safe());
assert!(!Method::Post.is_idempotent());
assert_eq!(Method::Get.index(), 0);
assert_eq!(Method::Other.index(), 9);
```

## `MethodSet`

```rust,ignore
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct MethodSet { /* private: u16 */ }
impl MethodSet {
    pub const EMPTY: MethodSet;
    pub const fn of(methods: &[Method]) -> MethodSet;
    pub const fn with(self, method: Method) -> MethodSet;
    pub const fn contains(&self, method: Method) -> bool;
    pub const fn union(self, other: MethodSet) -> MethodSet;
    pub const fn is_empty(&self) -> bool;
    pub fn iter(&self) -> impl Iterator<Item = Method>;
    pub fn write_allow(&self, out: &mut Vec<u8>);
}
```

A bit set of methods, one AND per membership check: for routers and for the
`Allow` field of a `405`. `Other` cannot be represented precisely, so
`contains(Method::Other)` means "some extension method is allowed".
`write_allow` writes the registered members in `index` order separated by
`", "` (`Other` is skipped, it has no name). **Ships:** 0.3.

```rust
use http_net::{Method, MethodSet, Response};

const READ: MethodSet = MethodSet::of(&[Method::Get, Method::Head]);
let allowed = READ.with(Method::Post);
assert!(allowed.contains(Method::Post));
assert!(!allowed.contains(Method::Delete));
assert_eq!(allowed.iter().count(), 3);

let mut allow = Vec::new();
allowed.write_allow(&mut allow);
assert_eq!(allow, b"GET, HEAD, POST");
let resp = Response::new(405).header("allow", &allow);
assert_eq!(resp.header_value("allow"), Some(&b"GET, HEAD, POST"[..]));
```

## `Version`

```rust,ignore
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Version { Http10, Http11 }
impl Version { pub const fn as_str(&self) -> &'static str; }
```

`as_str()` gives `"HTTP/1.0"` / `"HTTP/1.1"`. Requests with `HTTP/1.2` to
`HTTP/1.9` are processed as 1.1 (RFC 9110 section 2.5); other majors are
`UnsupportedVersion`. **Ships:** exists.

```rust
assert_eq!(http_net::Version::Http11.as_str(), "HTTP/1.1");
```

## `BodyFraming`

```rust,ignore
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BodyFraming { None, Length(u64), Chunked, UntilClose }
```

How a body is delimited. `UntilClose` occurs only for responses.
`Content-Length: 0` reports `None` (OD-22: `framing()` answers "is there a
body", `content_length()` answers "what was declared"). **Ships:** exists.

## `TargetForm`

```rust,ignore
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TargetForm { Origin, Absolute, Authority, Asterisk }
```

The four request-target forms of RFC 9112 section 3.2, from
`RequestHead::target_form`. **Ships:** 0.3.

```rust
use http_net::{ServerConn, ServerEvent, TargetForm};

let mut conn = ServerConn::new();
let _ = conn.feed(b"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n");
let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
assert_eq!(req.target_form(), TargetForm::Asterisk);
```

## Status codes

Status codes stay plain `u16` (OD-9), with names from the
[`status`](#status-constants) module.

### `reason_phrase`

```rust,ignore
pub const fn reason_phrase(status: u16) -> &'static str
```

The canonical phrase for every code in the IANA HTTP Status Code Registry
(RFC 9110 names: `413 Content Too Large`, `422 Unprocessable Content`), or
`""` for an unassigned code. 0.3 completes the registry: `102`, `103`,
`207`, `208`, `226`, `305`, `402`, `407`, `423`, `424`, `425`, `451`, `506`,
`507`, `508`, `510`, `511`. `306` and `418` are reserved / unused in the
registry (RFC 9110 sections 15.4.7 and 15.5.19) and return `""`.
**Ships:** exists; 0.3.

```rust
use http_net::reason_phrase;

assert_eq!(reason_phrase(404), "Not Found");
assert_eq!(reason_phrase(103), "Early Hints");
assert_eq!(reason_phrase(451), "Unavailable For Legal Reasons");
assert_eq!(reason_phrase(418), "");
assert_eq!(reason_phrase(299), "");
```

### `StatusClass` and `status_class`

```rust,ignore
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StatusClass { Informational, Success, Redirection, ClientError, ServerError }
pub const fn status_class(status: u16) -> Option<StatusClass>
```

The class of a code; `None` outside `100..=599`. **Ships:** 0.3.

```rust
use http_net::{StatusClass, status_class};

assert_eq!(status_class(204), Some(StatusClass::Success));
assert_eq!(status_class(503), Some(StatusClass::ServerError));
assert_eq!(status_class(99), None);
```

### `status` constants

```rust,ignore
pub mod status {
    pub const CONTINUE: u16 = 100;
    pub const SWITCHING_PROTOCOLS: u16 = 101;
    pub const EARLY_HINTS: u16 = 103;
    pub const OK: u16 = 200;
    // ... one constant for every registered code
}
```

Named `u16` constants for every registered code, named after the RFC
phrase in upper snake case (`CONTENT_TOO_LARGE`, `UNPROCESSABLE_CONTENT`,
`IM_USED`). **Ships:** 0.3.

```rust
use http_net::{Response, status};

let r = Response::new(status::NO_CONTENT);
assert_eq!(r.status(), 204);
assert_eq!(status::REQUEST_HEADER_FIELDS_TOO_LARGE, 431);
```

### `status_allows_body`

```rust,ignore
pub const fn status_allows_body(status: u16, request: Method) -> bool
```

False for 1xx, 204, 304, a `HEAD` request, and 2xx to `CONNECT` (RFC 9112
section 6.3 rules 1 and 2), for proxies and fetch-net. **Ships:** 0.4.

```rust
use http_net::{Method, status_allows_body};

assert!(status_allows_body(200, Method::Get));
assert!(!status_allows_body(200, Method::Head));
assert!(!status_allows_body(304, Method::Get));
assert!(!status_allows_body(200, Method::Connect));
assert!(status_allows_body(407, Method::Connect));
```

## `HttpDate` and `DateCache`

```rust,ignore
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HttpDate { /* [u8; 29] */ }
impl HttpDate {
    pub const fn from_unix_seconds(secs: u64) -> HttpDate; // IMF-fixdate, years clamped to 9999
    pub const fn as_bytes(&self) -> &[u8; 29];
    pub fn as_str(&self) -> &str;
}
impl Display for HttpDate;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DateCache { /* last second, formatted value */ }
impl DateCache {
    pub const fn new() -> DateCache;
    pub fn update(&mut self, unix_seconds: u64) -> &HttpDate; // reformats only when the second changed
    pub const fn current(&self) -> &HttpDate;
}
// feature std
pub fn blocking::now_date() -> HttpDate; // thread-local DateCache over SystemTime
```

The `Date` field value (IMF-fixdate, RFC 9110 section 5.6.7), and a cache
that formats it at most once per second. The core takes the time from the
caller (it has no clock and stays `no_std`); `blocking::now_date` wraps the
system clock with one cache per thread, so nothing is shared. Times after
the year 9999 show its last second. **Ships:** 0.4.

```rust
use http_net::{DateCache, HttpDate};

assert_eq!(HttpDate::from_unix_seconds(784_111_777).as_str(), "Sun, 06 Nov 1994 08:49:37 GMT");
let mut cache = DateCache::new();
let first = *cache.update(1_000_000_000);
assert_eq!(cache.update(1_000_000_000), &first); // same second: not reformatted
assert_ne!(cache.update(1_000_000_001), &first);
```

## `Response`

```rust,ignore
#[derive(Clone, PartialEq, Eq)]
pub struct Response { /* private */ }
impl core::fmt::Debug for Response; // set-cookie (and any credential field) redacted (0.3)
```

An outgoing response. Builder methods validate as they go and remember the
first problem; it is returned when the response is written. Framing fields
(`content-length`, `transfer-encoding`, `connection`, `upgrade`) are refused
with `ReservedHeader`: the connection writes them.

| Method | Notes | Ships |
|---|---|---|
| `new(status: u16) -> Response` | empty body; status validated when written; allocates nothing until a field is added | exists |
| `text(status: u16, text: &str) -> Response` | `content-type: text/plain; charset=utf-8`, body copied | exists |
| `from_error(error: &HttpError) -> Response` | the answer to a request parse error; see below | 0.3 |
| `switching_protocols(protocol: &str) -> Response` | 101 with `connection: upgrade` and `upgrade: <protocol>` | exists; 0.3 |
| `header(self, name: &str, value: impl AsRef<[u8]>) -> Response` | token name; no reserved name; no CR, LF, or other controls; no leading or trailing whitespace; `date` marks the date as set | exists |
| `body(self, body: impl Into<Cow<'static, [u8]>>) -> Response` | full body sent with `content-length`; static data borrowed, `Vec` moved | exists |
| `chunked(self) -> Response` | stream with `send_body` / `end_body` (close-delimited to HTTP/1.0) | exists |
| `content_length(self, len: u64) -> Response` | stream exactly `len` bytes | exists |
| `close(self) -> Response` | `connection: close`; end the connection after this response | exists |
| `status(&self) -> u16`, `closes(&self) -> bool` | | exists |
| `body_bytes(&self) -> Option<&[u8]>` | `None` for a streamed body | exists |
| `header_value(&self, name: &str) -> Option<&[u8]>` | first added field with that name | exists |
| `clear(&mut self, status: u16)` | reset for reuse, keeping the field allocation: no fields, an empty body, no close, no upgrade, no remembered error | 0.5 |

```rust
use http_net::Response;

let mut reused = Response::new(404).header("x-a", "1").close();
reused.clear(200);
assert_eq!((reused.status(), reused.closes(), reused.header_value("x-a")), (200, false, None));

let asset = Response::new(200)
    .header("content-type", "text/css")
    .header("cache-control", "max-age=31536000, immutable")
    .body(&b"body { margin: 0 }"[..]);
assert_eq!(asset.header_value("content-type"), Some(&b"text/css"[..]));

let r = Response::new(200).header("set-cookie", "sid=abc123; HttpOnly");
assert!(!format!("{r:?}").contains("abc123"));
```

### `Response::from_error`

```rust,ignore
pub fn from_error(error: &HttpError) -> Response
```

The response a server sends after `poll` returned a parse error:
`error.status()` (400 when it is `None`), a short `text/plain` body from
the error's `Display` (static text only, never input bytes), and `close`.
**Ships:** 0.3.

```rust
use http_net::{HttpError, Response};

let r = Response::from_error(&HttpError::HeadersTooLarge);
assert_eq!(r.status(), 431);
assert!(r.closes());
assert_eq!(Response::from_error(&HttpError::UnexpectedEof).status(), 400);
```

### `Response::switching_protocols`

```rust,ignore
pub fn switching_protocols(protocol: &str) -> Response
```

A `101 Switching Protocols` handing the connection to `protocol`. Add
protocol-specific fields (such as `sec-websocket-accept`) with `header`.
**Errors** (when written): `InvalidHeaderValue` if `protocol` is not a
token (a `name/version` product token is accepted); `UpgradeNotOffered` if
it is `h2c` or the request did not offer it (0.3). **Ships:** exists; 0.3.

```rust
let r = http_net::Response::switching_protocols("websocket")
    .header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
assert_eq!(r.status(), 101);
assert_eq!(r.header_value("upgrade"), Some(&b"websocket"[..]));
```

```rust
use http_net::{HttpError, Response, ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n");
while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
let mut out = Vec::new();
assert_eq!(
    conn.respond(&Response::switching_protocols("ftp"), &mut out),
    Err(HttpError::UpgradeNotOffered)
);
conn.respond(&Response::switching_protocols("WebSocket"), &mut out).unwrap();
assert!(conn.is_upgraded());
```

## `Request`

```rust,ignore
#[derive(Clone, PartialEq, Eq)]
pub struct Request { /* private */ }
impl core::fmt::Debug for Request; // authorization, proxy-authorization, cookie redacted (0.3)
```

An outgoing request for `ClientConn::send_request`; the request line always
says HTTP/1.1.

| Method | Notes | Ships |
|---|---|---|
| `new(method: &str, target: &str) -> Request` | method must be a token; the target must be in a form the method allows | exists |
| `get(target)`, `post(target)` | shorthands | exists |
| `head(target)`, `put(target)`, `delete(target)`, `options(target)` | shorthands | 0.3 |
| `header(self, name, value) -> Request` | as for `Response`; `host` validated and allowed once | exists |
| `body`, `chunked`, `content_length`, `close` | as for `Response`; an empty full body omits `content-length` except on POST, PUT, PATCH | exists |
| `upgrade(self, protocol: &str) -> Request` | writes `connection: upgrade` and `upgrade: <protocol>`; `h2c` refused from 0.3 | exists; 0.3 |
| `method(&self) -> &str`, `target(&self) -> &str` | | exists |
| `body_bytes`, `header_value` | as for `Response` | exists |
| `expect_continue(self) -> Request` | adds `expect: 100-continue` and makes the connection wait for `100` before the body; needs a streamed body (`content_length` or `chunked`) | 0.4 |
| `forward_from(head: &RequestHead<'_>) -> Request` | a request for an upstream with the hop-by-hop fields removed (RFC 9110 section 7.6.1); see [below](#requestforward_from) | 0.5 |

```rust
use http_net::Request;

let get = Request::get("/index.html").header("host", "example.com");
let put = Request::put("/files/a").header("host", "example.com").body(&b"data"[..]);
let opts = Request::options("*").header("host", "example.com");
assert_eq!(get.method(), "GET");
assert_eq!(put.method(), "PUT");
assert_eq!(opts.target(), "*");

let auth = Request::get("/").header("host", "a").header("authorization", "Bearer t0k3n");
assert!(!format!("{auth:?}").contains("t0k3n"));
```

### `Request::upgrade`

```rust
use http_net::{ClientConn, HttpError, Request};

let r = Request::get("/rpc").header("host", "a").upgrade("websocket");
assert_eq!(r.header_value("upgrade"), Some(&b"websocket"[..]));

let h2c = Request::get("/").header("host", "a").upgrade("h2c");
let mut conn = ClientConn::new();
assert_eq!(conn.send_request(&h2c, &mut Vec::new()), Err(HttpError::UpgradeNotOffered));
```

### `Request::forward_from`

```rust,ignore
pub fn forward_from(head: &RequestHead<'_>) -> Request
```

A request for an upstream server, built from a received head (the proxy
path: requests are re-serialized, never passed through as raw bytes). It
keeps the method and the target as received, and every field except the
hop-by-hop ones (RFC 9110 section 7.6.1: `connection`, `keep-alive`,
`proxy-connection`, `te`, `transfer-encoding`, `upgrade`, `trailer`, and
any name the head's `Connection` lists) in their original order.
`content-length` is not copied: the body mode follows the head's framing
(chunked stays chunked, a length stays that length; stream the body with
`ClientConn::send_body`) and the connection writes the framing field
itself. An absolute-form target stays absolute (origin servers accept it,
RFC 9112 section 3.2.2); rebuild with `Request::new` for origin form. Add
`via` and forwarding fields with `header`. **Errors** (at `send_request`):
`InvalidState` for an upgrade request (tunnel it instead); the builders'
errors, such as `MissingHost` for an HTTP/1.0 head without `Host`.
**Ships:** 0.5.

```rust
use http_net::{ClientConn, Request, ServerConn, ServerEvent};

let mut downstream = ServerConn::new();
let _ = downstream.feed(b"POST /api HTTP/1.1\r\nHost: app\r\nConnection: X-Hop\r\nX-Hop: 1\r\nKeep-Alive: timeout=5\r\nAccept: */*\r\nContent-Length: 2\r\n\r\nhi");
let ServerEvent::Request(head) = downstream.poll()? else { unreachable!() };
let forwarded = Request::forward_from(&head).header("via", "1.1 proxy");
let mut upstream = ClientConn::new();
let mut out = Vec::new();
upstream.send_request(&forwarded, &mut out)?;
assert_eq!(out, b"POST /api HTTP/1.1\r\nHost: app\r\nAccept: */*\r\nvia: 1.1 proxy\r\ncontent-length: 2\r\n\r\n");
# Ok::<(), http_net::HttpError>(())
```

### `Request::expect_continue`

```rust,ignore
pub fn expect_continue(self) -> Request
```

Sends `expect: 100-continue` and holds the body back until the server
agrees (RFC 9110 section 10.1.1), so a large upload can be refused from the
head alone. The body must be streamed (`content_length` or `chunked`);
`send_request` refuses a full body with `InvalidState`, because a full body
would be written at once. Send the body after `ClientEvent::Continue`, or
after a wait of your own (the RFC allows sending without waiting). A final
status instead of `100` means the server does not want the body: `send_body`
then fails with `InvalidState`, and the connection closes after the
response. **Ships:** 0.4.

```rust
use http_net::{ClientConn, ClientEvent, HttpError, Request};

let mut conn = ClientConn::new();
let mut out = Vec::new();
let upload = Request::put("/big").header("host", "a").content_length(4).expect_continue();
conn.send_request(&upload, &mut out)?;
assert!(conn.is_waiting_for_continue());
let _ = conn.feed(b"HTTP/1.1 100 Continue\r\n\r\n");
assert!(matches!(conn.poll()?, ClientEvent::Continue));
conn.send_body(b"data", &mut out)?;
conn.end_body(&mut out)?;

// Refused from the head alone: the body is never sent.
let mut conn = ClientConn::new();
conn.send_request(&upload, &mut out)?;
let _ = conn.feed(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n");
assert!(matches!(conn.poll()?, ClientEvent::Response(r) if r.status() == 413));
assert!(matches!(conn.send_body(b"data", &mut out), Err(HttpError::InvalidState(_))));
assert!(matches!(conn.poll()?, ClientEvent::ResponseEnd));
assert!(matches!(conn.poll()?, ClientEvent::Closed));
# Ok::<(), http_net::HttpError>(())
```

## `ClientConn`

```rust,ignore
pub struct ClientConn { /* private */ }
impl Default for ClientConn;
impl core::fmt::Debug for ClientConn; // state, buffered length, limits; never bytes
```

The client side of one HTTP/1.1 connection: one outstanding request at a
time; `Send + Sync`.

| Method | Signature | Notes | Ships |
|---|---|---|---|
| `new` | `fn new() -> ClientConn` | default limits | exists |
| `with_limits` | `fn with_limits(limits: Limits) -> ClientConn` | limits on responses | exists |
| `limits` | `fn limits(&self) -> &Limits` | | exists |
| `feed`, `read_buf`, `commit` | as on `ServerConn` | | exists |
| `feed_eof` | `fn feed_eof(&mut self)` | ends an until-close body; mid-message it is `UnexpectedEof` | exists |
| `send_request` | `fn send_request(&mut self, request: &Request, out: &mut Vec<u8>) -> Result<(), HttpError>` | see below | exists |
| `send_body`, `end_body` | as on `ServerConn` | streamed request bodies | exists |
| `poll` | `fn poll(&mut self) -> Result<ClientEvent<'_>, HttpError>` | parse errors close the connection | exists |
| `response` | `fn response(&self) -> Option<ResponseHead<'_>>` | current final response head | exists |
| `is_upgraded`, `remaining_input` | as on `ServerConn` | after `Upgraded`: the new protocol's first bytes | exists |

The response is framed by the request: a `HEAD` request's response has no
body whatever its fields say, a `CONNECT` 2xx becomes a tunnel, and a
response with neither `Content-Length` nor `Transfer-Encoding` runs until
the server closes. A status line without the space after the code
(`HTTP/1.1 200` CRLF) is accepted from 0.3 (real servers send it; it cannot
change framing). Interim responses (100, 103) are skipped unless
`set_report_informational(true)`; they count against `max_interim`
(`TooManyInterim`) and together against `max_header_bytes`
(`HeadersTooLarge`), so a server cannot keep the client parsing interim
responses forever. A `101` that the
request did not ask for, or one without `Upgrade`, is `UnexpectedUpgrade`.
Bytes that arrive after a complete response, with no request outstanding,
are `UnexpectedData` (never queued as the next response).

### `ClientConn::send_request`

Writes `request` into `out` and waits for its response. A full body is
sent with `content-length` (omitted for an empty body unless the method is
POST, PUT, or PATCH); a streamed body continues with `send_body` and
`end_body`. **Errors:** the builder's first error; `MissingHost` without a
`host` field; `InvalidState` while a request is outstanding or after the
connection closed or upgraded; `UnexpectedData` if unsolicited bytes are
buffered. **Ships:** exists.

```rust
use http_net::{ClientConn, ClientEvent, HttpError, Request};

let mut conn = ClientConn::new();
let mut out = Vec::new();
assert_eq!(conn.send_request(&Request::get("/"), &mut out), Err(HttpError::MissingHost));
conn.send_request(&Request::post("/f").header("host", "a").body(&b"xyz"[..]), &mut out).unwrap();
assert_eq!(out, b"POST /f HTTP/1.1\r\nhost: a\r\ncontent-length: 3\r\n\r\nxyz");

let _ = conn.feed(b"HTTP/1.1 204 No Content\r\n\r\n");
assert!(matches!(conn.poll().unwrap(), ClientEvent::Response(_)));
assert!(matches!(conn.poll().unwrap(), ClientEvent::ResponseEnd));
assert!(matches!(conn.poll().unwrap(), ClientEvent::Idle));
```

### Interim responses, `Expect`, trailers, and reuse

```rust,ignore
pub fn set_report_informational(&mut self, report: bool)
pub fn is_waiting_for_continue(&self) -> bool
pub fn set_report_trailers(&mut self, report: bool)
pub fn end_body_with_trailers(&mut self, trailers: &[(&str, &[u8])], out: &mut Vec<u8>) -> Result<(), HttpError>
pub fn is_reusable(&self) -> bool
pub fn progress(&self) -> Progress
```

- `set_report_informational(true)` reports each 1xx other than `101` as
  `ClientEvent::Informational` (103 hints, 102 progress); by default they
  are skipped. A `100` to a request built with `expect_continue` is always
  reported, as `ClientEvent::Continue`.
- `is_waiting_for_continue()` is true after sending an `expect_continue`
  request until a `100`, a final response, or the first `send_body`.
- `set_report_trailers(true)` reports a response's trailer fields as
  `ClientEvent::Trailers` before `ResponseEnd`.
- `end_body_with_trailers` ends a chunked request body with trailers (the
  same forbidden list as on the server; `TrailerNotAllowed` for a body that
  is not chunked).
- `is_reusable()`: another request can be sent now.
- `progress()`: the phase, for response deadlines.

**Ships:** 0.4.

```rust
use http_net::{ClientConn, ClientEvent, Progress, Request};

let mut conn = ClientConn::new();
conn.set_report_informational(true);
conn.set_report_trailers(true);
conn.send_request(&Request::get("/page").header("host", "a"), &mut Vec::new())?;
assert_eq!(conn.progress(), Progress::AwaitingResponse);
let _ = conn.feed(b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nServer-Timing: db;dur=5\r\n\r\n");
let mut seen = Vec::new();
loop {
    match conn.poll()? {
        ClientEvent::Informational(h) => seen.push(format!("hint {}", h.status())),
        ClientEvent::Response(r) => seen.push(format!("response {}", r.status())),
        ClientEvent::Body(b) => seen.push(format!("body {}", b.len())),
        ClientEvent::Trailers(t) => seen.push(format!("trailers {}", t.len())),
        ClientEvent::ResponseEnd => break,
        _ => {}
    }
}
assert_eq!(seen, ["hint 103", "response 200", "body 2", "trailers 1"]);
assert!(conn.is_reusable());
# Ok::<(), http_net::HttpError>(())
```

### Pipelining

```rust,ignore
pub fn outstanding(&self) -> usize
pub fn can_send(&self) -> bool
```

With [`Limits::with_pipeline_depth`](#limitswith_pipeline_depth) above 1, a
client may send more requests before the first response arrives; responses
are matched to them in order, from a fixed array (no allocation after
construction). Only idempotent requests with a full body are pipelined, and
nothing goes behind a request that streams its body, asks to close,
upgrades, uses `CONNECT`, or expects `100 Continue` (RFC 9112 section 9.3.2:
a client should not pipeline non-idempotent requests). `can_send()` says
whether `send_request` would accept another request now; `outstanding()`
counts requests whose response has not completed. If the server closes the
connection mid-pipeline, `outstanding()` reports how many requests got no
response, to retry on a new connection. **Ships:** 0.5.

```rust
use http_net::{ClientConn, ClientEvent, Limits, Request};

let mut conn = ClientConn::with_limits(Limits::new().with_pipeline_depth(3));
let mut out = Vec::new();
for path in ["/a", "/b", "/c"] {
    conn.send_request(&Request::get(path).header("host", "x"), &mut out)?;
}
assert_eq!(conn.outstanding(), 3);
assert!(!conn.can_send()); // the depth is full
let _ = conn.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\naHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nbHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nc");
let mut bodies = Vec::new();
loop {
    match conn.poll()? {
        ClientEvent::Body(b) => bodies.extend_from_slice(b),
        ClientEvent::Idle => break,
        _ => {}
    }
}
assert_eq!(bodies, b"abc");
assert_eq!(conn.outstanding(), 0);
# Ok::<(), http_net::HttpError>(())
```

### Reuse and pooling

`reset()`, `with_buffer(storage, limits)`, `into_buffer()`, and
`shrink_idle()` work as on `ServerConn`: back to the initial state keeping
allocations (outstanding requests are forgotten), adopt and return pooled
storage, and free the buffer while no request is outstanding. **Ships:**
0.5.

### `ClientConn::set_leniency` and `ClientLeniency`

```rust,ignore
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ClientLeniency { pub obs_fold_in_responses: bool }
impl ClientLeniency {
    pub const fn new() -> ClientLeniency;
    pub const fn with_obs_fold_in_responses(self, on: bool) -> ClientLeniency;
}
impl ClientConn { pub fn set_leniency(&mut self, leniency: ClientLeniency); }
```

Opt-in tolerances for responses; the default is strict, and requests are
never parsed leniently. `obs_fold_in_responses` follows the RFC 9112 section
5.2 user-agent rule: each obsolete line fold in a response head is replaced
by overwriting its CR and LF with spaces, in place in the connection's
buffer, so offsets do not move, views stay borrowed, and nothing is
allocated. A line end is held back until its next byte arrives (only that
byte says whether the line is folded), so the result does not depend on how
the input is split. Whitespace before the first field, bare LF, bare CR,
`Content-Length` with `Transfer-Encoding`, and whitespace before a colon are
never tolerated (OD-7). A folded line counts as one field line against the
budgets. **Ships:** 0.5.

```rust
use http_net::{ClientConn, ClientEvent, ClientLeniency, HttpError, Request};

let folded = b"HTTP/1.1 200 OK\r\nX-Long: one,\r\n two\r\nContent-Length: 0\r\n\r\n";
let mut strict = ClientConn::new();
strict.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())?;
let _ = strict.feed(folded);
assert_eq!(strict.poll().unwrap_err(), HttpError::ObsFold);

let mut lenient = ClientConn::new();
lenient.set_leniency(ClientLeniency::new().with_obs_fold_in_responses(true));
lenient.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())?;
let _ = lenient.feed(folded);
let ClientEvent::Response(resp) = lenient.poll()? else { unreachable!() };
assert_eq!(resp.header("x-long"), Some(&b"one,   two"[..]));
# Ok::<(), http_net::HttpError>(())
```

### `ClientConn` methods added in 0.5

| Method | Behaviour | Ships |
|---|---|---|
| `set_leniency(&mut self, leniency: ClientLeniency)` | opt-in tolerance: `obs_fold_in_responses` replaces each fold's CR LF with SP SP in place (RFC 9112 section 5.2 user-agent rule); bare LF, bare CR, CL with TE, and whitespace before a colon are never tolerated | 0.5 |
| `outstanding(&self) -> usize`, `can_send(&self) -> bool` | pipelining state (depth from `Limits::pipeline_depth`, idempotent requests only) | 0.5 |
| `reset`, `with_buffer`, `into_buffer`, `shrink_idle` | as on `ServerConn` | 0.5 |

## `ClientEvent`

```rust,ignore
#[non_exhaustive]
#[derive(Debug)]
pub enum ClientEvent<'a> {
    Response(ResponseHead<'a>),
    Informational(ResponseHead<'a>), // only with set_report_informational(true)
    Continue,                        // a 100 to an expect_continue request
    Body(&'a [u8]),
    Trailers(Headers<'a>),           // only with set_report_trailers(true)
    ResponseEnd,
    NeedInput,
    Idle,
    Upgraded,
    Closed,
}
```

`Idle` means no request is outstanding (send the next one); `Closed` means
the connection cannot carry another request. **Ships:** exists;
`Informational`, `Continue`, `Trailers` 0.4.

## Tier 3: stateless parsers, chunked decoder, output

New in 0.5 (`respond_head_only` in 0.6), allocation-free, and
sharing code with the connections rather than copying it. The stateless
parsers are described in [Stateless head parsers](#stateless-head-parsers).

```rust,ignore
pub struct ChunkedDecoder { /* state, budgets */ }
impl ChunkedDecoder {
    pub fn new(limits: &Limits) -> ChunkedDecoder;
    pub fn decode(&mut self, input: &[u8], eof: bool) -> Result<ChunkStep, HttpError>;
    pub fn is_done(&self) -> bool;
    pub fn total(&self) -> u64;
}

#[non_exhaustive] pub enum ChunkStep {
    Data { skip: usize, len: usize }, NeedMore { consumed: usize },
    Trailers { skip: usize, len: usize }, Done { consumed: usize } }

pub trait Output { fn put(&mut self, bytes: &[u8]); fn reserve(&mut self, additional: usize) {} }
impl Output for Vec<u8>;
impl<O: Output + ?Sized> Output for &mut O;
pub struct ResponseHeadRef<'a> { pub status: u16, pub fields: &'a [(&'a str, &'a [u8])],
    pub body: OutgoingBody, pub close: bool, pub upgrade: Option<&'a str> }
impl<'a> ResponseHeadRef<'a> {
    pub const fn new(status: u16, fields: &'a [(&'a str, &'a [u8])], body: OutgoingBody) -> Self;
}
#[non_exhaustive] pub enum OutgoingBody { Empty, Full(u64), Length(u64), Chunked }
#[non_exhaustive] pub enum BodyPlan { None, Raw, Stream }

pub fn is_hop_by_hop(name: &str, connection_options: ListElements<'_, '_>) -> bool;
pub fn is_h2_preface(input: &[u8]) -> Option<bool>;
```

| Item | Behaviour | Ships |
|---|---|---|
| `ChunkedDecoder`, `ChunkStep` | standalone chunked decoding with explicit byte accounting, for proxy streaming and fetch-net | 0.5 |
| `Output`, `ResponseHeadRef`, `OutgoingBody`, `BodyPlan` | where serialized bytes go (`Vec<u8>` or a caller type such as a zeroizing buffer), and a borrowed response description; `put` cannot fail (OD-2) | 0.5 |
| `is_hop_by_hop` | `connection`, `keep-alive`, `proxy-connection`, `te`, `transfer-encoding`, `upgrade`, `trailer`, and any name listed in `Connection` | 0.5 |
| `is_h2_preface` | `Some(true)` for the 24-byte HTTP/2 preface, `Some(false)` when the input cannot be it, `None` when too short to tell | 0.5 |

### `is_hop_by_hop`

Whether a field name is hop-by-hop for a message: the fixed set
(`connection`, `keep-alive`, `proxy-connection`, `te`, `transfer-encoding`,
`upgrade`, `trailer`) or any name the message's `Connection` lists (RFC
9110 section 7.6.1), ASCII case-insensitively. **Ships:** 0.5.

```rust
use http_net::{ServerConn, ServerEvent, is_hop_by_hop};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: X-Trace\r\nX-Trace: 1\r\n\r\n");
let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
assert!(is_hop_by_hop("Keep-Alive", req.connection_options()));
assert!(is_hop_by_hop("x-trace", req.connection_options()));
assert!(!is_hop_by_hop("host", req.connection_options()));
```

### `is_h2_preface`

Whether input starts with the 24-byte HTTP/2 connection preface (RFC 9113
section 3.4): `Some(true)`, `Some(false)` as soon as a byte differs, or
`None` while the input is a shorter matching prefix. `ServerConn` checks it
before a connection's first request (never later) and refuses the preface
with `Http2Preface` (505), waiting while the input could still be the
preface so the answer does not depend on how the bytes arrived; a driver
that accepts prior-knowledge HTTP/2 (behind a trusted proxy only) checks it
first and routes the connection to an HTTP/2 engine. **Ships:** 0.5.

```rust
use http_net::{HttpError, ServerConn, is_h2_preface};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
assert_eq!(is_h2_preface(PREFACE), Some(true));
assert_eq!(is_h2_preface(&PREFACE[..10]), None);
assert_eq!(is_h2_preface(b"GET / HTTP/1.1\r\n"), Some(false));

let mut conn = ServerConn::new();
let _ = conn.feed(PREFACE);
assert_eq!(conn.poll().unwrap_err(), HttpError::Http2Preface);
```

### `ChunkedDecoder`

Decodes a chunked body from bytes the caller holds (a proxy streaming a
body through, a client on another buffer). It runs the connection's own
decoder, so the grammar and the budgets are the connection's: at most 16
hex digits in a size, checked arithmetic, the extension grammar and the
per-message extension budget, `max_body` checked before each chunk's data,
the CRLF after the data, and the trailer section validated against
`max_trailer_bytes` and `max_trailer_fields`. Nothing is allocated, the
decoder included.

| Step | Meaning | What to do |
|---|---|---|
| `Data { skip, len }` | `skip` framing bytes, then `len` bytes of body (never 0) | consume `skip + len`, call again with what follows |
| `NeedMore { consumed }` | the framing so far is valid but incomplete | drop `consumed`, keep the rest, append input, call again |
| `Trailers { skip, len }` | `skip` framing bytes, then a validated trailer section of `len` bytes (its field lines and the final CRLF); only for a section with at least one field | consume `skip + len`; the next call reports `Done { consumed: 0 }` |
| `Done { consumed }` | the body ends after `consumed` bytes; what follows is the next message | stop |

`eof` says no more input will come: a body still open then fails with
`UnexpectedEof`. Errors are the connection's (`InvalidChunkSize`,
`ExtensionsTooLarge`, `BodyTooLarge`, `TrailersTooLarge`,
`InvalidHeaderName`, and so on). `total()` counts the data bytes delivered;
`is_done()` is true once `Done` has been reported.

```rust
use http_net::{ChunkStep, ChunkedDecoder, Limits};

let wire = b"5;name=a\r\nhello\r\n0\r\nDigest: x\r\n\r\nGET / HTTP/1.1\r\n";
let mut decoder = ChunkedDecoder::new(&Limits::new());
let (mut pos, mut body) = (0, Vec::new());
loop {
    match decoder.decode(&wire[pos..], false)? {
        ChunkStep::Data { skip, len } => {
            body.extend_from_slice(&wire[pos + skip..pos + skip + len]);
            pos += skip + len;
        }
        ChunkStep::Trailers { skip, len } => {
            assert_eq!(&wire[pos + skip..pos + skip + len], b"Digest: x\r\n\r\n");
            pos += skip + len;
        }
        ChunkStep::Done { consumed } => {
            pos += consumed;
            break;
        }
        ChunkStep::NeedMore { .. } => unreachable!("the whole body is here"),
        _ => unreachable!(),
    }
}
assert_eq!(body, b"hello");
assert_eq!(decoder.total(), 5);
assert!(decoder.is_done());
assert_eq!(&wire[pos..], b"GET / HTTP/1.1\r\n");
# Ok::<(), http_net::HttpError>(())
```

### `Output` and the borrowed writer

`Output` is where serialized bytes go: a `Vec<u8>`, or a caller type such as
a zeroizing buffer, a slab, or a byte counter. `put` cannot fail (decision
OD-2): a sink with a fixed capacity records the overflow itself and reports
it after the call. `reserve` is a hint and may be ignored. `&mut O` is an
`Output` for any `O: Output`, so a sink can be passed down without being
moved.

`ResponseHeadRef` describes a response head with borrowed fields, so a head
whose fields change per response is written without building a `Response`.
The fields are checked exactly as `Response::header` checks them (a token
name, no reserved name, no control bytes, no surrounding whitespace), and a
`date` field means the connection adds none. `upgrade` names the protocol of
a `101` and writes `connection: upgrade` and `upgrade: <protocol>` before the
fields, as `Response::switching_protocols` does. It is a plain struct, built
with a literal or with `ResponseHeadRef::new` (no close, no upgrade).

`OutgoingBody` gives the framing:

| `OutgoingBody` | Framing written | Plan |
|---|---|---|
| `Empty` | `content-length: 0` where a body is allowed | `None` |
| `Full(n)` | `content-length: n`; the caller writes the `n` bytes | `Raw` (`None` when `n` is 0 or for `HEAD`) |
| `Length(n)` | `content-length: n`; stream exactly `n` bytes | `Stream` |
| `Chunked` | `transfer-encoding: chunked` (close-delimited to HTTP/1.0) | `Stream` |

`BodyPlan` says what follows the head:

| `BodyPlan` | Meaning |
|---|---|
| `None` | the response is complete |
| `Raw` | write the `Full(n)` body bytes yourself, right after the head; the connection already counts the response as sent |
| `Stream` | continue with `send_body_into` / `end_body_into` (or the `Vec` forms); for `HEAD` the connection drops the bytes, as `respond` does |

### `ServerConn::write_head` and `respond_into`

```rust,ignore
pub fn write_head<O: Output + ?Sized>(&mut self, head: &ResponseHeadRef<'_>, date: Option<&HttpDate>,
    out: &mut O) -> Result<BodyPlan, HttpError>;
pub fn respond_into<O: Output + ?Sized>(&mut self, response: &Response, date: Option<&HttpDate>,
    out: &mut O) -> Result<(), HttpError>;
pub fn send_body_into<O: Output + ?Sized>(&mut self, data: &[u8], out: &mut O) -> Result<(), HttpError>;
pub fn end_body_into<O: Output + ?Sized>(&mut self, trailers: &[(&str, &[u8])], out: &mut O)
    -> Result<(), HttpError>;
```

`write_head` writes the bytes `respond` writes for the equivalent `Response`
and fails the same way, through the same code: the same state rules, the
same framing, the same `connection` handling, the same upgrade checks
(`101` needs `upgrade`, `upgrade` needs `101`, a protocol the client did not
offer is `UpgradeNotOffered`, a body other than `Empty` or `Full(0)` on a
1xx, 204, 304, or tunnel status is `BodyNotAllowed`). On an error nothing is
written. `date` is
added unless the fields set one. With a reused `Vec` it allocates nothing.

`respond_into` is `respond_with_date` over any `Output`. `send_body_into`
and `end_body_into` are `send_body` and `end_body_with_trailers` over any
`Output`.

```rust
use http_net::{BodyPlan, OutgoingBody, ResponseHeadRef, ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET /a HTTP/1.1\r\nHost: a\r\n\r\n");
while !matches!(conn.poll()?, ServerEvent::RequestEnd) {}

let request_id = b"7f3a";
let fields: [(&str, &[u8]); 2] = [("content-type", b"text/plain"), ("x-request-id", request_id)];
let mut out = Vec::new();
let plan = conn.write_head(&ResponseHeadRef::new(200, &fields, OutgoingBody::Full(2)), None, &mut out)?;
assert_eq!(plan, BodyPlan::Raw);
out.extend_from_slice(b"ok");
assert_eq!(
    out,
    b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\ncontent-type: text/plain\r\nx-request-id: 7f3a\r\n\r\nok"
);
# Ok::<(), http_net::HttpError>(())
```

### `ServerConn::respond_head_only`

```rust,ignore
pub fn respond_head_only(&mut self, response: &Response, out: &mut Vec<u8>)
    -> Result<BodyPlan, HttpError>;
```

As `respond`, but writes only the head. For a full-body response the plan
is `Raw`: the caller sends [`Response::body_bytes`](#response) right after
the head, typically with one vectored write (`write_vectored` with the head
and the body), so the body is never copied into `out`. The response counts
as sent. `None` follows an empty body, `HEAD`, 204, 304, or a tunnel;
`Stream` a streamed response, continued with `send_body` and `end_body`.
The bytes written plus the body are exactly what `respond` writes, and the
errors are the same, with nothing written on error. The blocking server
uses it for full bodies over 4 KiB. Allocation-free with a reused `Vec`.
**Ships:** 0.6.

```rust
use http_net::{BodyPlan, Response, ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET /file HTTP/1.1\r\nHost: a\r\n\r\n");
while !matches!(conn.poll()?, ServerEvent::RequestEnd) {}
let response = Response::new(200)
    .header("content-type", "application/octet-stream")
    .body(vec![0u8; 256 * 1024]);
let mut head = Vec::new();
assert_eq!(conn.respond_head_only(&response, &mut head)?, BodyPlan::Raw);
assert!(head.len() < 128); // the head alone
let body = response.body_bytes().unwrap_or_default();
assert_eq!(body.len(), 256 * 1024);
// socket.write_vectored(&[IoSlice::new(&head), IoSlice::new(body)])
# Ok::<(), http_net::HttpError>(())
```

---

## Blocking adapter

Feature `std` (on by default). A thin shell over the sans-IO core; plain
`http://` only.

### `blocking::Server`

```rust,ignore
pub struct Server { /* private */ }
```

| Method | Notes | Ships |
|---|---|---|
| `bind(addr: impl ToSocketAddrs) -> io::Result<Server>` | use `127.0.0.1:0` for an ephemeral port | exists |
| `with_config(self, config: ServerConfig) -> Server` | | exists |
| `on_upgrade(self, hook: impl Fn(Upgraded) + Send + Sync + 'static) -> Server` | receives sockets after a 101; without a hook they are closed | exists |
| `local_addr(&self) -> SocketAddr` | | exists |
| `shutdown_handle(&self) -> ShutdownHandle` | | exists |
| `serve<H>(self, handler: H) -> io::Result<()>` | `H: Fn(&RequestHead<'_>, &[u8]) -> Response + Send + Sync + 'static` | exists |

`serve` runs one thread per connection, up to `max_connections`. The next
connection is answered 503 and closed from the accept thread without
waiting on the peer: only bytes that have already arrived are drained, so a
refused client cannot stall the accept loop. The handler receives the
complete body; a request with `Expect: 100-continue` gets `100 Continue`
before its body is read. Parse errors are answered with
`Response::from_error` and closed. A request that is still incomplete when
its request timeout (or a read timeout) expires is answered `408` and
closed. A handler that returns a streamed response (`chunked` /
`content_length`, which `Server` cannot send) or an invalid one (for
example a reserved field, or a 101 to a request that did not ask) is
answered `500` and closed; streamed framing on a `HEAD` answer is allowed,
since no body follows. A request with an expectation other than
`100-continue` is answered `417 Expectation Failed` and closed, before its
body is read and without `100 Continue` (0.4). Every response gets a
`date` field from [`now_date`](#blockingnow_date) unless the handler set
one. Writing one response may take at most `response_deadline` in total
(0.4), and a connection that reaches `max_requests_per_connection` closes
after that response (0.4). Closing connections are drained (lingering
close) for at most 1 s and 256 KiB so the last response is not lost to a
reset. **Errors:** only if accepting fails persistently (1,000
consecutive errors); transient accept errors are retried after 10 ms.

### `blocking::serve`

```rust,ignore
pub fn serve<H>(addr: impl ToSocketAddrs, handler: H) -> io::Result<()>
where H: Fn(&RequestHead<'_>, &[u8]) -> Response + Send + Sync + 'static
```

Binds `addr` and serves `handler` with the default `ServerConfig` until
the process ends: the one-call Tier-1 server. For a shutdown handle, a
configuration, or an upgrade hook, use `Server`. **Errors:** the bind
error, or as `Server::serve`. **Ships:** 0.4.

```rust,no_run
use http_net::{blocking, Response};

blocking::serve("127.0.0.1:8080", |req, _body| Response::text(200, req.path()))?;
# Ok::<(), std::io::Error>(())
```

### `blocking::now_date`

```rust,ignore
pub fn now_date() -> HttpDate
```

The current `Date` value from a per-thread `DateCache` fed by
`SystemTime::now()`: formatted at most once per second per thread. The
server and `Connection::respond` use it. **Ships:** 0.4.

```rust
let date = http_net::blocking::now_date();
assert!(date.as_str().ends_with(" GMT"));
```

### `blocking::ServerConfig`

| Setter | Getter | Default | Ships |
|---|---|---|---|
| `with_limits(Limits)` | `limits()` | `Limits::new()` | exists |
| `with_max_connections(usize)` | `max_connections()` | 64 (at least 1) | exists |
| `with_read_timeout(Option<Duration>)` | `read_timeout()` | 10 s (each read; also the idle keep-alive timeout) | exists |
| `with_request_timeout(Option<Duration>)` | `request_timeout()` | 30 s, from a request's first byte to the end of its body; idle keep-alive time does not count (this stops slowloris) | exists |
| `with_write_timeout(Option<Duration>)` | `write_timeout()` | 10 s (each write) | exists |
| `with_response_deadline(Option<Duration>)` | `response_deadline()` | 60 s to write one whole response; each write waits at most what is left (and never more than the write timeout), so a client reading one byte at a time cannot hold a thread (threat T-26) | 0.4 |
| `with_max_requests_per_connection(Option<u64>)` | `max_requests_per_connection()` | none; the response that reaches the cap carries `connection: close` (`Some(0)` counts as 1) | 0.4 |

For LexerSketch Studio's budget ("header timeout 10 s"), set
`with_request_timeout(Some(Duration::from_secs(10)))`.

```rust
use std::time::Duration;
use http_net::blocking::ServerConfig;

let config = ServerConfig::new()
    .with_response_deadline(Some(Duration::from_secs(20)))
    .with_max_requests_per_connection(Some(1000));
assert_eq!(config.response_deadline(), Some(Duration::from_secs(20)));
assert_eq!(config.max_requests_per_connection(), Some(1000));
```

### `blocking::ShutdownHandle`

`shutdown(&self)`: stop accepting, let each connection finish its current
exchange, wait for them, and return from `serve`. A connection idle in a
read finishes when its read timeout expires. **Ships:** exists.

### `blocking::Connection`

A blocking server connection for your own accept loop, streamed responses,
or keeping the socket after an upgrade.

| Method | Notes | Ships |
|---|---|---|
| `new(stream: TcpStream, limits: Limits) -> Connection` | set socket timeouts first if you want them; the socket's read timeout is the idle timeout | exists |
| `with_request_timeout(self, Option<Duration>) -> Connection` | deadline per request, from its first byte to the end of its body; `None` by default | exists |
| `with_response_deadline(self, Option<Duration>) -> Connection` | total time to write one response, from `respond` through `end_body`; a miss is `Error::Io` of kind `TimedOut`; `None` by default | 0.4 |
| `next_request(&mut self) -> Result<Option<Incoming<'_>>, Error>` | `None` when the connection is finished; answers `Expect: 100-continue` itself (other expectations are left to the caller: check `has_unknown_expectation`); a missed deadline is `Error::Io` of kind `TimedOut` | exists |
| `respond(&mut self, response: &Response) -> Result<(), Error>` | adds `date` from `now_date` | exists; 0.4 |
| `send_informational(&mut self, response: &Response) -> Result<(), Error>` | a 1xx (for example `103`) through `ServerConn::send_informational`, before `respond` | 0.4 |
| `send_body(&mut self, data: &[u8])`, `end_body(&mut self)` | streamed responses | exists |
| `is_upgraded(&self) -> bool`, `into_upgraded(self) -> Option<Upgraded>` | | exists |
| `close(self)` | lingering close | exists |

### `blocking::Incoming`

`head(&self) -> RequestHead<'a>` and `body(&self) -> &'a [u8]`: a request
head and its complete body. **Ships:** exists.

### `blocking::Upgraded`

```rust,ignore
pub struct Upgraded {
    pub stream: TcpStream,
    pub leftover: Vec<u8>,
    pub target: String,
}
```

The socket after a 101, the bytes of the new protocol already read, and the
request target. **Ships:** exists.

### `blocking::get`

```rust,ignore
pub fn get(url: &str) -> Result<ClientResponse, Error>
```

`Client::new().get(url)`. **Errors:** `InvalidUrl` for anything but
`http://host[:port][/path][?query]`; `Io` for connection failures and
timeouts; `Http` for a response this crate refuses. **Ships:** exists.

### `blocking::post`

```rust,ignore
pub fn post(url: &str, content_type: &str, body: &[u8]) -> Result<ClientResponse, Error>
```

A Tier-1 POST of `body` with `content-type: <content_type>` through the
default `Client`. **Errors:** as `get`, plus the builder's errors for an
invalid content type. **Ships:** 0.4.

```rust,no_run
let resp = http_net::blocking::post("http://127.0.0.1:8080/notes", "text/plain", b"hello")?;
assert_eq!(resp.status(), 201);
# Ok::<(), http_net::blocking::Error>(())
```

### `blocking::Client`

| Method | Default / notes | Ships |
|---|---|---|
| `new()` | 16 MiB body limit, 30 s timeouts (each connect, read, and write) | exists |
| `with_limits(Limits)` | | exists |
| `with_timeout(Duration)` | connect, read, and write timeout (zero is raised to 1 ms) | exists |
| `get(&self, url: &str) -> Result<ClientResponse, Error>` | one connection per request with `connection: close` | exists |
| `with_deadline(Option<Duration>)` | one total deadline for connect, write, and read of an exchange (`Error::Io` of kind `TimedOut`); `None` by default | 0.4 |
| `request(&self, url: &str, request: Request) -> Result<ClientResponse, Error>` | any `Request` to an `http://` URL: the URL gives the target and `host`, the request gives method, fields, and a full body; refuses a request that already has `host` (`Http(InvalidHost)`), a streamed body, or an upgrade (`InvalidState`) | 0.4 |

```rust,no_run
use std::time::Duration;
use http_net::{Request, blocking::Client};

let client = Client::new().with_deadline(Some(Duration::from_secs(5)));
let put = Request::put("/ignored").header("content-type", "application/json").body(&b"{}"[..]);
let resp = client.request("http://127.0.0.1:8080/items/7", put)?;
# let _ = resp;
# Ok::<(), http_net::blocking::Error>(())
```

The blocking client stays minimal (OD-17): pooling, redirects, TLS, and
cookies belong to `fetch-net`.

### `blocking::ClientResponse`

`status()`, `headers()` (iterator of `(&str, &[u8])`), `header(name)`,
`body()`, `text()` (if UTF-8), `into_body()`. Its `Debug` redacts
credential field values (0.3). **Ships:** exists; 0.3.

### `blocking::Error`

```rust,ignore
#[non_exhaustive]
pub enum Error { Io(io::Error), Http(HttpError), InvalidUrl(&'static str) }
```

Implements `Display`, `std::error::Error` (with `source`), and `From` for
`io::Error` and `HttpError`. **Ships:** exists.

## Not provided, on purpose

| Not provided | Why | Instead |
|---|---|---|
| A header map type (hash map) | attacker-keyed hashing and an allocation per request; field counts are small (100 max) | ordered views and `header_all` |
| Header name case conversion on output | the caller writes names in the case it wants; incoming names are preserved | none needed |
| Skipping invalid header lines | silently skipping a line is a desync vector | refusal |
| Lenient request parsing of any kind | the server is the hop that must not desynchronise | none |
| Automatic decompression; transfer codings other than `chunked` | out of scope | a separate compression crate |
| A status code newtype | `u16` with constants is enough (OD-9) | the `status` module |
| An async runtime or async adapter | no crate in this family takes one; drivers call the sans-IO core (OD-11) | `serve-net`, `net-io` |
| TLS | out of scope | `tls-net` |

## Limits and guarantees

- Every limit is checked before the bytes it governs are buffered; declared
  lengths and chunk sizes before their data is read.
- Head parsing resumes where it stopped, so it is linear in the head size
  however the input is split; buffer compaction copies at most the pinned
  head plus one partial line, so total copying is linear in the input.
- Steady-state parsing allocates nothing: a counting-allocator test serves
  10,000 keep-alive requests on one `ServerConn` after warm-up and counts
  zero allocations in the core (0.3).
- No reachable panics: `#![forbid(unsafe_code)]`, no `unwrap`, `expect`, or
  `unreachable!` in library code, property tests on arbitrary input both
  from the first byte and behind valid heads, and cargo-fuzz targets for
  both connections, the chunk-line grammar, the builders, and two
  differential oracles (0.3).
- The parse result does not depend on how the input is split (property
  tested, including after a valid head).
- On every request head it accepts, `http-net` agrees with `httparse` on the
  head length, method, path, version, and field list (differential test,
  0.3); everywhere they differ, `http-net` refused and `httparse` accepted.
- Every refusal in [What is refused](#what-is-refused-and-why) has a test
  that feeds it whole and split at every byte (`tests/smuggling.rs`,
  `tests/rfc_cases.rs`, `tests/adversarial.rs`).
- No credential value appears in any `Debug` output (0.3).
