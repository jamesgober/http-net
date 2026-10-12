# http-net &mdash; API Reference

> Complete reference for every public item in `http-net`, with examples.
> **Status: pre-1.0 (`0.2.0`).** The surface below may still change in the
> 0.x series; it is frozen at `1.0.0` (see [`../dev/ROADMAP.md`](../dev/ROADMAP.md)).

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Table of contents

- [Overview](#overview)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Concepts](#concepts)
  - [The sans-IO loop](#the-sans-io-loop)
  - [Keep-alive and pipelining](#keep-alive-and-pipelining)
  - [Body framing](#body-framing)
  - [What is refused, and why](#what-is-refused-and-why)
  - [Request targets and the authority](#request-targets-and-the-authority)
  - [`Expect: 100-continue`](#expect-100-continue)
  - [Upgrades](#upgrades)
- [`ServerConn`](#serverconn)
- [`ServerEvent`](#serverevent)
- [`ClientConn`](#clientconn)
- [`ClientEvent`](#clientevent)
- [`RequestHead`](#requesthead)
- [`ResponseHead`](#responsehead)
- [`Headers`](#headers)
- [`Response`](#response)
- [`Request`](#request)
- [`Method`](#method)
- [`Version`](#version)
- [`BodyFraming`](#bodyframing)
- [`Limits`](#limits)
- [`HttpError`](#httperror)
- [`reason_phrase`](#reason_phrase)
- [Blocking adapter](#blocking-adapter)
  - [`blocking::Server`](#blockingserver)
  - [`blocking::ServerConfig`](#blockingserverconfig)
  - [`blocking::ShutdownHandle`](#blockingshutdownhandle)
  - [`blocking::Connection`](#blockingconnection)
  - [`blocking::Incoming`](#blockingincoming)
  - [`blocking::Upgraded`](#blockingupgraded)
  - [`blocking::get`](#blockingget)
  - [`blocking::Client`](#blockingclient)
  - [`blocking::ClientResponse`](#blockingclientresponse)
  - [`blocking::Error`](#blockingerror)
- [Feature flags](#feature-flags)
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
| [`Headers`](#headers) | struct | Iterator over a head's fields. |
| [`Response`](#response) | struct | An outgoing response (builder). |
| [`Request`](#request) | struct | An outgoing request (builder). |
| [`Method`](#method) | enum | Request method, classified. |
| [`Version`](#version) | enum | HTTP/1.0 or HTTP/1.1. |
| [`BodyFraming`](#bodyframing) | enum | How a body is delimited. |
| [`Limits`](#limits) | struct | Budgets on incoming messages. |
| [`HttpError`](#httperror) | enum | Why a message was refused or a call was out of order. |
| [`reason_phrase`](#reason_phrase) | fn | Canonical reason phrase for a status code. |
| [`blocking`](#blocking-adapter) | module | `std::net` adapter: `Server`, `Connection`, `Client`, `get` (feature `std`). |

## Installation

```toml
[dependencies]
http-net = "0.2"
```

`no_std` (the core needs `alloc` only):

```toml
[dependencies]
http-net = { version = "0.2", default-features = false }
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

## Concepts

### The sans-IO loop

Every adapter runs the same loop:

1. `poll()` until it returns `NeedInput` (or `AwaitingResponse`, `Upgraded`,
   `Closed`).
2. On `NeedInput`, read from the socket into
   [`read_buf`](#serverconnread_buf) and [`commit`](#serverconncommit) the
   count, or [`feed`](#serverconnfeed) a slice; on EOF call
   [`feed_eof`](#serverconnfeed_eof).
3. Write whatever [`respond`](#serverconnrespond) /
   [`send_body`](#serverconnsend_body) appended to your output buffer.

`read_buf` is never empty while the connection is waiting for input: the
buffer capacity always covers what the parser is waiting to complete.

### Keep-alive and pipelining

A server connection handles one request at a time. After the response is
finished, the next `poll` starts the next request; if the client pipelined
it, it is already in the buffer. The connection closes (reports `Closed`)
when the client sent `Connection: close`, when an HTTP/1.0 client did not
ask for keep-alive, when the response asked to close, when a response was
sent while request body bytes were still unread (a request without a body
can be answered at `Request` and stays keep-alive), or after a parse error.

A client connection has one request outstanding at a time and returns to
`Idle` when the response allows reuse.

### Body framing

Incoming bodies follow RFC 9112 section 6.3:

| Situation | Framing |
|---|---|
| request with `Transfer-Encoding: chunked` | chunked |
| request with `Content-Length: n` | exactly `n` bytes |
| request with neither | no body |
| response to `HEAD`, or status 1xx, 204, 304 | no body, whatever the headers say |
| 2xx response to `CONNECT` | tunnel (`Upgraded`) |
| response with `chunked` / `Content-Length` | as for requests |
| response with neither | until the server closes (bounded by `max_body`) |

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
| a missing `Host` in HTTP/1.1; two `Host` fields (any case); a `Host` that is not `host[:port]` | `MissingHost` / `InvalidHost` | 9112 section 3.2: MUST answer 400. |
| a target with characters outside RFC 3986 or bad `%` escapes; `*` outside `OPTIONS`; authority form outside `CONNECT`; an absolute form without `//authority`, with userinfo, or with an empty host | `InvalidTarget` | 9112 section 3.2; 9110 sections 4.2.1 and 4.2.4. |
| chunk sizes over 16 hex digits or overflowing 64 bits, malformed extensions, data not followed by CRLF | `InvalidChunkSize` / `InvalidChunkExtension` / `InvalidChunkTerminator` | Each is a known desync. |
| more than `max_header_bytes` of chunk extensions in one message | `ChunkExtensionsTooLarge` | Unbounded extensions make a small body cost unbounded input (CVE-2024-22019). |

Accepted on purpose: `HTTP/1.2` to `HTTP/1.9` (processed as 1.1), empty
lines before a request line (counted against `max_start_line`), obs-text
(bytes 0x80 to 0xFF) in field values, header names in any case, and
`Expect` values other than `100-continue` (ignored; 9110 section 10.1.1
allows 417 but does not require it). Trailer fields are validated, counted,
and discarded, so a `Content-Length` or `Transfer-Encoding` in a trailer
cannot reframe anything.

After a parse error the connection is finished: nothing after the bad
message is parsed, and a server may send one error response, marked
`connection: close`.

### Request targets and the authority

| Form | Example | `path()` | `host()` |
|---|---|---|---|
| origin | `/a/b?q` | `/a/b` | the `Host` field |
| absolute | `http://example.com:8080/a?q` | `/a` (`/` when empty) | `example.com:8080`; `Host` is ignored (9112 section 3.2.2) but must still be present and valid |
| authority (`CONNECT` only) | `example.com:443` | the whole target | the `Host` field |
| asterisk (`OPTIONS` only) | `*` | `*` | the `Host` field |

`target()` always returns the target exactly as received, and
`header("host")` the raw field.

### `Expect: 100-continue`

A client that sends `Expect: 100-continue` waits for the server before
sending the body. RFC 9110 section 10.1.1 requires the server to answer the
expectation, either with `100 Continue` or with a final status, before it
waits for the body. [`RequestHead::expects_continue`](#requesthead) reports
the expectation (HTTP/1.1 requests with a body only) and
[`ServerConn::send_continue`](#serverconnsend_continue) writes the interim
response. The blocking adapter does this itself. A final response sent
instead closes the connection afterwards, since the body was not read.

### Upgrades

A request whose `Connection` lists `upgrade` and that has an `Upgrade`
field reports [`RequestHead::is_upgrade`](#requestheadis_upgrade). Answer it
with [`Response::switching_protocols`](#responseswitching_protocols) once
the request is complete; the connection then reports `Upgraded`, and
[`remaining_input`](#serverconnremaining_input) holds any bytes of the new
protocol that arrived with the request. On the client side,
[`Request::upgrade`](#requestupgrade) asks to switch, and a `101` reply
yields `Response` then `Upgraded`.

---

## `ServerConn`

```rust,ignore
pub struct ServerConn { /* private */ }
```

The server side of one HTTP/1.1 connection. `Send + Sync`. Steady state
allocates nothing: the input buffer and the field index are reused.

### `ServerConn::new`

```rust,ignore
pub fn new() -> ServerConn
```

A connection with [`Limits::new`](#limitsnew).

### `ServerConn::with_limits`

```rust,ignore
pub fn with_limits(limits: Limits) -> ServerConn
```

A connection enforcing `limits`.

```rust
use http_net::{HttpError, Limits, ServerConn};

let mut conn = ServerConn::with_limits(Limits::new().with_max_body(4));
let _ = conn.feed(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n");
assert_eq!(conn.poll().unwrap_err(), HttpError::BodyTooLarge);
```

### `ServerConn::limits`

```rust,ignore
pub fn limits(&self) -> &Limits
```

### `ServerConn::feed`

```rust,ignore
#[must_use]
pub fn feed(&mut self, bytes: &[u8]) -> usize
```

Copies as much of `bytes` as fits into the input buffer and returns the
count taken. A short count means the buffer is full: poll, then feed the
rest.

### `ServerConn::read_buf`

```rust,ignore
pub fn read_buf(&mut self) -> &mut [u8]
```

Spare space at the end of the input buffer, for reading from a socket
without an intermediate copy. Follow with [`commit`](#serverconncommit).

```rust
let mut conn = http_net::ServerConn::new();
let msg = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
conn.read_buf()[..msg.len()].copy_from_slice(msg);
conn.commit(msg.len());
assert!(matches!(conn.poll(), Ok(http_net::ServerEvent::Request(_))));
```

### `ServerConn::commit`

```rust,ignore
pub fn commit(&mut self, n: usize)
```

Records that `n` bytes were written into `read_buf`.

### `ServerConn::feed_eof`

```rust,ignore
pub fn feed_eof(&mut self)
```

The peer closed its sending side. Between requests the connection then
reports `Closed`; in the middle of one, `HttpError::UnexpectedEof`.

### `ServerConn::poll`

```rust,ignore
pub fn poll(&mut self) -> Result<ServerEvent<'_>, HttpError>
```

Advances the parser. **Errors:** any parse error from [`HttpError`](#httperror);
the connection is then finished (one error response may still be sent with
`respond`).

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
(still available after an upgrade).

### `ServerConn::is_upgraded`

```rust,ignore
pub fn is_upgraded(&self) -> bool
```

Whether a 101 (or a 2xx to `CONNECT`) was sent.

### `ServerConn::remaining_input`

```rust,ignore
pub fn remaining_input(&self) -> &[u8]
```

Unread input; after `Upgraded`, the first bytes of the new protocol.

### `ServerConn::respond`

```rust,ignore
pub fn respond(&mut self, response: &Response, out: &mut Vec<u8>) -> Result<(), HttpError>
```

Writes `response` for the current request into `out`. The connection
writes the status line, the framing header, and `connection: close` (or
`connection: keep-alive` for an HTTP/1.0 keep-alive client). A `HEAD`
request gets the headers without the body.

**Errors:** the builder's first recorded error; `InvalidStatus` (outside
`100..=599`, or 1xx other than 101); `BodyNotAllowed` (body on 1xx, 204,
304, 101, or 2xx-to-CONNECT); `InvalidState` (no request to answer, a
response already started, or a 101 that does not answer a complete upgrade
request).

```rust
use http_net::{Response, ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let _ = conn.feed(b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n");
while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
let mut out = Vec::new();
conn.respond(&Response::text(200, "hello"), &mut out).unwrap();
assert!(out.windows(17).any(|w| w == b"content-length: 5"));
assert!(out.ends_with(b"\r\n\r\n"));
```

### `ServerConn::send_continue`

```rust,ignore
pub fn send_continue(&mut self, out: &mut Vec<u8>) -> Result<(), HttpError>
```

Writes `HTTP/1.1 100 Continue\r\n\r\n`, telling a client that sent
`Expect: 100-continue` to send the body. **Errors:** `InvalidState` unless
the current request is HTTP/1.1, its body has not been read, no response
has been started, and `100 Continue` has not already been sent for it (RFC
9110 section 15.2 forbids 1xx responses to HTTP/1.0 clients).

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

### `ServerConn::send_body`

```rust,ignore
pub fn send_body(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), HttpError>
```

Body bytes of a streamed response (`Response::chunked` or
`Response::content_length`). Dropped for `HEAD`. **Errors:**
`BodyLengthMismatch` past the declared length; `InvalidState` with no
streamed response in progress.

### `ServerConn::end_body`

```rust,ignore
pub fn end_body(&mut self, out: &mut Vec<u8>) -> Result<(), HttpError>
```

Ends a streamed response. **Errors:** `BodyLengthMismatch` when fewer bytes
than declared were sent; `InvalidState` with no streamed response.

```rust
use http_net::{Response, ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET /log HTTP/1.1\r\nHost: a\r\n\r\n");
while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
let mut out = Vec::new();
conn.respond(&Response::new(200).chunked(), &mut out).unwrap();
conn.send_body(b"line 1\n", &mut out).unwrap();
conn.end_body(&mut out).unwrap();
assert!(out.ends_with(b"7\r\nline 1\n\r\n0\r\n\r\n"));
```

## `ServerEvent`

```rust,ignore
#[non_exhaustive]
pub enum ServerEvent<'a> {
    Request(RequestHead<'a>),
    Body(&'a [u8]),
    RequestEnd,
    NeedInput,
    AwaitingResponse,
    Upgraded,
    Closed,
}
```

| Variant | Meaning | What to do |
|---|---|---|
| `Request` | A request head arrived. | Inspect it; answer `expects_continue()`; you may respond now (closing afterwards if body bytes are unread). |
| `Body` | A run of body bytes (chunked encoding removed). | Consume it. |
| `RequestEnd` | The request is complete. | Respond if you have not. |
| `NeedInput` | More input is needed. | Read and feed, or `feed_eof`. |
| `AwaitingResponse` | The request is done; its response is not. | Finish the response. |
| `Upgraded` | The connection now speaks another protocol. | Take `remaining_input` and the socket. |
| `Closed` | The connection is finished. | Flush output, close the socket. |

## `ClientConn`

```rust,ignore
pub struct ClientConn { /* private */ }
```

The client side of one HTTP/1.1 connection: one outstanding request at a
time; `Send + Sync`.

| Method | Signature | Notes |
|---|---|---|
| `new` | `fn new() -> ClientConn` | Default limits. |
| `with_limits` | `fn with_limits(limits: Limits) -> ClientConn` | Limits on responses. |
| `limits` | `fn limits(&self) -> &Limits` | |
| `feed` | `fn feed(&mut self, bytes: &[u8]) -> usize` | As `ServerConn::feed`. |
| `read_buf` / `commit` | `fn read_buf(&mut self) -> &mut [u8]`, `fn commit(&mut self, n: usize)` | As on `ServerConn`. |
| `feed_eof` | `fn feed_eof(&mut self)` | Ends an until-close body; mid-message it is `UnexpectedEof`. |
| `send_request` | `fn send_request(&mut self, request: &Request, out: &mut Vec<u8>) -> Result<(), HttpError>` | See below. |
| `send_body` / `end_body` | as on `ServerConn` | Streamed request bodies. |
| `poll` | `fn poll(&mut self) -> Result<ClientEvent<'_>, HttpError>` | Parse errors close the connection. |
| `response` | `fn response(&self) -> Option<ResponseHead<'_>>` | Current response head. |
| `is_upgraded` | `fn is_upgraded(&self) -> bool` | |
| `remaining_input` | `fn remaining_input(&self) -> &[u8]` | After `Upgraded`: the new protocol's first bytes. |

### `ClientConn::send_request`

Writes `request` into `out` and waits for its response. A full body is
sent with `content-length` (omitted for an empty body unless the method is
`POST`, `PUT`, or `PATCH`); a streamed body continues with `send_body` and
`end_body`. **Errors:** the builder's first error; `MissingHost` without a
`host` header; `InvalidState` while a request is outstanding or after the
connection closed; `UnexpectedData` if unsolicited bytes are buffered.

```rust
use http_net::{ClientConn, HttpError, Request};

let mut conn = ClientConn::new();
let mut out = Vec::new();
assert_eq!(conn.send_request(&Request::get("/"), &mut out), Err(HttpError::MissingHost));
conn.send_request(&Request::post("/f").header("host", "a").body(&b"xyz"[..]), &mut out).unwrap();
assert_eq!(out, b"POST /f HTTP/1.1\r\nhost: a\r\ncontent-length: 3\r\n\r\nxyz");
```

Interim responses (100, 103) are skipped; together they count against
`max_header_bytes`, so a server cannot keep the client parsing interim
responses forever (`HeadersTooLarge`). A `101` that the request did not ask
for is `UnexpectedUpgrade`. Bytes that arrive after a complete response,
with no request outstanding, are `UnexpectedData` (never queued as the next
response).

## `ClientEvent`

```rust,ignore
#[non_exhaustive]
pub enum ClientEvent<'a> {
    Response(ResponseHead<'a>),
    Body(&'a [u8]),
    ResponseEnd,
    NeedInput,
    Idle,
    Upgraded,
    Closed,
}
```

`Idle` means no request is outstanding (send the next one); `Closed` means
the connection cannot carry another request.

## `RequestHead`

```rust,ignore
#[derive(Clone, Copy)]
pub struct RequestHead<'a> { /* private */ }
```

A parsed request head borrowed from the connection's buffer.

| Method | Returns | Notes |
|---|---|---|
| `method()` | `Method` | Classified, case-sensitive. |
| `method_str()` | `&'a str` | Exactly as received. |
| `target()` | `&'a str` | Origin, absolute, authority (`CONNECT`), or `*` (`OPTIONS`) form. |
| `path()` | `&'a str` | Target up to the first `?`, percent-encoding kept; for the absolute form, the path after the authority (`/` if empty). See [Request targets](#request-targets-and-the-authority). |
| `query()` | `Option<&'a str>` | After the first `?`. |
| `version()` | `Version` | |
| `headers()` | `Headers<'a>` | All fields in order. |
| `header(name)` | `Option<&'a [u8]>` | First match, case-insensitive name. |
| `header_str(name)` | `Option<&'a str>` | Same, if UTF-8. |
| `host()` | `Option<&'a str>` | Validated `host[:port]`: the absolute-form authority if there is one, else the `Host` field. |
| `framing()` | `BodyFraming` | |
| `keep_alive()` | `bool` | Whether the client allows reuse. |
| `is_upgrade()` | `bool` | HTTP/1.1, `Connection: upgrade`, and an `Upgrade` field. |
| `expects_continue()` | `bool` | HTTP/1.1, `Expect: 100-continue`, and a body follows. |

```rust
use http_net::{Method, ServerConn, ServerEvent, Version};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET /search?q=rust HTTP/1.1\r\nHost: example.com\r\n\r\n");
let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
assert_eq!(req.method(), Method::Get);
assert_eq!(req.path(), "/search");
assert_eq!(req.query(), Some("q=rust"));
assert_eq!(req.version(), Version::Http11);
assert_eq!(req.host(), Some("example.com"));
```

### `RequestHead::is_upgrade`

See [Upgrades](#upgrades).

## `ResponseHead`

```rust,ignore
#[derive(Clone, Copy)]
pub struct ResponseHead<'a> { /* private */ }
```

| Method | Returns |
|---|---|
| `status()` | `u16` (`100..=599`) |
| `reason()` | `&'a str` (empty if not UTF-8; carries no meaning) |
| `version()` | `Version` |
| `headers()` / `header(name)` / `header_str(name)` | as on `RequestHead` |
| `framing()` | `BodyFraming` (accounts for `HEAD` and bodiless statuses) |
| `keep_alive()` | `bool` |

## `Headers`

```rust,ignore
pub struct Headers<'a> { /* private */ }
impl<'a> Iterator for Headers<'a> { type Item = (&'a str, &'a [u8]); }
impl ExactSizeIterator for Headers<'_> {}
```

Names as received; values trimmed of surrounding whitespace, as bytes (they
may contain `obs-text`).

## `Response`

```rust,ignore
pub struct Response { /* private */ }
```

An outgoing response. Builder methods validate as they go and remember the
first problem; it is returned when the response is written. Framing
headers (`content-length`, `transfer-encoding`, `connection`, `upgrade`)
are refused with `ReservedHeader`: the connection writes them.

| Method | Notes |
|---|---|
| `new(status: u16) -> Response` | Empty body; status validated when written. |
| `text(status: u16, text: &str) -> Response` | `text/plain; charset=utf-8`. |
| `switching_protocols(protocol: &str) -> Response` | 101 with `connection: upgrade` and `upgrade: <protocol>`. |
| `header(self, name: &str, value: impl AsRef<[u8]>) -> Response` | Token name; no CR/LF/controls; no leading or trailing whitespace. |
| `body(self, body: impl Into<Cow<'static, [u8]>>) -> Response` | Static bodies are borrowed, not copied. |
| `chunked(self) -> Response` | Stream with `send_body` / `end_body`. |
| `content_length(self, len: u64) -> Response` | Stream exactly `len` bytes. |
| `close(self) -> Response` | Close after this response. |
| `status(&self) -> u16`, `closes(&self) -> bool` | |
| `body_bytes(&self) -> Option<&[u8]>` | `None` for a streamed body. |
| `header_value(&self, name: &str) -> Option<&[u8]>` | First added header with that name. |

### `Response::switching_protocols`

```rust
let r = http_net::Response::switching_protocols("websocket")
    .header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
assert_eq!(r.status(), 101);
assert_eq!(r.header_value("upgrade"), Some(&b"websocket"[..]));
```

## `Request`

```rust,ignore
pub struct Request { /* private */ }
```

An outgoing request; the request line always says HTTP/1.1.

| Method | Notes |
|---|---|
| `new(method: &str, target: &str) -> Request` | Method must be a token; the target must be in a form the method allows. |
| `get(target)`, `post(target)` | Shorthands. |
| `header(self, name, value) -> Request` | As for `Response`; a second `host` is `InvalidHost`. |
| `body`, `chunked`, `content_length`, `close` | As for `Response`. |
| `upgrade(self, protocol: &str) -> Request` | Writes `connection: upgrade` and `upgrade: <protocol>`. |
| `method(&self) -> &str`, `target(&self) -> &str` | |
| `body_bytes`, `header_value` | As for `Response`. |

### `Request::upgrade`

```rust
let r = http_net::Request::get("/rpc").header("host", "a").upgrade("websocket");
assert_eq!(r.header_value("upgrade"), Some(&b"websocket"[..]));
```

## `Method`

```rust,ignore
#[non_exhaustive]
pub enum Method { Get, Head, Post, Put, Delete, Connect, Options, Trace, Patch, Other }
```

`Method::from_bytes(&[u8]) -> Method` (case-sensitive) and
`Method::as_str(&self) -> Option<&'static str>` (`None` for `Other`).

## `Version`

```rust,ignore
#[non_exhaustive]
pub enum Version { Http10, Http11 }
```

`as_str()` gives `"HTTP/1.0"` / `"HTTP/1.1"`. Requests with `HTTP/1.2` to
`HTTP/1.9` are processed as 1.1 (RFC 9110 section 2.5); other majors are
`UnsupportedVersion`.

## `BodyFraming`

```rust,ignore
#[non_exhaustive]
pub enum BodyFraming { None, Length(u64), Chunked, UntilClose }
```

`UntilClose` occurs only for responses. `Content-Length: 0` reports `None`.

## `Limits`

```rust,ignore
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Limits { /* private */ }
```

| Setter | Getter | Default | Range |
|---|---|---|---|
| `with_max_start_line(usize)` | `max_start_line()` | 8 KiB | clamped to `16..=16 MiB` |
| `with_max_header_bytes(usize)` | `max_header_bytes()` | 16 KiB | clamped to `2..=16 MiB` |
| `with_max_headers(usize)` | `max_headers()` | 100 | clamped to `0..=65536` |
| `with_max_body(u64)` | `max_body()` | 1 MiB | any |

`max_start_line` also bounds each chunk-size line; `max_header_bytes`
counts every field line plus the blank line that ends the section. Trailer
fields are counted against `max_headers` and `max_header_bytes` separately
from the head. `max_header_bytes` also caps, per message, the total of all
chunk extensions and (on the client) of all interim 1xx heads. A
read-until-close response body is delivered up to `max_body` and refused
at the first byte past it. The input buffer never exceeds
`2 * (max_start_line + max_header_bytes) + 16 KiB`.

### `Limits::new`

```rust
use http_net::Limits;

let limits = Limits::new().with_max_body(64 * 1024).with_max_headers(32);
assert_eq!(limits.max_body(), 64 * 1024);
assert_eq!(limits.max_start_line(), 8 * 1024);
```

## `HttpError`

```rust,ignore
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HttpError { /* see table */ }
```

`HttpError::status(&self) -> Option<u16>` is the status a server should
answer with when the error came from parsing a request.

| Variant | `status()` | Meaning |
|---|---|---|
| `InvalidStartLine` | 400 | Start line does not have three parts (or the status line is malformed). |
| `InvalidMethod` | 400 | Method is not a token. |
| `InvalidTarget` | 400 | Bad characters, bad percent-encoding, a form the method does not allow, or an absolute form without `//authority`, with userinfo, or with an empty host. |
| `InvalidVersion` | 400 | Not `HTTP/DIGIT.DIGIT`. |
| `UnsupportedVersion` | 505 | Not HTTP/1.x. |
| `InvalidStatus` | none | Status outside `100..=599` or not three digits; also an unsupported 1xx on `respond`. |
| `StartLineTooLong` | 414 | Over `max_start_line`. |
| `HeadersTooLarge` | 431 | Over `max_header_bytes` (on the client, also interim 1xx heads in total). |
| `TooManyHeaders` | 431 | Over `max_headers`. |
| `BareCr` | 400 | CR not followed by LF. |
| `BareLf` | 400 | LF not preceded by CR. |
| `ObsFold` | 400 | A field line starts with whitespace. |
| `InvalidHeaderName` | 400 | Empty or non-token name, or no colon. |
| `WhitespaceBeforeColon` | 400 | Space or tab between name and colon. |
| `InvalidHeaderValue` | 400 | Control byte in a value. |
| `MissingHost` | 400 | HTTP/1.1 request without `Host`. |
| `InvalidHost` | 400 | Two `Host` fields or a malformed one. |
| `InvalidContentLength` | 400 | Not a single decimal number. |
| `DuplicateContentLength` | 400 | `Content-Length` twice. |
| `ConflictingFraming` | 400 | Both `Content-Length` and `Transfer-Encoding`. |
| `InvalidTransferEncoding` | 400 | Empty, `chunked` twice or with parameters, or not ending in `chunked`. |
| `UnsupportedTransferEncoding` | 501 | A coding other than `chunked`. |
| `TransferEncodingInHttp10` | 400 | `Transfer-Encoding` in HTTP/1.0. |
| `InvalidChunkSize` | 400 | Chunk size not hex or over 16 digits. |
| `InvalidChunkExtension` | 400 | Chunk extension does not follow the grammar. |
| `InvalidChunkTerminator` | 400 | Chunk data not followed by CRLF. |
| `ChunkLineTooLong` | 400 | Chunk-size line over `max_start_line`. |
| `ChunkExtensionsTooLarge` | 400 | Chunk extensions of one message over `max_header_bytes` in total. |
| `BodyTooLarge` | 413 | Over `max_body`: detected from the declared size, or for a read-until-close body at the first byte past it. |
| `UnexpectedEof` | none | Peer closed mid-message. |
| `UnexpectedData` | none | Bytes when no message was expected. |
| `UnexpectedUpgrade` | none | 101 (or CONNECT 2xx) without asking. |
| `ReservedHeader` | none | A builder tried to set a framing header. |
| `BodyNotAllowed` | none | Body on a status that cannot carry one. |
| `BodyLengthMismatch` | none | Streamed length differs from the declared length. |
| `InvalidState(&'static str)` | none | A call out of order; the text names the rule. |

`HttpError` implements `Display` and `core::error::Error`.

## `reason_phrase`

```rust,ignore
pub const fn reason_phrase(status: u16) -> &'static str
```

The RFC 9110 reason phrase, or `""` for an unregistered code.

```rust
assert_eq!(http_net::reason_phrase(404), "Not Found");
```

---

## Blocking adapter

Feature `std` (on by default). A thin shell over the sans-IO core; plain
`http://` only.

### `blocking::Server`

```rust,ignore
pub struct Server { /* private */ }
```

| Method | Notes |
|---|---|
| `bind(addr: impl ToSocketAddrs) -> io::Result<Server>` | Use `127.0.0.1:0` for an ephemeral port. |
| `with_config(self, config: ServerConfig) -> Server` | |
| `on_upgrade(self, hook: impl Fn(Upgraded) + Send + Sync + 'static) -> Server` | Receives sockets after a 101; without a hook they are closed. |
| `local_addr(&self) -> SocketAddr` | |
| `shutdown_handle(&self) -> ShutdownHandle` | |
| `serve<H>(self, handler: H) -> io::Result<()>` | `H: Fn(&RequestHead<'_>, &[u8]) -> Response + Send + Sync + 'static`. |

`serve` runs one thread per connection, up to `max_connections`. The next
connection is answered 503 and closed from the accept thread without
waiting on the peer: only bytes that have already arrived are drained, so a
refused client cannot stall the accept loop. The handler receives the
complete body; a request with `Expect: 100-continue` gets `100 Continue`
before its body is read. Parse errors are answered with their status and
closed. A request that is still incomplete when its request timeout (or a
read timeout) expires is answered `408` and closed. A handler that returns
a streamed response (`chunked` / `content_length`, which `Server` cannot
send) or an invalid one (for example a reserved header, or a 101 to a
request that did not ask) is answered `500` and closed; streamed framing on
a `HEAD` answer is allowed, since no body follows. Every response gets a
`date` header unless the handler set one. Closing connections are drained
(lingering close) for at most 1 s and 256 KiB so the last response is not
lost to a reset. **Errors:** only if accepting fails persistently (1000
consecutive errors); transient accept errors are retried after 10 ms.

### `blocking::ServerConfig`

| Setter | Getter | Default |
|---|---|---|
| `with_limits(Limits)` | `limits()` | `Limits::new()` |
| `with_max_connections(usize)` | `max_connections()` | 64 (at least 1) |
| `with_read_timeout(Option<Duration>)` | `read_timeout()` | 10 s (each read; also the idle keep-alive timeout) |
| `with_request_timeout(Option<Duration>)` | `request_timeout()` | 30 s, from a request's first byte to the end of its body; idle keep-alive time does not count. This is what stops a client that sends one byte just inside the read timeout (slowloris). |
| `with_write_timeout(Option<Duration>)` | `write_timeout()` | 10 s (each write) |

For LexerSketch Studio's budget ("header timeout 10 s"), set
`with_request_timeout(Some(Duration::from_secs(10)))`.

### `blocking::ShutdownHandle`

`shutdown(&self)`: stop accepting, let each connection finish its current
exchange, wait for them, and return from `serve`. A connection idle in a
read finishes when its read timeout expires.

### `blocking::Connection`

A blocking server connection for your own accept loop or for keeping the
socket after an upgrade.

| Method | Notes |
|---|---|
| `new(stream: TcpStream, limits: Limits) -> Connection` | Set socket timeouts first if you want them; the socket's read timeout is the idle timeout. |
| `with_request_timeout(self, Option<Duration>) -> Connection` | Deadline per request, from its first byte to the end of its body; `None` by default. |
| `next_request(&mut self) -> Result<Option<Incoming<'_>>, Error>` | `None` when the connection is finished. Answers `Expect: 100-continue` itself. A missed deadline is `Error::Io` of kind `TimedOut`. |
| `respond(&mut self, response: &Response) -> Result<(), Error>` | Adds `date`. |
| `send_body(&mut self, data: &[u8])`, `end_body(&mut self)` | Streamed responses. |
| `is_upgraded(&self) -> bool` | |
| `into_upgraded(self) -> Option<Upgraded>` | |
| `close(self)` | Lingering close. |

### `blocking::Incoming`

`head(&self) -> RequestHead<'a>` and `body(&self) -> &'a [u8]`.

### `blocking::Upgraded`

```rust,ignore
pub struct Upgraded {
    pub stream: TcpStream,
    pub leftover: Vec<u8>,
    pub target: String,
}
```

### `blocking::get`

```rust,ignore
pub fn get(url: &str) -> Result<ClientResponse, Error>
```

`Client::new().get(url)`.

### `blocking::Client`

| Method | Default |
|---|---|
| `new()` | 16 MiB body limit, 30 s timeouts (each connect, read, and write; there is no total deadline per response) |
| `with_limits(Limits)` | |
| `with_timeout(Duration)` | connect, read, and write timeout |
| `get(&self, url: &str) -> Result<ClientResponse, Error>` | `http://host[:port][/path][?query]`; one connection per request |

### `blocking::ClientResponse`

`status()`, `headers()` (iterator of `(&str, &[u8])`), `header(name)`,
`body()`, `text()` (if UTF-8), `into_body()`.

### `blocking::Error`

```rust,ignore
#[non_exhaustive]
pub enum Error { Io(io::Error), Http(HttpError), InvalidUrl(&'static str) }
```

Implements `Display`, `std::error::Error` (with `source`), and `From` for
`io::Error` and `HttpError`.

## Feature flags

| Feature | Default | Description |
|---|---|---|
| `std` | yes | The `blocking` module. Without it the crate is `no_std` + `alloc`. |

## Limits and guarantees

- Every limit is checked before the bytes it governs are buffered; declared
  lengths and chunk sizes before their data is read.
- Head parsing resumes where it stopped, so it is linear in the head size
  however the input is split; buffer compaction copies at most the pinned
  head plus one partial line, so total copying is linear in the input.
- No reachable panics: `#![forbid(unsafe_code)]`, no `unwrap`/`expect` in
  library code, and property tests on arbitrary input, both from the first
  byte and behind valid heads (so body, chunk, and trailer states are
  reached).
- The parse result does not depend on how the input is split (property
  tested, including after a valid head).
- Every refusal in [What is refused](#what-is-refused-and-why) has a test
  that feeds it whole and split at every byte (`tests/smuggling.rs`,
  `tests/rfc_cases.rs`, `tests/adversarial.rs`).

Not provided in 0.2.0 (see the roadmap): TLS; `cargo fuzz` targets (v0.9.0;
the property tests above stand in); a client with several outstanding
pipelined requests; interim responses other than `100 Continue` from the
server (for example `103 Early Hints`); sending `Expect: 100-continue` from
the client; an async adapter; content codings (`gzip`) and transfer codings
other than `chunked`.
