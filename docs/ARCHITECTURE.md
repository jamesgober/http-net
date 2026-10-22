# http-net - Architecture

How the crate is built: the modules, how bytes flow through a connection,
the state machines, how bodies are framed, and how memory is bounded. For
the public surface see [`API.md`](API.md); for threats and their defences
see [`SECURITY.md`](SECURITY.md).

## Principles

- **No I/O.** The caller owns sockets, threads, timers, and the clock. A
  connection object takes bytes in (`feed`, or `read_buf` + `commit`),
  reports what it parsed (`poll`), and serializes outgoing messages into a
  caller-owned buffer. The same core runs under a blocking loop, an event
  loop, or a test without sockets.
- **Strict by construction.** A message two implementations could frame
  differently is refused with a specific `HttpError`, never repaired.
- **Bounded by configuration, never by input.** Every budget in `Limits` is
  checked before the bytes it governs are buffered.
- **Zero-copy views.** Parsed heads are offsets into the connection's own
  buffer; accessors return slices of the bytes that arrived.
- **No dependencies, no `unsafe`.** `#![forbid(unsafe_code)]`; the core is
  `no_std` + `alloc`.

## Modules

| Module | Responsibility |
|---|---|
| `lib.rs` | crate docs, re-exports, `VERSION`, lint policy |
| `error.rs` | `HttpError`, the status to answer with, peer and usage categories |
| `limits.rs` | `Limits`: every budget, and the derived buffer capacity |
| `buffer.rs` | the bounded input buffer: pinned head, read cursor, lazy growth, compaction, pooling, wiping |
| `syntax.rs` | the 256-entry byte-class table, word-at-a-time (SWAR) scanners, token, field-value, target, and `Host` checks, the quote-aware list walker, number writers |
| `head.rs` | the resumable head scanner, field parsing, interpretation (framing, `Host`, `Expect`, `Upgrade`), and the borrowed views (`RequestHead`, `ResponseHead`, `Headers`, `HeaderValues`, `ListElements`) |
| `method.rs` | `Method`, `MethodSet` |
| `status.rs` | the status registry: `reason_phrase`, `StatusClass`, the `status` constants |
| `date.rs` | `HttpDate` (IMF-fixdate) and `DateCache` |
| `redact.rs` | the credential-field list and the redacting formatter every `Debug` uses |
| `body.rs` | the body decoder (Content-Length, chunked, until close) and encoder |
| `message.rs` | the `Request` and `Response` builders, outgoing trailer validation |
| `server.rs` | `ServerConn`, `ServerEvent`, `Progress` |
| `client.rs` | `ClientConn`, `ClientEvent`, the pipelining queue |
| `blocking.rs` | (feature `std`) a bounded thread-per-connection server, a per-connection driver, a minimal client |

The Tier-3 surface of 0.5 adds stateless head parsers, a standalone
chunked decoder, an `Output` trait with an allocation-free head writer,
hop-by-hop forwarding helpers, and HTTP/2 preface detection, each in its
own module and sharing code with the connections rather than copying it.

## Data flow (server side)

```
 socket bytes
   |  feed(&[u8])  or  read_buf() + commit(n)        bounded by Limits::buffer_capacity
   v
 Buffer [ pinned head | consumed | unread | spare ]
   |  poll()
   v
 HeadScanner.advance    line by line, resumable; budgets checked before waiting
   |  head complete
   v
 interpret_request      start line, target form, version, field facts,
   |                    framing, Host, Expect, Upgrade
   |                    error -> Failed: one error response allowed, then Closed
   v
 ServerEvent::Request(RequestHead)      views over the pinned head
   |  poll()
   v
 Decoder.step           Length | chunked (size line, data, CRLF, trailers) | none
   v
 Body(&[u8]) ... [Trailers(Headers), opt-in] ... RequestEnd
   |  respond / send_informational / send_continue / send_body / end_body
   v
 the caller's Vec<u8>   -> the caller writes it to the socket
   |  poll()
   v
 next request (pipelined bytes already buffered) | AwaitingResponse | Upgraded | Closed
```

The client mirrors it: `send_request` writes into the caller's buffer
(several requests when pipelining), and `poll` reports `Response`, `Body`,
the opt-in `Informational` and `Trailers`, `Continue`, `ResponseEnd`, then
`Idle` (reusable) or `Closed`.

## Head scanning

The scanner finds one CRLF-terminated line at a time and remembers where its
search for LF stopped, so input that arrives one byte at a time is examined
once: head parsing is linear in the head's length however the input is
split. The LF search and the field-value check go eight bytes at a time
(SWAR), with an exact per-byte fallback proven equal for every byte at every
position. A line is fully validated when it completes; its budget (the start
line, one field line, or what is left of the section) is checked against the
bytes seen before the scanner waits for more, so a peer cannot make the
connection buffer past a budget by withholding the line end.

Most field lines take a one-pass fast path when the whole line is already
buffered: the name is walked with the byte-class table up to the colon,
spaces are skipped, the value is checked eight bytes at a time for anything
outside printable ASCII, and the line must end in CR LF. Any other shape (a
tab or obs-text in the value, a control byte, a bare CR or LF, a fold, a
line whose search began on earlier input) takes the general path above from
the line's start, so the fast path changes speed, never the outcome. Chunk
lines have the same arrangement: hex digits and CR LF in one pass,
extensions and everything else through the general chunk-line parser.

Field positions are stored as `u32` offsets (two spans, 16 bytes per field)
relative to the message start, in a field index reused across messages.

## State machines

### Server

The request state and the response state are separate, because a response
may start before the request body was read.

```
 Request:  Head --head ok--> Body --body done--> Complete
           Head|Body --parse error--> Failed --one error response--> Closed
           Body --response sent while body unread--> Closed
           Complete --response sent, keep-alive--> Head (next exchange)
           Complete --response sent, close--> Closed
           Body|Complete --101 or CONNECT 2xx sent--> Upgraded
 Response: Idle --respond(full body)--> Sent
           Idle --respond(streamed)--> Streaming --end_body--> Sent
           Idle --send_continue / send_informational--> Idle
```

Invariants, each with a test: nothing is parsed after `Failed`; at most one
response per request and one error response after `Failed`; a response sent
while body bytes are unread closes the connection; `Upgraded` only by a 101
naming an offered protocol for a complete upgrade request, or a 2xx to a
complete `CONNECT`; the parser never waits for input while the buffer is
full.

### Client

```
 Idle --send_request--> Head
 Head --1xx (not 101), under budget--> Head    [Informational if reported]
 Head --100 while waiting for continue--> Head  [Continue]
 Head --101 asked, with Upgrade--> Upgraded
 Head --2xx to CONNECT--> Upgraded
 Head --final response--> Body --done--> Complete
 Complete --reusable, requests queued--> Head (next queued request)
 Complete --reusable--> Idle
 Complete --otherwise--> Closed
 any --parse error--> Closed
```

With a pipeline depth above 1, `send_request` also accepts idempotent,
full-body requests while others are outstanding; they wait in a fixed array
of 32 entries and are answered in order.

### Body decoder

```
 start: None | Length(0) -> Done;  Length(n) -> Length;  Chunked -> ChunkSize;  UntilClose
 ChunkSize --"0[ext]"--> Trailers --blank line--> Done   (or TrailersReady, reported, then Done)
 ChunkSize --"n[ext]", total + n <= max_body--> ChunkData --n bytes--> ChunkDataEnd --CRLF--> ChunkSize
 UntilClose --EOF--> Done;  --a byte past max_body--> BodyTooLarge
 Length / ChunkData --EOF before the end--> UnexpectedEof
```

## Framing

RFC 9112 section 6.3 is applied in order, with stricter choices where a
recipient could otherwise read a message differently from another hop:

| Situation | RFC 9112 6.3 | http-net |
|---|---|---|
| Response to HEAD; 1xx, 204, 304 | no body | no body, whatever the fields say |
| 2xx to CONNECT | tunnel | `Upgraded` (client); no framing fields written (server) |
| `Transfer-Encoding` and `Content-Length` | TE wins; may reject | refused, `ConflictingFraming` |
| TE not ending in `chunked` (request) | 400 | refused; also `chunked` twice or with parameters, an empty TE |
| TE with another coding before `chunked` | valid | refused, `UnsupportedTransferEncoding` (501): no transfer codings besides chunked |
| TE in HTTP/1.0 | faulty framing | refused, `TransferEncodingInHttp10` |
| TE not ending in `chunked` (response) | read until close | refused |
| Invalid or listed CL | error unless identical | anything but one `1*DIGIT` refused, identical lists and repeated fields included |
| Valid CL | that many bytes | the same; over `max_body` refused on the header line |
| Request with neither | no body | no body |
| Response with neither | until close | until close, bounded by `max_body`; not reusable |

## Memory

- **Input buffer:** one `Vec<u8>` per connection, grown lazily from 4 KiB by
  doubling, capped at `Limits::buffer_capacity()` (64 KiB with the
  defaults): room for a pinned head plus one chunk-size line or trailer
  section. Compaction moves only the pinned head and the unread tail, and
  only when spare space runs out, so total copying is linear in the input.
  Drivers can adopt pooled storage (`with_buffer`), give it back
  (`into_buffer`), free it while idle (`shrink_idle`), and reuse the object
  for a new socket (`reset`).
- **Wiping (opt-in):** with `set_wipe(true)` the buffer zeroes each
  finished message's bytes, the stale copies compaction leaves past the new
  end, and everything on reset, release, and drop.
- **Field index:** one `Vec` of 16-byte records per connection, reused; at
  most `max_headers` entries (and as many for trailers when they are
  reported).
- **Offsets:** `u32`, safe because `Limits` caps every budget at 16 MiB.
- **Output:** caller-owned.
- **Steady state:** a counting-allocator test serves 10,000 keep-alive
  requests (and 10,000 pipelined responses on the client) on one connection
  after warm-up and counts zero allocations.

## Shared grammar

The generic field grammar (tokens, field values, quoted strings, list
splitting, HTTP-date) is specified by the sibling crate `parse-net`. Until
it is published, http-net keeps it internally behind the same shapes (the
quote-aware list walker, the IMF-fixdate formatter); the HTTP/1.1 wire
scanners (line finding, chunk lines, request-target and `Host` checks, the
status line) stay here because they are framing, not field grammar.
