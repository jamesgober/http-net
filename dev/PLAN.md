# http-net - Plan

> The design of `http-net` and the record of every design decision. Created
> at the start of 0.3 from the library specification (kept privately by the
> maintainer; it stays the contract). This file carries the decision log and
> the defence-ideas log from here on. Read with `dev/DIRECTIVES.md`
> (standards and definition of done), `dev/ROADMAP.md` (versions and exit
> criteria), and `docs/API.md` (the approved public surface).

---

## 1. What it is

`http-net` owns HTTP/1.1 message syntax, framing, and connection state for
servers and clients, and nothing else. It does no I/O: the caller owns
sockets, threads, timers, and the clock, so one core runs under a blocking
loop, `serve-net`'s connection engine, WASP's gateway workers, or a test
that never opens a socket.

It is strict by construction (a message two implementations could frame
differently is refused with a specific `HttpError`, never repaired) and
bounded by configuration, never by input (every budget is checked before
the bytes it governs are buffered).

Not here: TLS (`tls-net`), event loops and accept loops at scale (`net-io`,
`serve-net`), routing (`web-net`), URL normalisation and percent-decoding
(the URL crate), cookies (`cookie-net`), form bodies (`form-net`), generic
field grammar (`parse-net`, from 0.4), content codings (a compression
crate), HTTP/2 (`h2-net`), WebSocket framing (`ws-net`), the full client
(`fetch-net`), proxying (`proxy-net`), caching, authentication.

First consumers: LexerSketch Studio (blocking server and client, upgrade
hand-off), `serve-net` (engine slot), WASP `gateway-io` (parser slot),
`fetch-net`, `proxy-net`, `ws-net`, `h2-net` (shared semantic types).

## 2. Modules

| Module | Responsibility |
|---|---|
| `lib.rs` | crate docs (Tier 1 first), re-exports, `VERSION`, lint policy |
| `error.rs` | `HttpError`, `status()`, peer / usage categories |
| `limits.rs` | `Limits` and `buffer_capacity` |
| `buffer.rs` | one bounded input buffer per connection: pinned head, read cursor, lazy growth, compaction only when spare space runs out |
| `syntax.rs` | the 256-entry byte-class table, SWAR scanners, token / field-value / target / `Host` checks, number writers (the generic grammar part moves to `parse-net` in 0.4, OD-1) |
| `head.rs` | resumable `HeadScanner`, field parsing, interpretation (framing, `Host`, `Expect`, `Upgrade`), the `RequestHead` / `ResponseHead` / `Headers` / `HeaderValues` views |
| `method.rs` | `Method`, `MethodSet` |
| `status.rs` | `reason_phrase`, `StatusClass`, the `status` constants |
| `redact.rs` | the credential-field list and the redacting value formatter used by every `Debug` |
| `body.rs` | the body decoder (Content-Length, chunked, until close) and encoder |
| `message.rs` | `Request` and `Response` builders, `Response::from_error` |
| `server.rs` | `ServerConn`, `ServerEvent` |
| `client.rs` | `ClientConn`, `ClientEvent` |
| `blocking.rs` | (feature `std`) bounded thread-per-connection server, per-connection driver, minimal client |

Target layout at 1.0 adds `chunked.rs` (standalone decoder), `trailers.rs`,
`write.rs` (`Output`, allocation-free writer), `forward.rs`, `date.rs`,
`parse.rs` (stateless parsers), and splits `blocking` into a directory; each
module keeps one responsibility and the public surface is exactly
`docs/API.md`.

## 3. Data flow (server side)

```
 socket bytes
   |  feed(&[u8]) or read_buf() + commit(n)     (bounded: Limits::buffer_capacity)
   v
 Buffer [ pinned head | consumed | unread | spare ]
   |  poll()
   v
 HeadScanner.advance   line by line, resumable, budgets checked first
   |  head complete
   v
 interpret_request     start line, target form, version, field facts, framing, Host, Expect, Upgrade
   |                   error -> Failed: one error response allowed, then Closed
   v
 ServerEvent::Request(RequestHead)   views over the pinned head
   |  poll()
   v
 Decoder.step          Length | chunked (size line, data, CRLF, trailers) | none
   v
 ServerEvent::Body(&[u8]) ... ServerEvent::RequestEnd
   |  respond / send_continue / send_body / end_body  -> caller's Vec<u8>
   v
 next request (pipelined bytes already buffered) | AwaitingResponse | Upgraded | Closed
```

The client mirrors it: `send_request` writes into `out`, `poll` reports
`Response`, `Body`, `ResponseEnd`, then `Idle` (reusable) or `Closed`.

## 4. State machines and invariants

Server request state: `Head -> Body -> Complete -> (Head | Closed)`,
`Head|Body -> Failed -> Closed`, `Body|Complete -> Upgraded` (101 or
CONNECT 2xx). Response state is separate (`Idle -> Streaming -> Sent`)
because a response may start before the request body is read.

| Invariant | Test |
|---|---|
| I-S1 after `Failed`, no further request is parsed, whatever bytes follow | `test_connection_is_dead_after_an_error` |
| I-S2 at most one response per request; at most one error response after `Failed` | `test_respond_after_failure_is_once_and_closes` |
| I-S3 a response sent while request body bytes are unread forces `Closed` after it | `test_early_response_closes_connection` |
| I-S4 `Upgraded` only by a 101 answering a complete upgrade request with an offered protocol, or a 2xx answering a complete CONNECT | upgrade tests in `tests/adversarial.rs` |
| I-S5 the parser never waits for input while the buffer is full | asserted by every test driver |

Client: `Idle -> Head -> (Body -> Complete -> Idle|Closed) | Upgraded`;
bytes in `Idle` are `UnexpectedData`; any parse error closes.

## 5. Framing and strictness

RFC 9112 section 6.3 is applied in order, with these stricter choices (each
has a test): CL with TE refused (`ConflictingFraming`), duplicate or list
CL refused even when equal, TE must end in exactly one parameterless
`chunked`, other transfer codings 501, TE in HTTP/1.0 refused, a response
whose TE does not end in `chunked` refused (not read until close), bare LF
and bare CR refused, obs-fold refused (client opt-in replacement in 0.5),
chunk sizes over 16 hex digits refused, a space after a chunk size without
an extension refused. Accepted on purpose: HTTP/1.2 to 1.9 as 1.1, empty
lines before a request line (budgeted), obs-text in values, a status line
without the space after the code (client, from 0.3).

## 6. Memory

- Input buffer: one `Vec<u8>` per connection, grown lazily from 4 KiB by
  doubling, capped at `2 * (max_start_line + max_header_bytes) + 16 KiB`
  (64 KiB by default). Compaction moves only the pinned head and the
  unread tail, and only when spare space is exhausted: total copying is
  linear in the input.
- Field index: one `Vec` of 16-byte records per connection, reused; at
  most `max_headers` entries.
- Offsets are `u32`, safe because `Limits` caps every budget at 16 MiB.
- Output is caller-owned (`Vec<u8>` today, any `Output` from 0.5).
- Steady state allocates nothing in the core (counting-allocator test,
  `tests/alloc.rs`).

## 7. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-1 | 2026-10-21 | **Design lock revisited at the start of 0.3 (OD-18 a).** `docs/API.md` was rewritten from the specification's API section (the full 1.0 surface, every item tagged with the version it ships in) and approved by James before the first 0.3 code change. From 0.3 the series follows the standard version table. | 0.2.0 shipped a working core but no approved 1.0 surface; a docs-only 0.2.1 would add noise. |
| D-2 | 2026-10-21 | The specification's recommendations for its open decisions OD-1 to OD-23 are adopted as written (approved with D-1). Summary: parse-net carries the generic field grammar from 0.4, HTTP/1.1 wire scanners stay here (OD-1); an `Output` trait beside the `Vec` methods in 0.5 (OD-2); `Response::clear` and a borrowed writer (OD-3); opt-in trailer and interim events (OD-4, OD-5); `h2c` ignored as an upgrade offer (OD-6); opt-in in-place obs-fold replacement on the client (OD-7); SWAR only until 0.6 numbers exist (OD-8); `u16` status codes with constants (OD-9); a `Method` variant only when an RFC registers it (OD-10); no async adapter (OD-11); passport copy-out, not buffer swap (OD-12, decided earlier by James); h2-net uses this crate's semantic types (OD-13); identical duplicate CL and CL with TE stay refused (OD-14, OD-15); a core without `alloc` after 1.0 (OD-16); the blocking client stays minimal (OD-17); unknown expectations reported, 417 only in the blocking server (OD-19); the caller supplies the time for `Date` (OD-20); new default budgets of 8 KiB per field line, 16 interim responses, 60 s response deadline, from 0.4 (OD-21); `Content-Length: 0` stays `BodyFraming::None` and `content_length()` reports the declared value (OD-22); a fixed redaction list in 0.3, an extensible one evaluated in 0.5 (OD-23). | Each recommendation is argued in the specification; none conflicts with a written rule. |
| D-3 | 2026-10-21 | Approved exception to the REPS clause "MUST use tokio": this crate uses no async runtime and has no async adapter (the old roadmap's v0.5.0 async adapter is withdrawn). | Portfolio rule: cores are sans-IO; `serve-net` and `net-io` drive the core. |
| D-4 | 2026-10-21 | `HttpError::is_peer_error` and `is_usage_error` are per variant. Variants that both parsing and a caller mistake can raise (`InvalidTarget`, `InvalidMethod`, `InvalidStatus`, `BareCr`, `InvalidHeaderName`, `InvalidHeaderValue`, `MissingHost`, `InvalidHost`, `UnexpectedData`) return true for both; the call that returned the error tells which it was (`poll` returns only peer errors). | The enum is fieldless and `Copy`; splitting the dual variants would double the error surface for no gain to a caller, who always knows which call failed. |
| D-5 | 2026-10-21 | A `101` must name an offered protocol: compared ASCII case-insensitively, and a `101` naming only a protocol name matches an offer of that name with or without a version. `h2c` never counts as offered. | RFC 9110 section 7.8 MUST NOT; WebSocket clients vary in case; RFC 9113 section 3.1 deprecates h2c. |
| D-6 | 2026-10-21 | Redaction covers `Headers`' `Debug` as well as the views, builders, and `ClientResponse`, since every event and view prints through it. Format: `<redacted N bytes>`. | FR-55 says every `Debug` output of the crate. |
| D-7 | 2026-10-21 | `MethodSet` gains `is_empty`; `write_allow` skips `Other`, which has no name to write. | A router needs to test for an empty set; an `Allow` field must list real methods. |
| D-8 | 2026-10-21 | GitHub release titles use `vX.Y.Z - Title` with an ASCII hyphen. | The library standard bans the em dash in public text. |
| D-9 | 2026-10-21 | `Host` and authority validation tightened: an empty host before a port (`:80`) and a `%` not followed by two hex digits are refused (`InvalidHost` for `Host`, `InvalidTarget` for authority-form and absolute-form authorities, `InvalidHost` for `Request::header("host", ...)`). A port above 65535 stays accepted by syntax (RFC 3986 does not bound it). | FR-12; moved from the old v0.5.0 to sit with the design lock. |
| D-10 | 2026-10-21 | The client accepts a status line without the space after the code (`HTTP/1.1 200` CRLF); `reason()` is then `""`. The server side is unaffected. | Real servers omit it and it cannot change framing (FR-41). |
| D-11 | 2026-10-21 | `httparse` is a dev-dependency (differential tests only); hyper and tokio never become dev-dependencies (their comparison lives in a separate, unpublished bench repository). The fuzz crate under `fuzz/` is its own package, excluded from the published crate, and uses `libfuzzer-sys` and `arbitrary`. | Dev tooling is allowed; the published crate keeps zero runtime dependencies and `cargo deny` stays clean. |
| D-12 | 2026-10-21 | `HeaderValues` has two lifetimes, `HeaderValues<'a, 'n>`: the values borrow the head (`'a`) and only the lookup name is `'n`. The approved sketch had one lifetime, which tied the values to the name. | With one lifetime, `req.header_all(&name)` with a temporary `String` could not keep its values, unlike `header()`. Found while testing 0.3; adding the lifetime after release would be breaking. |

## 8. Defence ideas (one per version)

| Version | Hypothesis | Method | Expected cost | Outcome |
|---|---|---|---|---|
| 0.3 | A differential test against httparse on every input http-net accepts will find any byte where the two disagree on the head boundary or field split, which is what a front-end / back-end desync needs. | Property and fuzz harness: for inputs http-net accepts, httparse (strict config) must accept with the same length and fields; every disagreement is an http-net refusal httparse lacks, or a bug. | dev-only, CI time | `tests/prop_httparse.rs` and the `httparse_diff` fuzz target |
| 0.4 | An "agreement mode" for proxies: report the facts a lenient hop would read differently (for example a GET with a body) so proxy-net can log or refuse them. | a `quirks` bit set computed during field facts | under 1 ns | |
| 0.5 | Wiping consumed input removes credential remnants between keep-alive requests at under 2% of a request. | measure `set_wipe(true)` on the head bench | 30-60 ns [est.] | |
| 0.6 | SWAR scanning of 16 bytes per step closes most of the gap to SIMD without `unsafe`. | bench against httparse with and without SIMD | code size | |
| 0.7 | HTTP Garden runs find no discrepancy class that hyper does not also have. | containerised origin in the Garden | CI time | |
| 0.8 | A per-connection strike counter lets drivers ban abusive sources earlier. | `ServerConn::strikes()` | one increment per refusal | |
| 0.9 | Normalising outgoing field-name case removes a fingerprinting surface at no measurable cost. | bench `respond` with lowercasing | about 1 ns per name [est.] | |
