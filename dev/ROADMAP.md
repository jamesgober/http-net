# http-net - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Master plan: C:/Dev/libraries/Rust/lang-collection/_lexersketch/ROADMAP.md and NEW-LIBS.md
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.

## v0.1.0 - Scaffold (DONE)
Compiles, CI green, structure correct, no domain logic.
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP.

## v0.2.0 - Foundation (DONE, 2026-10-12)
- [x] Sans-IO request/response parser and serializer, keep-alive, chunked bodies, server and client state machines, a blocking std adapter; smuggling and fuzz-style property tests.
- [x] Upgrade hand-off for ws-net (moved forward from v0.5.0: LexerSketch Studio's
  WebSocket needs it, and it is a small, self-contained state transition).
- [x] `Expect: 100-continue` on the server (moved forward from v0.5.0 during the
  adversarial review: RFC 9110 section 10.1.1 makes answering the expectation a
  MUST, and the blocking server, which reads the whole body before calling the
  handler, otherwise stalled every expecting client).
- [x] Adversarial review against RFC 9110 / 9112 (2026-10-12): findings fixed with
  a failing test first; see "Review fixes" below.

Delivered:
- `ServerConn` / `ServerEvent` and `ClientConn` / `ClientEvent`: sans-IO state
  machines over one bounded input buffer each (`feed` or `read_buf` + `commit`,
  `poll`, `feed_eof`); responses and requests serialized into a caller-owned
  `Vec<u8>`; streamed bodies through `send_body` / `end_body`.
- Strict RFC 9112 parsing: request line forms checked against the method,
  versions (1.2-1.9 processed as 1.1), field syntax, `Host` rules, and framing
  per section 6.3 (HEAD, 1xx, 204, 304, CONNECT 2xx, until-close responses).
- Smuggling defences: CL+TE, duplicate or list CL, any TE other than a single
  final `chunked`, TE in HTTP/1.0, obs-fold, bare CR, bare LF, whitespace
  before colon, control bytes, malformed chunk lines and extensions. After a
  parse error the connection parses nothing further.
- `Limits` (8 KiB line, 16 KiB headers, 100 fields, 1 MiB body by default),
  each checked before the bytes it governs are buffered; the input buffer is
  capped at `2 * (line + headers) + 16 KiB`; head scanning resumes where it
  stopped, so parsing is linear however the input is split.
- Keep-alive (HTTP/1.1 default, HTTP/1.0 opt-in), in-order serving of pipelined
  requests, early responses (close afterwards when body bytes are unread; a
  bodiless request stays keep-alive), HTTP/1.0 chunked fallback.
- Request targets: origin, absolute (`scheme://authority[path][?query]`, no
  userinfo, non-empty host; its authority is `host()` and `Host` is ignored per
  RFC 9112 section 3.2.2), authority (`CONNECT`), asterisk (`OPTIONS`).
- `Expect: 100-continue`: `RequestHead::expects_continue`,
  `ServerConn::send_continue`; the blocking server answers it itself.
- Cumulative budgets: chunk extensions per message and interim 1xx heads per
  response count against `max_header_bytes`; a read-until-close body is
  delivered up to `max_body` and refused past it.
- Upgrade hand-off: `RequestHead::is_upgrade`, `Response::switching_protocols`,
  `ServerEvent::Upgraded` + `remaining_input`; client side `Request::upgrade`,
  `ClientEvent::Upgraded`; CONNECT 2xx tunnels.
- `blocking`: bounded thread-per-connection `Server` (503 over the cap without
  the accept thread waiting on the peer, read/write timeouts, a per-request
  deadline answered with 408, automatic `100 Continue`, `date`, lingering close
  bounded to 1 s, 500 for streamed or invalid handler responses, upgrade hook,
  shutdown), `Connection` (with `with_request_timeout`), `Client` / `get`.
- Tests: RFC cases as data, smuggling suite, adversarial suite, property tests
  (round trip, split invariance, no panics, from the first byte and behind valid
  heads), a differential test against an independent reference parser, a
  100k-request scale test, localhost socket tests (including slow peers).
  Criterion benches.

Review fixes (adversarial review, 2026-10-12; each has a test that failed first):
- Blocking server: lingering close waited 250 ms *per read* with no total, and
  the 503 refusal ran it on the accept thread, so one refused client trickling
  bytes stalled every new connection (measured 2.8 s; unbounded in general).
  Now the refusal never waits on the peer and the drain stops after 1 s total.
- Blocking server: only a per-read timeout, so a client sending a byte every
  few seconds held a connection forever (slowloris). Added the per-request
  deadline (`ServerConfig::with_request_timeout`, 30 s) answered with 408.
- Blocking server: `Expect: 100-continue` was never answered (RFC 9110 MUST).
- Absolute-form targets: `host()` returned the `Host` field rather than the
  target's authority, `path()` returned the whole URI, and userinfo, an empty
  host, or no `//authority` at all were accepted.
- Chunk extensions were bounded per line but not per message.
- The client skipped interim 1xx responses without any budget.
- A response sent at `ServerEvent::Request` to a bodiless request closed the
  connection needlessly.
- A read-until-close body over `max_body` produced different events depending
  on how the input was split (found by the new behind-the-head property test).
- A handler returning a streamed or invalid `Response` left the client with a
  half-written response or none; it now gets 500.

Dependency wiring (recorded per the anti-deferral rule):
- **None wired.** No first-party `-lang` crate covers HTTP syntax; the crate is
  dependency-free (runtime and build). `criterion` and `proptest` are
  dev-dependencies only.
- **Fuzz target (DIRECTIVES section 3 item 6):** planned for v0.9.0 Hardening,
  as this roadmap already lists. In this release the property tests that feed
  arbitrary and dictionary-built bytes to both connections (whole, split, and
  with tiny limits) cover the same ground without nightly tooling.

Remaining in v0.5.0 (as originally planned): interim 1xx responses other than
`100 Continue` from the server (for example `103 Early Hints`); sending
`Expect: 100-continue` from the client and waiting for it; a client with
several outstanding pipelined requests (the server already serves pipelined
requests in order); an async adapter.

## v0.5.0 - Implementation
- [ ] Client-side pipelining (several outstanding requests), client-side Expect: 100-continue, server interim 1xx responses other than 100, an async adapter.
- [ ] Blocking client: a total deadline per response (today its timeouts apply to each connect, read, and write).
- [ ] Blocking server: a total deadline per response write (today the write timeout applies to each write, so a client that reads very slowly can hold a worker thread during a large response). Found in the 0.2.0 adversarial review.
- [ ] Interop: accept a status line without a reason phrase (`HTTP/1.1 200`) on the client side; check percent-escapes in `Host` and refuse an empty host (`:80`).

## v0.9.0 - Hardening
- [ ] Fuzzing (`cargo fuzz` targets for `ServerConn` and `ClientConn`); conformance tests.

## v1.0.0 - Stable
- [ ] Frozen after LexerSketch Studio and ls-publish use it (D18).
