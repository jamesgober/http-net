<h1 align="center">
    <img width="90px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <br><b>CHANGELOG</b>
</h1>
<p>
  All notable changes to <code>http-net</code> will be documented in this file. The format is based on <a href="https://keepachangelog.com/en/1.1.0/">Keep a Changelog</a>,
  and this project adheres to <a href="https://semver.org/spec/v2.0.0.html/">Semantic Versioning</a>.
</p>

---

## [Unreleased]

---

## [0.7.0] - 2026-10-26

Hardening: a 24-CPU-hour fuzz campaign per target, an 8-hour soak of the
blocking server, an attack test for every threat in the specification
(which found and fixed one client upgrade gap), a response-side
differential against httparse, and the completed `docs/SECURITY.md` and
`docs/PLATFORM-NOTES.md`. See `docs/MIGRATION.md` for the one change a 0.6
user can notice.

### Security

- The client switches protocols on a `101` only when every protocol its
  `Upgrade` field names is one the request offered (RFC 9110 section
  7.8); otherwise `UnexpectedUpgrade` (threat T-21). Before, any non-empty
  `Upgrade` was accepted, so a server answering a `websocket` upgrade with
  another protocol took over the connection.

### Added

- `examples/soak.rs`: the soak test of the blocking server (mixed
  workload, one status line per minute, resident memory on Linux).
- An attack test for the accept loop's back-off on persistent accept
  errors (threat T-41).
- Attack tests for every gap the 0.7 threat audit found: non-101 answers
  and protocol-less 101s to an upgrade, a server 101 before the body is
  read, HTTP/0.9 responses, over-long chunk lines (and a 10 MiB stream of
  one), an unanswered pipelining flood, the lingering-close byte cap, a
  slow body answered `408`, wiping on reset, builder injection through
  targets, methods, and values, reserved request fields, `Transfer-Encoding`
  split across fields, redaction of every owned and stateless view,
  `from_error` for every variant, and client trailers that cannot reframe.
- `tests/prop_httparse_response.rs`: the response-side differential against
  httparse (47,249 single-byte mutations and three property tests).
- `docs/PLATFORM-NOTES.md`: timeouts, lingering close, ports and
  TIME_WAIT, memory measurement, `no_std` targets, and fuzzing per
  platform. `docs/SECURITY.md` complete, with the 0.7 hardening record.

---

## [0.6.0] - 2026-10-22

Optimisation: one-pass parsing of the common field and chunk lines,
compile-time status lines, `respond_head_only` with vectored writes, the
comparison repository `http-net-bench`, and `docs/PERFORMANCE.md`. Nothing
a 0.5 user can notice changes except speed (see `docs/MIGRATION.md`).

### Added

- `ServerConn::respond_head_only` (A-224): writes only the head of a
  response and returns the `BodyPlan`, so a driver sends a full body after
  the head with one vectored write instead of copying it into the output
  buffer. The head plus the body are exactly what `respond` writes.
- The blocking server sends full bodies over 4 KiB after the head with one
  `write_vectored`, without copying them.
- `docs/PERFORMANCE.md`: method, numbers, the comparison with httparse and
  hyper, and the decisions behind the optimisations.
- The comparison repository
  [`http-net-bench`](https://github.com/jamesgober/http-net-bench)
  (workloads H1 to H5 against httparse and hyper on identical bytes).
- `scripts/bench_ab.sh`: interleaved A/B benchmarks of the working tree
  against a tag, pinned to one core, for the 5% regression gate.
- Tests: the linearity guard (`tests/linearity.rs`: a head fed one byte at
  a time costs time linear in its size); `respond_head_only` equivalence
  with `respond` over 2,048 generated cases (`tests/head_only.rs`) and over
  real sockets; the fast paths against the general paths on 300,000
  generated field lines and 200,000 chunk lines; `find_byte` at every
  position among near-miss bytes; the status-line table against the parts
  for every code.

### Changed

- Faster head parsing: the common field line (token name, colon, spaces,
  printable value, CR LF) is parsed in one pass instead of three; every
  other shape takes the general path, so what is accepted and refused does
  not change. About 20% faster on the 12-field request head, 15% on
  client response parsing, 12% on pipelined requests.
- Faster chunked bodies: the common chunk line (hex digits, CR LF) is
  parsed in one pass. About 9% faster on a 1 MiB chunked body, 36% on
  `ChunkedDecoder` framing.
- Faster responses: status lines come from a compile-time table built
  from the status registry. About 10% faster on response serialization.

---

## [0.5.0] - 2026-10-21

Feature complete: client pipelining, connection reuse and buffer pooling,
optional wiping of consumed input, and the allocation-free Tier-3 surface
(spans and copied heads, stateless parsers, the `Output` writer, a
standalone chunked decoder, request forwarding, HTTP/2 preface detection),
plus opt-in client tolerance for folded response fields. See
`docs/MIGRATION.md` for what a 0.4 user can notice.

### Added

- Client pipelining: `Limits::with_pipeline_depth` / `pipeline_depth`
  (1 to 32, default 1), `ClientConn::outstanding` and `ClientConn::can_send`.
  Idempotent requests with full bodies are sent before earlier responses
  arrive and matched to them in order from a fixed array.
- Connection reuse and buffer pooling: `reset`, `with_buffer`,
  `into_buffer`, and `shrink_idle` on both connections.
- `ServerConn::set_wipe`: zero each finished request's bytes, the stale
  copies compaction leaves, and the whole buffer on reset, release, and
  drop (threat T-36).
- `Request::forward_from`: a request for an upstream built from a received
  head, with the hop-by-hop fields (RFC 9110 section 7.6.1) removed and the
  framing mode kept; `is_hop_by_hop` and `RequestHead::connection_options`.
- `is_h2_preface`, and the error `HttpError::Http2Preface` (505).
- `ClientLeniency` and `ClientConn::set_leniency`: an opt-in tolerance for
  obsolete line folding in response heads, replaced by spaces in place
  (RFC 9112 section 5.2); every other refusal stays.
- Example `proxy_forward`.
- Example `pipelined_client`: four requests in flight on one connection.
- `docs/ARCHITECTURE.md` (modules, data flow, state machines, framing,
  memory) and the `docs/SECURITY.md` draft (threat model T-1 to T-42 with
  each defence, test, and cost; the deliberate strictness choices).
- Tests: pipelining, reuse, and wiping (`tests/pipelining_reuse.rs`, with a
  property test and control runs for the wipe); allocation tests for
  pipelined responses, wiping, and reset; the `client_conn` fuzz target
  runs with fold leniency and checks that leniency changes nothing on
  unfolded input.
- Spans and raw heads (Tier 3): `Span` and `FieldSpan`, public `u32`
  offsets into a head's bytes (`Span::get` returns an empty slice for a
  span out of range and never panics); `RequestHead::raw` and
  `ResponseHead::raw` return a `RawHead` with the head bytes and the spans
  of the start line, method, target, version, status, and every field.
- The head passport (OD-12): `RequestHead::copy_into` copies the head
  bytes and field spans into caller-owned, reused vectors and returns
  `HeadFacts`; `OwnedRequestHead::from_parts` rebuilds a view from them
  after checking every span and the line structure (`InvalidState` for a
  changed buffer), `view` reads it, and `into_parts` gives the vectors
  back. `RequestHead::to_owned` makes an owned copy in one call. Once the
  vectors have grown, the copy allocates nothing.
- Stateless head parsers (Tier 3): `parse_request_head` and
  `parse_response_head` read one head from a caller slice into a caller
  array of field spans, with the same scanner and rules as the
  connections, and no allocation. They return `Parsed::Complete` with
  `ParsedRequest` / `ParsedResponse` and the head length, or
  `Parsed::Partial`; a head with more fields than the array is
  `TooManyHeaders`. `Asked` tells the response parser whether the request
  was `HEAD` or `CONNECT`.
- Example `passport`: a reader parses pipelined requests with the
  stateless parser and passes copied heads through a passport pool to a
  worker thread.
- Tests: unit tests for every `from_parts` refusal; property tests that
  the stateless parsers agree with `ServerConn` and `ClientConn` and that
  a copied head rebuilds the same view; allocation tests for the
  stateless parsers and `copy_into` into grown vectors (zero
  allocations); fuzz target `stateless_parse` (oracle: equal to
  `ServerConn` and `ClientConn`, copies rebuild) in the CI fuzz matrix.
- `Output`: where serialized bytes go, a `Vec<u8>` or a caller type (a
  zeroizing buffer, a slab, a counter). `put` cannot fail; `reserve` is a
  hint. `&mut O` is an `Output` for any `O: Output`.
- The borrowed writer: `ServerConn::write_head` writes a response head from
  a `ResponseHeadRef` (borrowed fields, an `OutgoingBody`, `close`, an
  optional upgrade protocol) to any `Output` and returns a `BodyPlan`. It
  writes the bytes `respond` writes for the equivalent `Response` and fails
  the same way, and allocates nothing with a reused `Vec`.
- `ServerConn::respond_into`, `send_body_into`, `end_body_into`:
  `respond_with_date`, `send_body`, `end_body_with_trailers` over any
  `Output`.
- `Response::clear`: reset a response for reuse, keeping its field
  allocation.
- `ChunkedDecoder` and `ChunkStep`: a standalone chunked-body decoder over
  caller-owned bytes, with explicit byte accounting and the connection's
  grammar and budgets. It shares the connection's decoder and allocates
  nothing.

### Changed

- A connection that starts with the HTTP/2 connection preface is refused
  with `Http2Preface` instead of `UnsupportedVersion` (both answer 505). The
  check runs only before a connection's first request.
- `respond`, `send_body`, `end_body`, and `end_body_with_trailers` now run
  through the generic `Output` code; their behaviour and output are
  unchanged.

---

## [0.4.0] - 2026-10-21

Extended: trailers and interim responses both ways, the client side of
`Expect: 100-continue`, keep-alive control and progress for drivers, a
cached `Date`, per-line and trailer budgets, and total deadlines in the
blocking adapter. See `docs/MIGRATION.md` for what a 0.3 user can notice.

### Added

- Trailers both ways. `ServerConn::set_report_trailers` and
  `ClientConn::set_report_trailers` report a non-empty trailer section as
  `ServerEvent::Trailers` / `ClientEvent::Trailers` before the end event;
  `ServerConn::end_body_with_trailers` and
  `ClientConn::end_body_with_trailers` send one after a chunked body,
  refusing the fields RFC 9110 section 6.5.1 keeps out of trailers with the
  new `HttpError::TrailerNotAllowed`.
- Interim responses both ways. `ServerConn::send_informational` sends a
  1xx other than 100 and 101 (for example `103 Early Hints`) before the
  final response; `ClientConn::set_report_informational` reports them as
  `ClientEvent::Informational`; `ResponseHead::is_informational`.
- The client side of `Expect: 100-continue`: `Request::expect_continue`,
  `ClientConn::is_waiting_for_continue`, `ClientEvent::Continue`. A final
  status instead of `100` refuses the promised body and closes the
  connection after the response.
- Driver controls: `ServerConn::set_keep_alive` and `keep_alive`,
  `requests_served`, and `progress` with the new `Progress` enum (also
  `ClientConn::progress`, `ClientConn::is_reusable`).
- `HttpDate` and `DateCache` (IMF-fixdate, formatted at most once per
  second; the caller supplies the time) and
  `ServerConn::respond_with_date`.
- `RequestHead::header_list`, `ResponseHead::header_list`, and the
  `ListElements` iterator; `RequestHead::upgrade_protocols` (the offered
  protocols, `h2c` left out); `RequestHead::has_unknown_expectation`.
- `status_allows_body`.
- `Limits::with_max_field_line` / `max_field_line` (8 KiB by default),
  `with_max_trailer_bytes` / `max_trailer_bytes`,
  `with_max_trailer_fields` / `max_trailer_fields` (both following the
  header budgets until set), `with_max_interim` / `max_interim` (16).
- Errors: `FieldLineTooLong` (431), `TooManyInterim`, `InterimNotAllowed`,
  `TrailerNotAllowed`.
- Blocking adapter: `blocking::serve` (bind and serve in one call),
  `blocking::post`, `blocking::now_date` (a per-thread `DateCache` over the
  system clock), `Client::request` (any `Request` to an `http://` URL),
  `Client::with_deadline` (one total deadline per exchange),
  `ServerConfig::with_response_deadline` (60 s to write one response) and
  `with_max_requests_per_connection`, `Connection::with_response_deadline`,
  and `Connection::send_informational`.
- Examples `early_hints` and `trailers`.

### Changed

- One field line may be at most 8 KiB by default (`FieldLineTooLong`); in
  0.3 a single line could use the whole 16 KiB header section. Raise it
  with `Limits::with_max_field_line`.
- `ServerConn::send_continue` reports `InterimNotAllowed` (was
  `InvalidState`) for an HTTP/1.0 request, after the body began or a
  response started, and when sent twice.
- The client stops after `max_interim` interim responses to one request
  (`TooManyInterim`), as well as at the header byte budget.
- Outgoing messages may no longer set `trailer`, `keep-alive`, or
  `proxy-connection`, and responses may not set `te` (`ReservedHeader`):
  they belong to the connection (RFC 9110 sections 7.6.1, 10.1.4).
- `Limits::buffer_capacity` accounts for a trailer budget larger than the
  header budget; with the defaults it is unchanged (64 KiB).
- The blocking server answers a request with an expectation other than
  `100-continue` with `417 Expectation Failed` (and closes) instead of
  ignoring it; `date` comes from a per-second cache instead of being
  formatted for every response.

### Security

- The blocking server's total response deadline (60 s by default) stops a
  client that reads one byte at a time from holding a worker thread during
  a large response (threat T-26); before, only each write had a timeout.
- The blocking client's `with_deadline` bounds a whole exchange, so a slow
  server cannot hold a caller past it.
- `dev/PLAN.md` records the 0.4 decisions (D-13 to D-20), among them
  keeping the shared grammar internal until `parse-net` is published.

### Fixed

- List fields are split with a quote-aware walker: a comma inside a quoted
  string no longer ends an element (the behaviour of the shared grammar
  crate `parse-net`). No message 0.3 accepted reads differently; this
  removes a latent differential between the two crates.

---

## [0.3.0] - 2026-10-21

Core, with the design lock revisited: `docs/API.md` now describes the
whole 1.0 surface, each item marked with the version it ships in, and was
approved before this release's code changes. This release closes a
credential leak in 0.2.0's `Debug` output, refuses the `h2c` upgrade and
switches to unoffered protocols, tightens `Host` validation, fills in the
method and status registries, and adds fuzzing, an allocation-counting
test, a differential test against `httparse`, and an RFC conformance table.
See `docs/MIGRATION.md` for what a 0.2.0 user can notice.

### Added

- `VERSION`: the crate version string.
- `HttpError::is_peer_error` and `HttpError::is_usage_error`, and the
  variant `HttpError::UpgradeNotOffered`.
- `Limits::buffer_capacity`: the input buffer's hard capacity, for planning
  memory per connection.
- `RequestHead::target_form` and the `TargetForm` enum (`Origin`,
  `Absolute`, `Authority`, `Asterisk`).
- `RequestHead::header_all`, `ResponseHead::header_all`, and the
  `HeaderValues` iterator: every field with one name, in arrival order
  (each `Set-Cookie` separately).
- `RequestHead::content_length` and `ResponseHead::content_length`: the
  declared `Content-Length`, telling `Some(0)` from an absent field.
- `Method::is_safe`, `Method::is_idempotent`, `Method::index`, and
  `MethodSet`, a bit set of methods with `write_allow` for the `Allow` field
  of a `405`.
- `StatusClass`, `status_class`, and the `status` module: a named `u16`
  constant for every registered status code.
- `Response::from_error`: the response for a request parse error (status,
  short `text/plain` body, `close`); the blocking server uses it.
- `Request::head`, `Request::put`, `Request::delete`, `Request::options`.
- `docs/MIGRATION.md`, `dev/PLAN.md` (design and decision log), and
  `.editorconfig`.
- Tests: `tests/alloc.rs` (a counting allocator: 10,000 keep-alive requests
  on one `ServerConn`, and 10,000 responses on one `ClientConn`, allocate
  nothing after warm-up; 10 MiB hostile streams never grow a connection
  past its buffer capacity), `tests/prop_httparse.rs` (differential against
  `httparse` 1.10 on every head both accept, and a classified count of the
  heads only `httparse` accepts), `tests/conformance.rs` (RFC 9112 and RFC
  9110 statements as a table, one check each), `tests/redaction.rs`, and
  new attack vectors for chunk-extension line ends (the Funky Chunks
  classes), 0.CL and `Expect`-based desync, `h2c` and unoffered upgrades,
  and `Host` escapes. The `docs/API.md` and `docs/MIGRATION.md` examples
  run as doctests.
- Fuzzing: six cargo-fuzz targets in `fuzz/` (`server_conn`, `client_conn`,
  `chunk_line`, `reference_diff`, `httparse_diff`, `builders`), each run
  for 60 s in CI.
- CI: a `no_std` build for `thumbv7em-none-eabihf` and the fuzz smoke run.

### Changed

- `RequestHead::is_upgrade` is false for a request whose `Upgrade` offers
  only `h2c`; such a request is served as plain HTTP/1.1 (RFC 9113 section
  3.1).
- `ServerConn::respond` refuses a `101` naming a protocol the request did
  not offer with `UpgradeNotOffered` (RFC 9110 section 7.8). Names are
  compared ASCII case-insensitively, and a name without a version answers
  an offer of that name with any version.
- `Response::switching_protocols` and `Request::upgrade` accept a
  `name/version` product token and refuse `h2c` with `UpgradeNotOffered`.
- The client accepts a status line without the space after the code
  (`HTTP/1.1 200`); `reason()` is then empty.
- `reason_phrase` covers every code in the IANA registry: `102`, `103`,
  `207`, `208`, `226`, `305`, `402`, `407`, `423`, `424`, `425`, `451`,
  `506`, `507`, `508`, `510`, and `511` were added; `306` and `418` stay
  empty as reserved.
- `Method` and the status registry moved to their own modules; the public
  paths (`http_net::Method`, `http_net::reason_phrase`) are unchanged.
- `dev/ROADMAP.md` follows the library specification's version plan: fuzz
  targets moved from 0.9 to 0.3, the client `Expect`, interim responses,
  and blocking deadlines to 0.4, client pipelining to 0.5; the async
  adapter is withdrawn (no crate in this family takes an async runtime).

### Security

- `Debug` for `RequestHead`, `ResponseHead`, `Headers`, `HeaderValues`,
  `ServerEvent`, `ClientEvent`, `Request`, `Response`, and
  `blocking::ClientResponse` replaces the values of `authorization`,
  `proxy-authorization`, `cookie`, and `set-cookie` with
  `<redacted N bytes>`. In 0.2.0 a `{:?}` of a request printed session
  cookies and bearer tokens in full.
- `Host` values with an empty host before a port (`:80`) or a `%` not
  followed by two hex digits are refused (`InvalidHost`), as are such
  authorities in `CONNECT` and absolute-form targets (`InvalidTarget`).
- The `h2c` upgrade is never honoured (h2c smuggling), and a server cannot
  switch to a protocol the client did not offer.

---

## [0.2.0] - 2026-10-12

The foundation: a sans-IO HTTP/1.1 engine for servers and clients, strict
per RFC 9112, with request smuggling defences, bounded buffers, keep-alive,
chunked bodies both ways, the protocol-upgrade hand-off for WebSocket,
`Expect: 100-continue` on the server, and a small blocking adapter over
`std::net`. No dependencies.

### Added

- `ServerConn` and `ServerEvent`: the server-side state machine. Input in
  through `feed` or `read_buf` + `commit`, events out through `poll`
  (`Request`, `Body`, `RequestEnd`, `NeedInput`, `AwaitingResponse`,
  `Upgraded`, `Closed`), responses out through `respond`, `send_body`, and
  `end_body`. Keep-alive is automatic; pipelined requests are served in
  order. A request without a body may be answered at `Request` and stays
  keep-alive; one with unread body bytes is closed afterwards.
- `ServerConn::send_continue` and `RequestHead::expects_continue`: the
  `100 Continue` answer RFC 9110 section 10.1.1 requires before a server
  waits for an expected body (HTTP/1.1 requests with a body only; never to
  HTTP/1.0 clients).
- `ClientConn` and `ClientEvent`: the client-side state machine
  (`send_request`, streamed request bodies, response parsing framed by the
  request method, interim 1xx responses skipped, `Idle` when reusable).
- `RequestHead`, `ResponseHead`, and `Headers`: zero-copy views of parsed
  heads. For an absolute-form target, `RequestHead::host` is the target's
  authority and `path` / `query` are its path and query (RFC 9112 section
  3.2.2: the server ignores `Host` then).
- `Request` and `Response` builders that validate as they go and own no
  framing headers; `Response::switching_protocols` and `Request::upgrade`
  for protocol upgrades.
- `Method`, `Version`, `BodyFraming`, `reason_phrase`.
- `Limits`: request/status/chunk line (8 KiB), header section (16 KiB),
  field count (100), and body (1 MiB) budgets, each checked before the
  bytes it governs are buffered. The header budget also caps, per message,
  the total of chunk extensions and of interim 1xx heads.
- `HttpError` (`#[non_exhaustive]`): one variant per refusal, with
  `status()` giving the status code to answer with.
- `blocking` module (feature `std`): `Server` (bounded thread per
  connection, connection cap with 503, read/write timeouts, a per-request
  deadline answered with 408, automatic `100 Continue`, `date` header,
  lingering close bounded to 1 s, 500 for a streamed or invalid handler
  response, upgrade hook, `ShutdownHandle`), `ServerConfig` (including
  `with_request_timeout`, 30 s by default), `Connection` for custom accept
  loops and upgrades (`with_request_timeout`), `Client` and `get` for
  `http://` URLs.
- Tests: RFC 9112 accept/reject/response cases as data, a smuggling suite,
  an adversarial suite (target forms and the authority, `Expect`, chunk and
  trailer edges, cumulative budgets, integer edges), property tests (round
  trip including absolute-form targets and keep-alive, split invariance,
  no panics on arbitrary bytes from the first byte and behind valid heads),
  a differential test against an independent reference parser, a
  100,000-request scale test, and localhost socket tests (including
  slowloris heads and bodies, a refused client trickling data, lingering
  close, and `Expect: 100-continue`).
- Criterion benchmarks (`benches/bench.rs`) and examples (`localhost`,
  `sans_io`, `serve`, `get`).

### Security

- Refused outright, each with its own `HttpError`: `Content-Length` with
  `Transfer-Encoding`; a duplicate (even equal) or list-valued
  `Content-Length`, or one with a sign, space, or hex; any
  `Transfer-Encoding` other than a single final `chunked`, in requests and
  responses alike; a transfer coding other than `chunked` (501);
  `Transfer-Encoding` in HTTP/1.0; obsolete line folding; a bare CR
  anywhere in a head; a bare LF as a line end; whitespace before a colon;
  control bytes in field values and non-token field names; a missing,
  duplicate, or malformed `Host`; request targets outside RFC 3986, in a
  form the method does not allow, or in absolute form without
  `//authority`, with userinfo, or with an empty host; chunk sizes over 16
  hex digits, malformed chunk extensions, chunk data without its CRLF; and
  more than the header budget of chunk extensions in one message (the
  CVE-2024-22019 pattern). After a parse error the connection parses
  nothing further.
- Trailer fields are validated, counted, and discarded: framing fields in a
  trailer cannot reframe the message or the next one.
- A read-until-close response body is delivered up to `max_body` and
  refused at the first byte past it, so the events do not depend on how
  the input was split.
- The client refuses bytes that arrive after a complete response with no
  request outstanding (`UnexpectedData`) rather than treating them as the
  next response, and stops parsing interim 1xx responses once they exceed
  the header budget.
- Outgoing messages cannot contain CR/LF in fields or set framing headers.
- The blocking server cannot be pinned by slow peers: a request trickled
  inside the read timeout is cut off by the request deadline (408); a
  refused connection is answered without the accept thread ever waiting on
  the peer; lingering close stops after 1 s and 256 KiB.

---

## [0.1.0] - 2026-10-08

Initial scaffold and repository bootstrap. No domain logic yet; this release establishes the structure, tooling, and quality gates the implementation will be built on.

### Added

- `Cargo.toml` with crate metadata, Rust 2024 edition, MSRV 1.85.
- Dual `Apache-2.0 OR MIT` license files.
- `README.md`, `CHANGELOG.md`, and a documentation skeleton.
- `REPS.md` compliance baseline.
- `.github/workflows/ci.yml` CI matrix; `deny.toml`, `clippy.toml`, `rustfmt.toml`.
- `dev/DIRECTIVES.md` and `dev/ROADMAP.md` (committed engineering standards + plan).

[Unreleased]: https://github.com/jamesgober/http-net/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/jamesgober/http-net/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/jamesgober/http-net/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/jamesgober/http-net/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/jamesgober/http-net/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jamesgober/http-net/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jamesgober/http-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/http-net/releases/tag/v0.1.0
