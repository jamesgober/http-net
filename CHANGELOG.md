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

[Unreleased]: https://github.com/jamesgober/http-net/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/jamesgober/http-net/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jamesgober/http-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/http-net/releases/tag/v0.1.0
