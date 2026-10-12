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

Initial scaffold and repository bootstrap. No domain logic yet &mdash; this release establishes the structure, tooling, and quality gates the implementation will be built on.

### Added

- `Cargo.toml` with crate metadata, Rust 2024 edition, MSRV 1.85.
- Dual `Apache-2.0 OR MIT` license files.
- `README.md`, `CHANGELOG.md`, and a documentation skeleton.
- `REPS.md` compliance baseline.
- `.github/workflows/ci.yml` CI matrix; `deny.toml`, `clippy.toml`, `rustfmt.toml`.
- `dev/DIRECTIVES.md` and `dev/ROADMAP.md` (committed engineering standards + plan).

[Unreleased]: https://github.com/jamesgober/http-net/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jamesgober/http-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/http-net/releases/tag/v0.1.0
