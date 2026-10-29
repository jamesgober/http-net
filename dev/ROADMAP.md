# http-net - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Master plan: C:/Dev/libraries/Rust/lang-collection/_lexersketch/ROADMAP.md and NEW-LIBS.md
> Design and decision log: `dev/PLAN.md`. Approved public surface, with the version each item ships in: `docs/API.md`.
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.

## v0.1.0 - Scaffold (DONE, 2026-10-08)
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
- **None wired.** No first-party crate covered HTTP syntax at 0.2.0; the crate is
  dependency-free (runtime and build). `criterion` and `proptest` are
  dev-dependencies only. `parse-net` (shared field grammar) is wired in v0.4.0
  (decision OD-1 in `dev/PLAN.md`).
- **Fuzz targets (DIRECTIVES section 3 item 6):** 0.2.0 planned them for v0.9.0
  and relied on property tests in the meantime. They moved to v0.3.0 (see the
  moves table below).

Items 0.2.0 listed as remaining for v0.5.0 (interim 1xx other than 100 from the
server, client `Expect: 100-continue`, client pipelining, an async adapter) and
the old v0.5.0 / v0.9.0 entries were re-planned when the design lock was
revisited; where each one went is in the moves table below.

## Moves recorded when the design lock was revisited (2026-10-21)

0.2.0 delivered a working core but no approved design for the full 1.0
surface. The design lock was revisited at the start of v0.3.0: `docs/API.md`
was rewritten to the 1.0 surface and approved (decision D-1 in
`dev/PLAN.md`). Breaking changes the lock implies sit in v0.3.0 so later
versions are additive.

| Item | Old place | New place | Reason |
|---|---|---|---|
| Fuzz targets | v0.9.0 Hardening | targets in v0.3.0; 24 CPU-hour campaign in v0.7.0 | the standard requires a fuzz target for every parser, and the parsers already exist |
| `103` and other interim responses from the server | v0.5.0 | v0.4.0 | parity with hyper and h11; a small state addition |
| Client `Expect: 100-continue` | v0.5.0 | v0.4.0 | fetch-net needs it for large uploads |
| Client pipelining | v0.5.0 | v0.5.0 | needs a fixed-capacity queue of outstanding requests; no first consumer needs it earlier |
| Async adapter | v0.5.0 | **withdrawn** | no crate in the portfolio takes an async runtime; drivers (`serve-net`, `net-io`) call the sans-IO core directly (decision OD-11, and the REPS tokio exception D-3) |
| Blocking client total deadline | v0.5.0 | v0.4.0 | small; closes a slow-server hold |
| Blocking server total write deadline | v0.5.0 | v0.4.0 | closes the slow-reader threat (T-26) |
| Status line without a reason phrase (client) | v0.5.0 | v0.3.0 | interop; breaking only in the accepting direction |
| `Host` percent escapes and an empty host with a port | v0.5.0 | v0.3.0 | security tightening belongs with the design lock |
| Conformance tests | v0.9.0 | table started in v0.3.0; HTTP Garden in v0.7.0 | earlier evidence |

## v0.3.0 - Core (design lock revisited) (DONE, 2026-10-21)
- [x] `docs/API.md` rewritten from the specification and approved before the first 0.3 code commit (recorded in `dev/PLAN.md`, D-1).
- [x] `dev/PLAN.md` created (decision log seeded with the open-decision outcomes); this roadmap rewritten; `.editorconfig`; em dash cleanup in public files (the literal character and its HTML entity); `docs/MIGRATION.md`.
- [x] Credential redaction in every `Debug` (`authorization`, `proxy-authorization`, `cookie`, `set-cookie`): `RequestHead`, `ResponseHead`, `Headers`, `Request`, `Response`, `blocking::ClientResponse`.
- [x] `pub const VERSION`.
- [x] `HttpError::UpgradeNotOffered`, `is_peer_error`, `is_usage_error`.
- [x] `Limits::buffer_capacity`.
- [x] `RequestHead::target_form` and `TargetForm`; `header_all` and `HeaderValues` on both views; `content_length` on both views.
- [x] `h2c` ignored as an upgrade offer and refused in `Response::switching_protocols` / `Request::upgrade`; a `101` must name an offered protocol.
- [x] `Method::is_safe`, `is_idempotent`, `index`; `MethodSet`.
- [x] Complete status registry in `reason_phrase`; `StatusClass`, `status_class`; the `status` constants.
- [x] `Response::from_error`; `Request::head`, `put`, `delete`, `options`.
- [x] `Host` and authority tightening (`:80`, bad `%XX`); client accepts `HTTP/1.1 200` without the space after the code.
- [x] Six cargo-fuzz targets (`server_conn`, `client_conn`, `chunk_line`, `reference_diff`, `httparse_diff`, `builders`) with a 60 s CI smoke run each.
- [x] `tests/prop_httparse.rs` (differential against httparse); `tests/alloc.rs` (counting allocator); `tests/conformance.rs` table started.
- [x] `no_std` CI job building for `thumbv7em-none-eabihf`.
- [x] Named Funky Chunks (TERM.EXT, EXT.TERM), 0.CL, Expect-based, and h2c attack vectors; compile-time `Send + Sync` test extended to every public type.

Exit criteria:
- [x] `docs/API.md` approved before the first 0.3 code commit (recorded in `dev/PLAN.md`).
- [x] Every listed item implemented, documented with a runnable example, and tested (`Ok` and `Err` paths).
- [x] Counting-allocator test: 10,000 keep-alive requests on one `ServerConn` after warm-up allocate 0 bytes in the core.
- [x] Fuzz targets run 60 s each in CI with no finding; httparse differential green.
- [x] `thumbv7em-none-eabihf` build green.
- [x] Benchmarks within 5% of the 0.2.0 baseline (interleaved A/B on one machine: largest consistent difference about +2%, head and pipelined benchmarks).
- [x] Local gate and CI green; release routine completed.

## v0.4.0 - Extended (DONE, 2026-10-21)
- [x] Budgets: per-field-line limit (`FieldLineTooLong`), separate trailer budgets, interim response count (`TooManyInterim`).
- [x] `ServerConn`: `set_keep_alive`, `keep_alive`, `requests_served`, `progress` (`Progress`), `respond_with_date`, `send_informational` (103 Early Hints), `end_body_with_trailers`, `set_report_trailers` (`ServerEvent::Trailers`); `send_continue` reports `InterimNotAllowed`.
- [x] Views: `header_list` and `ListElements`; `has_unknown_expectation`; `upgrade_protocols`; `ResponseHead::is_informational`; `status_allows_body`.
- [x] `HttpDate`, `DateCache`, `blocking::now_date` (the formatter moves out of `blocking`; the core takes the time from the caller).
- [x] `ClientConn`: `Request::expect_continue` and `is_waiting_for_continue` (`ClientEvent::Continue`), `set_report_informational` (`ClientEvent::Informational`), `set_report_trailers`, `end_body_with_trailers`, `is_reusable`, `progress`.
- [x] Error variants `FieldLineTooLong`, `TooManyInterim`, `InterimNotAllowed`, `TrailerNotAllowed`; `ReservedHeader` list extended.
- [x] Blocking: total response-write deadline and request cap in `ServerConfig`, automatic 417 and cached `date` in `Server`, `Connection::send_informational`, `Client::request` and `with_deadline`, `blocking::post`, `blocking::serve`.
- [x] `parse-net` wired for the shared grammar (OD-1) if its approved version is published; otherwise the move waits and this file records why. **Moved:** `parse-net` is not published, so the grammar stays internal behind the API shape `parse-net` specifies (the quote-aware list walker and the IMF-fixdate formatter); the switch happens in the first version after `parse-net` publishes an approved release (dev/PLAN.md D-13).

Exit criteria:
- [x] Trailers and interim responses round-trip in property tests, both directions.
- [x] Client `Expect` flows tested: `100` first, final status first, caller sends without waiting.
- [x] Blocking: response deadline socket test (slow reader) and 417 test green; `Client::request` and deadline tests green.
- [x] `parse-net` equality tests green and `request_head` within 1% of the pre-move baseline, or the move deferred with the reason recorded. (Deferred: D-13.)
- [x] Benchmarks within 5% of 0.3.0.
- [x] Release routine completed.

## v0.5.0 - Feature complete (DONE, 2026-10-21)
- [x] Client pipelining (`Limits::pipeline_depth`, `outstanding`, `can_send`).
- [x] Connection reuse: `reset`, `with_buffer`, `into_buffer`, `shrink_idle`; optional wipe of consumed input (`set_wipe`).
- [x] Tier 3: spans and raw heads (`Span`, `FieldSpan`, `RawHead`), `copy_into` and `HeadFacts` (passport copy-out, OD-12), `OwnedRequestHead`; stateless `parse_request_head` / `parse_response_head`; `ChunkedDecoder`; the `Output` trait, `ResponseHeadRef`, `write_head`, `respond_into`; `Response::clear`; `Request::forward_from` and `is_hop_by_hop`; `connection_options`; `is_h2_preface` and `Http2Preface`.
- [x] Opt-in client leniency for response obs-fold (`ClientLeniency`, in-place replacement).
- [x] Documentation: `docs/ARCHITECTURE.md`, `docs/SECURITY.md` draft; examples `passport`, `proxy_forward`, `pipelined_client`, `trailers`, `early_hints`.

Exit criteria:
- [x] Every functional requirement of the specification implemented and tested.
- [x] Counting allocator: Tier 3 parse and write paths allocate 0 bytes ever.
- [x] Stateless parser and `ChunkedDecoder` proven equal to the connection paths by property tests and fuzz targets.
- [x] `OwnedRequestHead::from_parts` refuses every tampered-span case in its unit tests.
- [x] Release routine completed.

## v0.6.0 - Optimisation (DONE, 2026-10-22)
- [x] `ServerConn::respond_head_only` (head-only write for vectored sends).
- [x] The hot-spot plan, each item measured: a precomputed status-line table and one-pass fast paths for the common field and chunk lines kept; 16-byte SWAR steps, the combined whole-line pass, and length-first matching measured slower and dropped (`dev/PLAN.md` D-45 to D-53); the `Date` cache shipped in 0.4.
- [x] Comparison repository [`http-net-bench`](https://github.com/jamesgober/http-net-bench) (H1 to H5 against httparse and hyper in memory; picohttpparser, llhttp, and H6 not run yet); `docs/PERFORMANCE.md`.

Exit criteria:
- [x] Performance targets met on Linux x86_64, or the SIMD decision (OD-8) taken with the measured gap: SWAR kept, at parity with httparse (D-54).
- [x] At least 20% faster than the best Rust competitor on the head-parse and full-exchange workloads at equal or stronger security, published; or the shortfall and its cause published with a recorded decision: met on full exchanges, head parsing at parity, published (D-54).
- [x] Byte-at-a-time linearity guard green.
- [x] Criterion baselines saved; the 5% regression gate documented and used for every later change (`scripts/bench_ab.sh`, `docs/PERFORMANCE.md`).

## v0.7.0 - Hardening (DONE, 2026-10-26)
- [x] Fuzz campaign: 24 CPU-hours per target, corpus stored outside the repository (no finding; `docs/SECURITY.md`).
- [x] Every threat in the specification has its attack test (audit: one defence gap fixed, T-21). HTTP Garden runs moved to a manual CI job (D-58): the development machine has no Docker.
- [x] 8-hour soak of the blocking server (191.7 M exchanges, +3.4% memory after warm-up).
- [x] `docs/SECURITY.md` and `docs/PLATFORM-NOTES.md` complete.

Exit criteria:
- [x] No open fuzz or Garden finding (Garden not run, D-58); every threat test green; soak RSS growth under 5% (3.4%); one new defence idea evaluated and recorded in `dev/PLAN.md` (the response-side httparse differential: held).

## v0.8.0 - Alpha (DONE, 2026-10-26, two of three consumers)
- [x] Integration with first consumers: the `serve-net` engine adapter and LexerSketch Studio run green against 0.8 with no change; the WASP `gateway-io` skeleton and the first `fetch-net` do not exist yet (D-62). No API change came from their feedback.
- [x] The shared grammar comes from `parse-net` 0.7 (D-59 to D-61; supersedes D-13).

Exit criteria:
- [ ] Three consumers run end to end against 0.8: two do (serve-net, LexerSketch Studio); the third waits for `gateway-io` or `fetch-net` (D-62).
- [x] Every P0 and P1 gap they report closed (none reported).
- [x] Benchmarks within 5% of 0.6 (D-61).

## v0.9.0 - Beta and release candidates (0.9.0 2026-10-29; 0.9.x until the exit criteria hold)
- [x] API frozen as the 1.0 candidate; `0.9.x` releases contain fixes only (D-63; `cargo semver-checks` against the previous release from 0.9.1 on).
- [x] Every unverified cell of the parity matrix resolved: `docs/PARITY.md`, evidence in `dev/PARITY-EVIDENCE.md` (D-67).
- [x] `docs/STABILITY-1.0.md` drafted.
- [x] Every rustdoc example and README claim re-checked against the build: four code defects found and fixed, the documentation corrected (D-69).
- [x] HTTP Garden as a manually triggered CI job (D-68); the first run (after the 0.9.0 merge, 679 cases) found no defect (D-70).
- [x] The 0.8 and 0.9 defence ideas evaluated (both rejected, D-64, D-65).

### 0.9.x polish pass (0.9.1, 2026-10-29)

Before 1.0, every accepted gap, deferred item, known issue, and missed
target was revisited, performance measured again, and the security review
repeated. Fixes ship as 0.9.x patches; what stays open is in
`docs/STABILITY-1.0.md` ("Open before 1.0").

- [x] Security and edge-case review repeated by an independent reviewer on the frozen code: no smuggling, desync, panic, or memory defect; three defects fixed in 0.9.1 (an error answer to `HEAD` with content, pipelining after a response that closes, body bytes in `Debug`) and `serve` now waits for live connections on persistent accept errors (D-73, `docs/SECURITY.md` review record).
- [x] Fuzzing repeated on the 0.9.1 code: each of the eight targets for 15 minutes on Linux x86_64 with AddressSanitizer, seeded with the 0.7 corpora (63 million executions in all). The crate had no finding. The `reference_diff` target stopped once inside its own oracle: the independent reference parser in `tests/common/reference.rs` added a chunk size of sixteen `f` digits to the body so far and overflowed, where the crate refuses the size as over the body budget. The oracle now subtracts instead (regression test in `tests/prop_reference.rs`), and the target ran its 15 minutes clean (D-74).
- [x] HTTP Garden run again on the 0.9.1 branch: the same 679 cases and the same 156 differences as the first run, no case changed, no quirk (D-70).
- [x] Performance against every release since 0.6.0: no regression (interleaved, nine rounds); the unmet write targets decomposed (about 62 ns of the response-write benches is reading the request; `write_head` costs about 12 ns per borrowed field); two write-path ideas measured level and dropped (D-72).
- [x] Competitors measured again on 0.9.0 (`http-net-bench`): the 0.6 ratios hold (D-72); aarch64 benchmark workflow added.
- [x] Deferred and estimated items revisited: the 0.5 wipe idea measured (+2.1%, D-72 and the defence-ideas log); the T-40 caps told apart by a test; the T-36 cost measured; the module layout settled (D-71); `PLAN.md` buffer bound corrected.
- [ ] Still open (not code, or not this repository): the third consumer (D-62); H6, picohttpparser, and llhttp in `http-net-bench`; a quiet-machine H1 run; the support window and report channel (James).

Exit criteria:
- [ ] Two consecutive weeks without an API change, counted from 0.9.0 (D-66).
- [x] Full documentation set present (`docs/ARCHITECTURE.md`, `docs/PERFORMANCE.md`, `docs/SECURITY.md`, `docs/PLATFORM-NOTES.md`, `docs/STABILITY-1.0.md`, plus `docs/PARITY.md`).
- [ ] Full local gate and CI green on all platforms and MSRV (each 0.9.x release).

## v1.0.0 - Stable
- [ ] The full audit (API, docs, tests, benchmarks, security) recorded in `docs/STABILITY-1.0.md`.
- [ ] Frozen after LexerSketch Studio and ls-publish use it end to end (DIRECTIVES item 9, decision D18).

Exit criteria:
- [ ] API frozen until 2.0; an MSRV raise after 1.0 is a major change.
