# http-net - Security

> The threat model, every threat with its defence, its test, and its cost,
> where http-net is deliberately stricter than the RFCs, and the 0.7
> hardening record (fuzz campaign, soak, threat audit). Every threat T-1 to
> T-42 has an attack test.

## Threat model

**Assets:** correct message boundaries (every hop agrees where each request
and response starts and ends); the server's memory and threads; the
credentials passing through the buffers; the integrity of what is written
(no injected fields or responses).

**Attackers:** any network peer (client to server, server to client); a
peer behind a lenient front end (proxy, CDN, load balancer) that frames
messages differently; an application that misuses the API (invalid fields,
calls in the wrong order).

**Trust boundary:** every byte given to `feed` or `commit` is hostile.
Values given to the builders are trusted to mean what the caller wants but
are validated so they cannot break the framing.

## Threats, defences, tests, costs

Costs are per request unless stated; estimates are marked. "Status" says
whether the attack test exists in this build.

| Id | Threat | Defence | Test | Cost | Status |
|---|---|---|---|---|---|
| T-1 | CL.TE smuggling | `Content-Length` with `Transfer-Encoding` refused (`ConflictingFraming`); nothing parsed after | `tests/smuggling.rs`, every split | one flag check, under 1 ns [est.] | tested |
| T-2 | TE.CL smuggling | as T-1 | `tests/smuggling.rs` | as T-1 | tested |
| T-3 | TE.TE obfuscation (`xchunked`, `chunked, identity`, a second TE, space before colon, VT/FF, NUL, CR, folding) | one final parameterless `chunked` across all TE fields; whitespace-before-colon, control-byte, obs-fold, and bare-CR refusals | ten vectors in `tests/smuggling.rs`; TE split across two fields (`chunked` twice, `gzip` then `chunked`) at every split; `tests/rfc_cases.rs` | part of field validation | tested |
| T-4 | duplicate or list `Content-Length` | any second CL refused; only `1*DIGIT` fitting `u64` | `tests/smuggling.rs` (duplicates, lists, hexadecimal); `tests/rfc_cases.rs` (signs, inner space, empty); `tests/adversarial.rs` (`-0`, overflow) | none beyond parsing | tested |
| T-5 | bare LF line ends | LF must follow CR in every head and chunk line | `tests/smuggling.rs`, `tests/rfc_cases.rs` | one compare per line | tested |
| T-6 | bare CR | refused anywhere in a head and in outgoing values | `tests/smuggling.rs`, `message.rs` units | part of the SWAR value check | tested |
| T-7 | obs-fold hiding a field from one hop | refused in requests always; in responses unless the client opts into in-place replacement | `tests/smuggling.rs`; the leniency on/off pairs in `tests/forwarding.rs`; `tests/rfc_cases.rs` (trailers) | none | tested |
| T-8 | whitespace before colon | refused (RFC 9112 section 5.1) | `tests/smuggling.rs` | none | tested |
| T-9 | chunk-extension line-end confusion (Funky Chunks TERM.EXT, EXT.TERM; Netty CVE-2025-58056 and CVE-2026-33870, Jetty CVE-2026-2332, ASP.NET Core CVE-2025-55315) | chunk lines end only at CRLF; a lone LF is `BareLf`; a CR in an extension or quoted string fails the grammar | seven named vectors in `tests/smuggling.rs`, every split | none | tested |
| T-10 | oversized chunk sizes wrapping | at most 16 hex digits, checked arithmetic, running total checked against `max_body` before data | `tests/smuggling.rs`, `tests/adversarial.rs` | a few instructions per chunk | tested |
| T-11 | chunk-extension flood (CVE-2024-22019) | per-message extension budget = `max_header_bytes`; one chunk line at most `max_start_line` | `tests/adversarial.rs` (budget across the message; one line over the budget at every split; exactly the budget accepted, one more refused); `tests/alloc.rs` (10 MiB of extensions, 10 MiB of one chunk line) | one add per chunk | tested |
| T-12 | chunk data longer than declared | CRLF required right after the data | `tests/smuggling.rs`, `tests/adversarial.rs`, `tests/rfc_cases.rs` | none | tested |
| T-13 | trailer fields reframing a message | trailers validated and never merged; framing from the header section only; forbidden outgoing trailer fields refused | `tests/adversarial.rs`, `tests/trailers.rs` (server, and a client pipelining two responses whose first trailer section carries `Content-Length`) | none | tested |
| T-14 | 0.CL desync | `Content-Length` honoured on every method; answering before reading the body closes | `tests/adversarial.rs` | none | tested |
| T-15 | `Expect`-based desync | `Expect` never changes framing; `100-continue` matched as a trimmed, case-insensitive list element | eight vectors in `tests/adversarial.rs` | none | tested |
| T-16 | smuggling a pipelined request after an error | nothing parsed after a parse error | `tests/smuggling.rs`; `tests/conformance.rs` | none | tested |
| T-17 | response queue poisoning on the client | `UnexpectedData` for bytes with no request outstanding; until-close responses never reused; no request pipelined behind a response that ends the connection (0.9.1) | `client.rs` units, `tests/adversarial.rs`, `tests/connection_control.rs`, `tests/pipelining_reuse.rs` | none | tested |
| T-18 | `Host` attacks (two Hosts, junk, `:80`, bad `%XX`) | one valid `Host`; the absolute-form authority wins | `tests/adversarial.rs` | O(Host length) | tested |
| T-19 | absolute-form tricks (userinfo, empty host, no `//`) | refused | `tests/adversarial.rs` | O(target) | tested |
| T-20 | h2c smuggling | `h2c` is never an upgrade offer; `switching_protocols("h2c")` refused | `tests/adversarial.rs` | none | tested |
| T-21 | upgrade smuggling | the client switches only on a 101 to a request with `Upgrade`, and only when every protocol the 101 names is one the request offered (0.7); the server switches only to an offered protocol, and only once the request is complete | `client.rs` units (offered, case and version variants, `h2c`, extra or missing protocols); `tests/adversarial.rs` (a non-101 answer stays HTTP; a 101 with no protocol; a server 101 before the body is read); `tests/conformance.rs` | one list walk per 101 | tested |
| T-22 | response splitting / CRLF injection through builders | token names; no CR, LF, controls, or surrounding whitespace in values; method and target checked; static reason phrases | `tests/smuggling.rs` (exact error for each case; CR, LF, and space in targets and methods; NUL, VT, edge whitespace, and bare LF in values; nothing written), `message.rs` units | O(value) per field | tested |
| T-23 | caller-set framing fields | framing and hop-by-hop fields reserved (`ReservedHeader`) | `message.rs` units, `tests/connection_control.rs`, `tests/smuggling.rs` (request side, every case spelling, nothing written) | O(1) per field | tested |
| T-24 | slowloris head | sans-IO: `progress()` lets drivers run a header deadline; blocking: per-request deadline answered 408 | `tests/localhost.rs` | one `Instant` per request in the adapter | tested |
| T-25 | slow body | as T-24 | `tests/localhost.rs` (answered `408`, closed within the deadline) | as T-24 | tested |
| T-26 | slow reader of a large response | blocking: total response deadline (60 s by default) | `tests/localhost.rs` | one `Instant` per write | tested |
| T-27 | memory exhaustion by huge heads or bodies | every budget checked before buffering; CL above `max_body` refused on the header line | boundary tests; seven 10 MiB hostile streams in `tests/alloc.rs` | none | tested |
| T-28 | many idle connections | `shrink_idle`; the blocking server's connection cap with 503 | `tests/pipelining_reuse.rs`, `tests/localhost.rs` | one free | tested |
| T-29 | pipelining flood | pipelined input stays in the bounded buffer; parsing stops until the response is written; request caps | a 100,000-request stream in `tests/prop_roundtrip.rs`; 100,000 requests offered without an answer stay within `buffer_capacity()` (`tests/adversarial.rs`) | none | tested |
| T-30 | header count or byte flood | `max_headers`, `max_header_bytes`, the 8 KiB per-line budget | boundary tests | a counter per field | tested |
| T-31 | interim response flood | interim heads budgeted by count (`max_interim`) and bytes | `tests/adversarial.rs`, `tests/interim.rs` | a counter per interim | tested |
| T-32 | quadratic parsing on byte-at-a-time input | resumable scanner; compaction only when full | a 16 KiB head fed one byte at a time (`tests/prop_roundtrip.rs`); the linearity guard (`tests/linearity.rs`: 8 times the bytes cost under 16 times the time) and its bench group | none | tested |
| T-33 | integer overflow | checked arithmetic for CL, chunk sizes, running totals | `tests/adversarial.rs`; fuzzing | none | tested |
| T-34 | panics | clippy denies (`unwrap`, `expect`, `unreachable!`, printing), bounded indexing, fuzzing | never-panic property tests; eight fuzz targets in CI; the 0.7 campaign (24 CPU-hours per target, no finding) | none | tested |
| T-35 | credentials in logs | `Debug` redacts `authorization`, `proxy-authorization`, `cookie`, `set-cookie` everywhere; body and tunnel bytes print as lengths | `tests/redaction.rs` (every view, owned and copied heads, the stateless parsers, `ResponseHeadRef`, `blocking::Connection`, whose buffers print as lengths only, and since 0.9.1 the body events, `blocking::Incoming`, and the leftover bytes of `blocking::Upgraded`) | only when formatting | tested |
| T-36 | credentials left in reused memory | `set_wipe`: zero finished requests, compaction leftovers, and the buffer on reset, release, drop | `tests/pipelining_reuse.rs` (finished requests, compaction, release, and reset mid-body, each with a control run); the wipe on drop is not tested, since observing it would mean reading the freed block | +5 ns (+2.1%) on the 453-byte browser GET, about 11 ns per KiB (0.9.1, `wipe` bench) | tested |
| T-37 | error text reflecting attacker bytes | `Display` is static text; `from_error` uses only it | `error.rs` units over every variant; `tests/adversarial.rs` (`from_error` for every variant; refused bytes never in the answer) | none | tested |
| T-38 | HTTP/0.9 messages | a version is required in both start lines | `tests/rfc_cases.rs` (request and response, whole and byte by byte) | none | tested |
| T-39 | status out of range | refused (`InvalidStatus`) | `tests/rfc_cases.rs` | none | tested |
| T-40 | lingering-close abuse | drain bounded to 1 s and 256 KiB; the refusal path never waits | `tests/localhost.rs` (a peer that trickles; a peer that writes 8 MiB unpaced; the only slot freed for the next client); since 0.9.1 a `blocking.rs` unit test shows the byte cap ends the drain of a peer that never stops (at most 256 KiB plus one read, well inside the 1 s cap) | at most 1 s of a thread per close | tested |
| T-41 | busy accept loop on persistent errors | 10 ms back-off after every failed accept; give up after more than 1,000 in a row; a success resets the count | `blocking.rs` unit test of the back-off policy the accept loop uses | none | tested |
| T-42 | prior-knowledge HTTP/2 to an HTTP/1.1 listener | 505 and close (`Http2Preface` in 0.5) | `tests/rfc_cases.rs` | 24 compares at connection start | tested |

## Hardening record (0.7)

**Threat audit.** Every row above was checked against the specification's
section 10 and the test code: the cited tests exist and attack what the
threat describes, and every vector the specification names has a test. The
audit found one defence gap, fixed in 0.7: the client switched protocols
on any `101` with a non-empty `Upgrade`, even to a protocol it had not
offered (T-21). It added 18 attack tests and tightened two.

**Fuzz campaign.** Every target ran 24 CPU-hours (one libFuzzer process
for 86,400 s each, AddressSanitizer, the dictionary in `fuzz/http.dict`),
on Windows x86_64 with the MSVC sanitizer runtime, at commit `d66f842`
(the 0.7 client fix included). No crash, no sanitizer report, no oracle
failure:

| Target | Executions | Coverage (edges) | Corpus |
|---|---:|---:|---:|
| `server_conn` | 87,910,971 | 839 | 4,901 |
| `client_conn` | 50,230,076 | 1,071 | 3,722 |
| `chunk_line` | 17,185,304 | 967 | 1,758 |
| `reference_diff` | 42,989,379 | 2,508 | 8,008 |
| `httparse_diff` | 80,202,799 | 1,447 | 11,811 |
| `builders` | 46,163,010 | 2,138 | 5,658 |
| `stateless_parse` | 98,232,701 | 1,056 | 3,999 |
| `chunked_decoder` | 35,292,073 | 2,174 | 4,736 |

libFuzzer flagged three inputs as slow (10 to 17 s each, once). Re-run
alone they take 92 ms (a 4-byte chunk line declaring a 64 KiB body, which
the target then feeds one byte at a time) and 16 ms; the machine was
shared with other builds at the time, so these are scheduling stalls, not
slow paths. The corpora are kept outside the repository.

**Soak.** `examples/soak.rs` ran the blocking server for 8 hours on
Windows x86_64 with four client threads (keep-alive runs with chunked
uploads and 96 KiB vectored bodies, pipelined bursts, one-shot requests,
malformed requests): 191.7 million exchanges and 467,445 malformed
requests answered `400` and closed. Memory, sampled every minute from
outside the process, rose during the first 12 minutes of warm-up (per-
connection threads and allocator caches) and then stayed flat: private
bytes 48.6 MB at one hour, 50.2 MB at eight hours (+3.4%, under the 5%
bound), working set 52 to 54 MB. Five client-side failures: three were
`connect` refused by Windows with "address in use" (port reuse under
TIME_WAIT, see `docs/PLATFORM-NOTES.md`); two came from the
malformed-request check, which records no message; none was a server
error. Other builds shared the machine during the run.

**HTTP Garden.** Run as a manually triggered CI job
(`.github/workflows/garden.yml`, [`dev/PLAN.md`](https://github.com/jamesgober/http-net/blob/main/dev/PLAN.md) D-68, D-70). The first
run, on 2026-10-29 at Garden `b417e80`, compared http-net with hyper,
nginx, h2o, and gunicorn: 133 seeds sent directly, 47 forwarded through
haproxy, and 499 seeded mutations. The Garden's quirk probe recorded no
quirk for http-net. In 156 cases http-net's result differs from at least
one other server's; none is a defect:

- **102 refusals** where another server accepts. Each is a choice in the
  table below or a rule of the grammar: bare LF, `Content-Length` with
  `Transfer-Encoding`, duplicate lengths (equal ones included), a
  repeated `chunked`, a coding before `chunked` (501), a space after a
  chunk size, a chunk size over 16 digits, extra spaces in the request
  line, control bytes and obs-text in the target or a field name,
  `*` with a method other than `OPTIONS`, an authority-form target with a
  method other than `CONNECT`, and two `Host` fields or an invalid one.
  `Connection: close, keep-alive` ends the connection after the first
  request (`close` wins), where gunicorn and h2o read on.
- **50 acceptances** where another server refuses, each one the RFCs
  allow and, apart from `HTTP/1.2`, hyper also accepts: empty lines before the
  request line (RFC 9112 section 2.2), a lowercase or unregistered method
  (methods are case-sensitive tokens), a tab around a field value, a
  trailer section (a trailer never frames the message and is never
  merged into the head), `OPTIONS *`, `Transfer-Encoding: ,chunked` (an
  empty list element is skipped, RFC 9110 section 5.6.1.2; with a
  `Content-Length` it is refused), `HTTP/1.2` (read as 1.1, RFC 9110
  section 2.5; hyper refuses it), an empty `Host` (a valid empty
  reg-name; `RequestHead::host` returns `Some("")`), an unknown `Expect`
  (passed to the application; gunicorn answers 417, which the RFC permits
  but does not require), and a second HTTP/1.0 request after
  `Connection: keep-alive` (nginx closes instead). Five of the 50 are
  `Expect: 100-continue` with the body already sent: the other servers
  answer `100 Continue` first, the Garden origin does not because the
  body has arrived (RFC 9110 section 10.1.1). That is the driver's
  choice, not the parser's.
- **4 cases where every server accepts and the echo differs**: an
  absolute-form target is reported as received (`RequestHead::host`
  returns its authority, T-18), where nginx and h2o rewrite it to origin
  form; the others are fields nginx or h2o leave out of their echo.

The run also showed the harness's limits. A `CONNECT` answered with a
tunnel cannot be read back by the Garden (the same for hyper), and the
first dispatch stopped inside the Garden's own mutator, before any
server saw the input, on a mutant whose chunk length overflowed its
regular expression; the driver now skips such mutants and reports how
many (one in the run above).

## Review record (0.9.1)

A second, independent review of the frozen 0.9.0 code (every source file,
against this threat table, `dev/PLAN.md`, and `docs/STABILITY-1.0.md`)
found nothing that enables smuggling, desync, a panic, or unbounded memory.
It checked every budget at its limit and one over at every two-piece split
and byte by byte, every budget at its minimum and maximum `Limits`,
the `u32` offsets and the `u64` totals at their extremes, the state
invariants I-S1 to I-S5, client framing of `HEAD`, 204, 304, 1xx, and
`CONNECT`, outgoing injection through every builder, redaction in every
`Debug`, and the bounds of the blocking adapter, and added five
split-invariance properties for paths without one (200,000 cases each,
all green). It found three defects, fixed in 0.9.1 with regression tests:

- An error answer to a `HEAD` that failed in its body (a bad chunk, EOF
  mid-body) was written as a `GET` answer, with the error text as content
  (RFC 9110 section 9.3.2); so was the blocking adapter's `408`. The
  answer always closed the connection, so only a front end that ignores
  `connection: close` could read the text as a response.
- The pipelining client kept sending after the response being read said
  the connection ends with it (RFC 9112 section 9.6). The extra request
  was never answered and was counted in `outstanding()`, so there was no
  desync.
- `Debug` printed body and tunnel bytes in four places (T-35 above).

It also found that `blocking::Server::serve` returned on persistent
accept errors without waiting for live connections, as it does on
shutdown; it now waits. Kept as they are, with the reason
(`dev/PLAN.md` D-73): `forward_from` drops every name `Connection` lists,
end-to-end ones included (RFC 9110 section 7.6.1 requires it; now
documented for proxy authors, and a dropped `host` fails closed); the
request builder may write `connection` twice (a legal list); a `205` may
carry content the caller gives it (framing stays explicit, and
`status_allows_body` describes framing, which RFC 9112 section 6.3 gives a
205); `commit(n)` clamps an over-long `n` (now documented); a lowercase
`head` is not `HEAD` (methods are case-sensitive).

## Where http-net is stricter than the RFCs

| Choice | The RFC permits | http-net | Why | Cost |
|---|---|---|---|---|
| bare LF | accepting it as a line end | refused | one line end for every hop | some broken scripts get 400 |
| bare CR | refusing or replacing | refused | replacing changes bytes other hops see differently | none known |
| obs-fold in requests | refusing or replacing | refused | replacement is a desync vector | none known |
| obs-fold in responses | user agents replace it | refused unless opted in | a client in front of a cache must not reinterpret silently | rare legacy servers fail by default |
| CL with TE | rejecting, or TE and close | refused | classic CL.TE / TE.CL | none |
| identical CL list | accepting | refused | no hop can pick another value | none known |
| chunk size over 16 hex digits | must parse | refused | keeps the overflow check exact | none legitimate |
| space after a chunk size without an extension | not in the grammar | refused | other parsers accept it only with a lenient flag | none |
| response `Transfer-Encoding` not ending in `chunked` | read the body until the connection closes | refused | a coding other than `chunked` is not supported, and guessing the body's end invites a desync | a server that sends one gets no response through |

One choice goes the other way: the client accepts a status line without
the space after the code (`HTTP/1.1 200`), which senders must send. It is
harmless to framing, and real servers omit it.

## Where http-net is stricter than httparse

A differential test (`tests/prop_httparse.rs`) compares http-net with
httparse 1.10 (strict configuration) on every single-byte mutation of the
seed requests. On every head both accept they agree on the length, method,
target, version, and fields. Where only httparse accepts, http-net refused
for one of these reasons (counts from the 0.3 run):

| Refusal | Count |
|---|---:|
| `InvalidHost` | 2,068 |
| `InvalidTarget` | 1,719 |
| `BareLf` | 679 |
| `MissingHost` | 656 |
| `InvalidTransferEncoding` | 387 |
| `InvalidContentLength` | 202 |
| `TransferEncodingInHttp10` | 1 |

The one case where http-net accepts and httparse refuses is HTTP/1.2 to
1.9, which RFC 9110 section 2.5 says to process as 1.1.

Responses get the same comparison since 0.7 (`tests/prop_httparse_response.rs`,
twelve seed responses, 47,249 single-byte mutations plus three 8,192-case
property tests): on every response head both accept, they agree on the
length, status, version, reason, and fields. Of the single-byte mutations,
21,003 were accepted identically by both, 24,230 refused by both, and 24
accepted only by http-net (HTTP/1.2 to 1.9). Where only httparse accepted,
http-net refused with:

| Refusal | Count |
|---|---:|
| `BareLf` | 989 |
| `InvalidContentLength` | 540 |
| `InvalidTransferEncoding` | 438 |
| `InvalidStatus` (a code outside 100 to 599, which httparse accepts) | 24 |
| `TransferEncodingInHttp10` | 1 |

The comparison covers heads, not body framing: httparse does no framing, so
a disagreement on where a body ends is covered by the framing tests above,
not by this differential.

## Costs of the security measures

| Measure | Latency | Memory |
|---|---|---|
| strict line and field validation (SWAR) | included in the head-parse benchmark; there is no switch to turn it off | none |
| framing facts and refusals | under 5 ns per request [est.] | none |
| budgets checked before buffering | a compare per line and per chunk | bounded by configuration |
| redaction | only when `Debug` runs | none |
| wiping (opt-in) | +5 ns (+2.1%) on the 453-byte browser GET, about 11 ns per KiB (measured 0.9.1) | none |
| blocking deadlines | one `Instant::now` per request and per write, about 20 to 30 ns each [est.] | none |
