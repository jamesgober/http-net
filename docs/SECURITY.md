# http-net - Security

> **Draft (0.5).** The threat model, every threat with its defence, its
> test, and its cost, and where http-net is deliberately stricter than the
> RFCs. Completed at 0.7 with the 24-hour fuzz campaign, the HTTP Garden
> runs, and the soak test.

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
| T-3 | TE.TE obfuscation (`xchunked`, `chunked, identity`, a second TE, space before colon, VT/FF, NUL, CR, folding) | one final parameterless `chunked` across all TE fields; whitespace-before-colon, control-byte, obs-fold, and bare-CR refusals | ten vectors in `tests/smuggling.rs` | part of field validation | tested |
| T-4 | duplicate or list `Content-Length` | any second CL refused; only `1*DIGIT` fitting `u64` | `tests/smuggling.rs`, `tests/adversarial.rs` | none beyond parsing | tested |
| T-5 | bare LF line ends | LF must follow CR in every head and chunk line | `tests/smuggling.rs`, `tests/rfc_cases.rs` | one compare per line | tested |
| T-6 | bare CR | refused anywhere in a head and in outgoing values | `tests/smuggling.rs`, `message.rs` units | part of the SWAR value check | tested |
| T-7 | obs-fold hiding a field from one hop | refused in requests always; in responses unless the client opts into in-place replacement | `tests/smuggling.rs`; leniency on/off pairs | none | tested |
| T-8 | whitespace before colon | refused (RFC 9112 section 5.1) | `tests/smuggling.rs` | none | tested |
| T-9 | chunk-extension line-end confusion (Funky Chunks TERM.EXT, EXT.TERM; Netty CVE-2025-58056 and CVE-2026-33870, Jetty CVE-2026-2332, ASP.NET Core CVE-2025-55315) | chunk lines end only at CRLF; a lone LF is `BareLf`; a CR in an extension or quoted string fails the grammar | seven named vectors in `tests/smuggling.rs`, every split | none | tested |
| T-10 | oversized chunk sizes wrapping | at most 16 hex digits, checked arithmetic, running total checked against `max_body` before data | `tests/smuggling.rs`, `tests/adversarial.rs` | a few instructions per chunk | tested |
| T-11 | chunk-extension flood (CVE-2024-22019) | per-message extension budget = `max_header_bytes` | `tests/adversarial.rs` | one add per chunk | tested |
| T-12 | chunk data longer than declared | CRLF required right after the data | `tests/adversarial.rs` | none | tested |
| T-13 | trailer fields reframing a message | trailers validated and never merged; framing from the header section only; forbidden outgoing trailer fields refused | `tests/adversarial.rs`, `tests/trailers.rs` | none | tested |
| T-14 | 0.CL desync | `Content-Length` honoured on every method; answering before reading the body closes | `tests/adversarial.rs` | none | tested |
| T-15 | `Expect`-based desync | `Expect` never changes framing; `100-continue` matched as a trimmed, case-insensitive list element | eight vectors in `tests/adversarial.rs` | none | tested |
| T-16 | smuggling a pipelined request after an error | nothing parsed after a parse error | `tests/adversarial.rs` | none | tested |
| T-17 | response queue poisoning on the client | `UnexpectedData` for bytes with no request outstanding; until-close responses never reused | `client.rs` units, `tests/adversarial.rs` | none | tested |
| T-18 | `Host` attacks (two Hosts, junk, `:80`, bad `%XX`) | one valid `Host`; the absolute-form authority wins | `tests/adversarial.rs` | O(Host length) | tested |
| T-19 | absolute-form tricks (userinfo, empty host, no `//`) | refused | `tests/adversarial.rs` | O(target) | tested |
| T-20 | h2c smuggling | `h2c` is never an upgrade offer; `switching_protocols("h2c")` refused | `tests/adversarial.rs` | none | tested |
| T-21 | upgrade smuggling | the client switches only on a 101 it asked for with `Upgrade`; the server only to an offered protocol | `tests/adversarial.rs` | none | tested |
| T-22 | response splitting / CRLF injection through builders | token names; no CR, LF, controls, or surrounding whitespace in values; static reason phrases | `tests/smuggling.rs`, `message.rs` units | O(value) per field | tested |
| T-23 | caller-set framing fields | framing and hop-by-hop fields reserved (`ReservedHeader`) | `message.rs` units, `tests/connection_control.rs` | O(1) per field | tested |
| T-24 | slowloris head | sans-IO: `progress()` lets drivers run a header deadline; blocking: per-request deadline answered 408 | `tests/localhost.rs` | one `Instant` per request in the adapter | tested |
| T-25 | slow body | as T-24 | `tests/localhost.rs` | as T-24 | tested |
| T-26 | slow reader of a large response | blocking: total response deadline (60 s by default) | `tests/localhost.rs` | one `Instant` per write | tested |
| T-27 | memory exhaustion by huge heads or bodies | every budget checked before buffering; CL above `max_body` refused on the header line | boundary tests; six 10 MiB hostile streams in `tests/alloc.rs` | none | tested |
| T-28 | many idle connections | `shrink_idle`; the blocking server's connection cap with 503 | `tests/pipelining_reuse.rs`, `tests/localhost.rs` | one free | tested |
| T-29 | pipelining flood | pipelined input stays in the bounded buffer; parsing stops until the response is written; request caps | a 100,000-request stream in `tests/prop_roundtrip.rs` | none | tested |
| T-30 | header count or byte flood | `max_headers`, `max_header_bytes`, the 8 KiB per-line budget | boundary tests | a counter per field | tested |
| T-31 | interim response flood | interim heads budgeted by count (`max_interim`) and bytes | `tests/adversarial.rs`, `tests/interim.rs` | a counter per interim | tested |
| T-32 | quadratic parsing on byte-at-a-time input | resumable scanner; compaction only when full | a 16 KiB head fed one byte at a time (`tests/prop_roundtrip.rs`) | none | tested (linearity bench: 0.6) |
| T-33 | integer overflow | checked arithmetic for CL, chunk sizes, running totals | `tests/adversarial.rs`; fuzzing | none | tested |
| T-34 | panics | clippy denies (`unwrap`, `expect`, `unreachable!`, printing), bounded indexing, fuzzing | never-panic property tests; seven fuzz targets in CI | none | tested (24 h campaign: 0.7) |
| T-35 | credentials in logs | `Debug` redacts `authorization`, `proxy-authorization`, `cookie`, `set-cookie` everywhere | `tests/redaction.rs` | only when formatting | tested |
| T-36 | credentials left in reused memory | `set_wipe`: zero finished requests, compaction leftovers, and the buffer on reset, release, drop | `tests/pipelining_reuse.rs` (with a control run) | about 30 to 60 ns per 2 KiB [est.] | tested |
| T-37 | error text reflecting attacker bytes | `Display` is static text; `from_error` uses only it | `error.rs` units over every variant | none | tested |
| T-38 | HTTP/0.9 messages | a version is required in both start lines | `tests/rfc_cases.rs` | none | tested |
| T-39 | status out of range | refused (`InvalidStatus`) | `tests/rfc_cases.rs` | none | tested |
| T-40 | lingering-close abuse | drain bounded to 1 s and 256 KiB; the refusal path never waits | `tests/localhost.rs` | at most 1 s of a thread per close | tested |
| T-41 | busy accept loop on persistent errors | 10 ms back-off; give up after 1,000 errors | code path; injected-error test planned | none | partly |
| T-42 | prior-knowledge HTTP/2 to an HTTP/1.1 listener | 505 and close (`Http2Preface` in 0.5) | `tests/rfc_cases.rs` | 24 compares at connection start | tested |

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
| status line without the space after the code (client) | senders must send it | accepted | harmless to framing; real servers omit it | none |

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

## Costs of the security measures

| Measure | Latency | Memory |
|---|---|---|
| strict line and field validation (SWAR) | included in the head-parse benchmark; there is no switch to turn it off | none |
| framing facts and refusals | under 5 ns per request [est.] | none |
| budgets checked before buffering | a compare per line and per chunk | bounded by configuration |
| redaction | only when `Debug` runs | none |
| wiping (opt-in) | about 30 to 60 ns per 2 KiB request [est.] | none |
| blocking deadlines | one `Instant::now` per request and per write, about 20 to 30 ns each [est.] | none |
