# http-net - Performance

How fast http-net is, how that is measured, how it compares with httparse
and hyper, and the decisions behind the code that makes it fast. Numbers
are for 0.6.0. 0.7.0 and 0.8.0 were measured against their predecessors
with no measurable difference ([`release/v0.8.0.md`](./release/v0.8.0.md)),
and the 0.9.x pass measured the 0.9.1 code against every release from
0.6.0 with no regression ([below](#the-09x-pass)), so these 0.6.0
numbers stand.

## Method

- **Machine:** AMD Ryzen 9 9950X3D (16 cores), Windows 11 x86_64; Linux
  numbers in WSL2 Ubuntu (kernel 6.6), Rust stable 1.99, release profile
  (`lto = "fat"`, one codegen unit, as published).
- **Harness:** criterion 0.5, 3 s measurement, 1 s warm-up, 100 samples
  (20 for `pipelined_100k/small_gets`), process pinned to one core with
  `taskset` on Linux.
- **Interleaving:** a comparison between two builds runs them alternately,
  round after round (five by default), and reports the median of each
  side, so a change in machine load falls on both. The machine had other
  load throughout; single runs vary by 5 to 10%, so only differences
  repeated in every round are reported as changes.
- **Library only:** no sockets. Body events borrow the input buffer, so
  the 1 MiB cases measure one copy into the buffer plus framing.
- **Inputs:** `benches/bench.rs` in this repository; the comparison
  repository uses the same bytes.

### The 5% regression gate

A change that makes a hot-path benchmark (request head, pipelined,
response parse, response write, both 1 MiB bodies) more than 5% slower
than the last release is blocked. `scripts/bench_ab.sh` runs the
interleaved comparison of the working tree against a tag and marks any
bench over the gate:

```bash
scripts/bench_ab.sh v0.8.0 5
```

## Results

Linux x86_64 (WSL2), medians of five interleaved rounds against 0.5.0:

| Benchmark | 0.5.0 | 0.6.0 | Change |
|---|---:|---:|---:|
| 12-field browser GET (453 bytes), parsed and answered with 204 | 304 ns | 234 ns | -23% |
| 100,000 pipelined GETs in 16 KiB reads | 10.1 ms | 8.8 ms (11.4 M requests/s) | -13% |
| client parsing a 1 KiB response | 112 ns | 100 ns | -11% |
| response with five fields and a 1 KiB body, serialized (after reading a one-field `GET`) | 89 ns | 74 ns | -17% |
| 1 MiB body, `Content-Length`, 16 KiB reads | 14.0 µs | 13.5 µs | -4% |
| 1 MiB body, chunked in 4 KiB chunks | 17.6 µs | 17.0 µs | -3% (-9% in a separate run) |
| `write_head`, the same five fields borrowed | | 128 ns | new in 0.5 |

Windows x86_64, the same machine, single runs: browser GET 243 ns,
pipelined 7.8 ms, client parse 97 ns, response write 72 ns, `write_head`
110 ns, 1 MiB bodies 13.9 and 17.3 µs. aarch64 is measured only on CI runners, on demand ([below](#the-09x-pass)).

### Against the targets

| Workload | Target | 0.6.0 | |
|---|---|---|---|
| browser GET parse and 204 | 200 ns | 234 ns | not met |
| head parse, 12 fields (H1) | 1.20x faster than httparse with SIMD, or the SIMD question decided with the gap | parity with httparse with SIMD | decided (below) |
| pipelined small GETs | 15 M requests/s | 11.4 M | not met |
| 1 MiB `Content-Length` body | 10 µs | 13.5 µs | not met |
| 1 MiB chunked body | 12 µs | 17.0 µs | not met |
| response write, five fields, 1 KiB | 50 ns | 74 ns, of which about 62 ns is reading the request the bench answers | not met as measured; the write alone is about 15 ns |
| `write_head`, five fields | 40 ns, zero allocations | 128 ns, zero allocations, the same 62 ns included | allocations met; time not met (about 12 ns per borrowed field) |
| client response parse, 1 KiB | 70 ns | 100 ns | not met |
| byte-at-a-time head feeding | at most 3x the whole-buffer time per byte | linear growth (below) | the guard holds; the literal ratio cannot (D-51) |
| steady-state allocations | 0 per request | 0 | met |

The 1 MiB targets assume the copy into the buffer runs at memory
bandwidth; most of the remaining time there is that copy. `write_head`
validates every borrowed field on each call (token name, reserved names,
value bytes) and writes each field in four pieces; a prebuilt `Response`
did both once when it was built, which is why `respond` is faster.

### Linearity

A head fed one byte at a time costs time linear in its size (the scanner
resumes where its search stopped and the buffer compacts only when full):

| Head | Whole | One byte at a time | Per byte, one at a time |
|---|---:|---:|---:|
| 4 KiB | 0.78 µs | 41.6 µs | 10.2 ns |
| 16 KiB | 2.89 µs | 162 µs | 9.9 ns |
| 32 KiB | 6.42 µs | 334 µs | 10.2 ns |

Eight times the bytes cost 8.0 times the time. One `poll` per byte costs
about 10 ns against about 0.2 ns per byte for whole input, so the spec's
"3x per byte" cannot hold literally; the guard (`tests/linearity.rs`)
checks the growth instead, which is what catches re-reading (D-51).

## Against other libraries

The comparison lives in its own repository,
[`http-net-bench`](https://github.com/jamesgober/http-net-bench), so this
crate never depends on tokio, hyper, or httparse. It runs identical input
bytes through both sides, and `tests/equivalence.rs` there proves each
pair does the same work: httparse is given a framing pass with exactly
http-net's rules (Content-Length duplicates and lists, final `chunked`, the
CL and TE conflict, TE in HTTP/1.0, body budget, keep-alive, `Host` count
and value, upgrade, `Expect`, target escapes), because it is only a parser.
hyper is driven in memory over a duplex stream on a current-thread
runtime; the cost of moving the same bytes through that runtime with no
HTTP is measured separately. picohttpparser gets the same framing pass as
httparse, and llhttp's callbacks do a server's reading and answer each
request. H6 runs whole servers over sockets, with serve-net carrying
http-net.

Linux x86_64 (WSL2), a quiet machine (no fuzzers; load average 0.2 at the
start, 2.7 at the end), pinned to one core, 2026-11-04: http-net 0.9.0,
httparse 1.10.1, hyper 1.12.0, picohttpparser `dd573d8`, llhttp 9.4.3
([`http-net-bench`](https://github.com/jamesgober/http-net-bench), results
`2026-11-04-fb4f3084276c`). H1 is from a second H1-only run straight after
the full run, four passes in which http-net read 172 to 174 ns: the
results file's drift check caught the full run's first H1 pass running 5
to 9% slow.

| Id | Workload | http-net | Competitor | |
|---|---|---:|---:|---|
| H1 | request head and framing, 12 fields | 173 ns | httparse with SIMD 169 to 176 ns; without SIMD 153 ns; parse only 99 to 114 ns. picohttpparser with the same pass 155 to 160 ns, parse only 98 to 111 ns | parity with httparse SIMD, 13% behind without; 8 to 12% behind picohttpparser |
| H2 | full server exchange, five fields and 1 KiB body | 244 ns (prebuilt `Response`), 437 ns (built per request) | hyper 1,313 ns (of which about 294 ns is the runtime) | 3.0 to 5.4x faster |
| H3 | response head and framing | 49 to 50 ns | httparse 45 to 52 ns | parity |
| H3 | full client exchange | 94 ns | hyper 1,230 to 1,239 ns (about 280 ns runtime) | 13x faster |
| H4 | chunked framing of 1 MiB, data in place | 1.63 µs | httparse `parse_chunk_size` loop 1.17 µs | 39% behind |
| H4 | the same with the body copied out | 16.8 µs | httparse loop 16.4 µs; picohttpparser `phr_decode_chunked` (in place, one move of every byte) 10.6 µs | parity with httparse; 58% behind picohttpparser |
| H5 | 100,000 pipelined requests | 7.12 ms | hyper with `pipeline_flush` 22.6 ms; llhttp answering each request 7.39 ms, counting only 5.69 ms | 3.2x faster than hyper; 4% ahead of llhttp doing the same work |
| H6 | plaintext over 127.0.0.1, one core, 16 connections, 16 pipelined | serve-net 373k req/s | hyper 429k, actix-web 384k, may-minihttp 530k | 13% behind hyper |
| H6 | the same on 1 connection, 16 pipelined | serve-net 168k req/s | hyper 164k, actix-web 153k, may-minihttp 184k | level with hyper |

H1, the picohttpparser and llhttp rows, and H6 are report only.
picohttpparser rows are compared within one build: the same C code moves
up to 12% between the bench's two builds (fat LTO lays out the Rust
around it anew), while http-net does not move. The 0.6.0 run had H1 at
177 ns, 16% behind httparse's scalar build; the frozen code is level with
it within noise.

httparse's SIMD path is slower than its own scalar path on this head, and
picohttpparser's SSE4.2 build gains at most 4% over its scalar build: the
lines are short (about 30 bytes), and SIMD setup does not pay off below a
few dozen bytes per line. Against the C parsers, http-net is 8 to 12%
behind picohttpparser on a head (both deciding framing with the same
rules), and 4% ahead of llhttp on pipelined requests when llhttp's
callbacks do a server's reading and answer each one; llhttp's own
benchmark shape, one counting callback, is 25% faster than http-net doing
the full work. picohttpparser's chunked decoder is 58% faster than
http-net's with the body copied out, because it moves each byte once, in
place.

H6 times whole servers on one core, so it reads as what serve-net does,
not http-net alone. serve-net 0.3 runs on net-io 0.3's blocking driver:
one thread per connection. On one connection it is level with hyper; at
16 connections the core switches threads on every batch, and serve-net
is 13% behind hyper, 3% behind actix-web, and 30% behind may-minihttp.
Each server used about 93% of its core at 16 connections, and about half
of it on one connection, where the client's turnaround sets the rate.
http-net's own exchange (H2) is 244 ns, about a tenth of the 2.7 µs
serve-net spends per request at 373k req/s; a non-blocking driver in
net-io is where that gap would close.

### What the comparison means

- **On the work a server does** (H2, H5) and a client does (H3 exchange),
  http-net is three to thirteen times faster than hyper, most of which is
  hyper's own HTTP work, not its runtime.
- **On parsing a head alone** (H1, H3 head), http-net is level with
  httparse and 8 to 12% behind picohttpparser, while doing more: it validates the `Host` value, the target's
  characters and escapes, every field value byte, and the framing rules
  above, all included in its time, and it does so without `unsafe` code.
- **On chunk framing alone** (H4, in place), httparse's minimal loop is
  faster; once the body bytes are moved, the two are level, and
  picohttpparser's in-place decoder is faster than both.
- **Over sockets** (H6), the server around http-net sets the rate:
  serve-net on a blocking, thread-per-connection driver is level with
  hyper on one connection and 13% behind at 16.

### Decisions

- **SIMD: stay with SWAR, no `unsafe`.** The specification's rule
  is to stay safe while the SWAR scanners are within 20% of httparse's
  SIMD path on H1. They are at parity, and httparse's own scalar path is
  faster than its SIMD path on this workload.
- **20% faster than the best competitor at equal or stronger security:
  met on the full exchanges (H2: 3.0x; H5: 3.2x), not met on head parsing
  (H1: parity with httparse's default configuration, 13% behind its scalar
  build, 8 to 12% behind picohttpparser).** The cause is the extra validation listed
  above, which the comparison counts in http-net's time but which httparse
  leaves to its caller. Reaching 20% ahead on H1 would need SIMD scanning
  with `unsafe` intrinsics or dropping checks; neither is
  taken. Recorded as decision D-54.

## The 0.9.x pass

Before 1.0 the frozen code was measured again: for regressions, for where
the time of the unmet write targets goes, and against the competitors on
the current release ([`dev/PLAN.md`](https://github.com/jamesgober/http-net/blob/main/dev/PLAN.md) D-72).

**No regression since 0.6.** Interleaved A/B, nine rounds, pinned to one
core in WSL2, the 0.9.1 tree against each release:

| Bench | against 0.6.0 | against 0.7.0 | against 0.8.0 |
|---|---:|---:|---:|
| `request_head` (browser GET) | +0.6% | +0.0% | +2.7% |
| `response_write/five_fields_1k_body` | -6.7% | -0.1% | -3.2% |

A five-round run had shown `request_head` 8% slower than 0.6.0; the
nine-round runs did not repeat it, which is the noise the method section
describes. `response_parse`, both 1 MiB bodies, and `pipelined_100k` were
within 4% in the five-round run.

**What the write benchmarks contain.** Each iteration of
`response_write` reads a one-field `GET` before it answers, so the
numbers above include a parse. A decomposition probe (single runs) put
reading that request and answering a bodiless `204` at about 62 ns; a
prebuilt `Response` with five fields adds 1 to 2 ns to it, and
`write_head` adds about 12 ns per borrowed field, which is the token,
reserved-name, and value check of each field on every call plus four
writes per field. Two ways to cut that cost, a length mask in front of
the reserved-name lists and one `reserve` for the whole field block, came
out level (-1.4%, within noise) and were dropped.

**Wiping** (`set_wipe(true)`, the `wipe` bench): +5 ns, +2.1%, on the
453-byte browser GET, medians of nine interleaved rounds.

**Against the competitors on 0.9.0** ([`http-net-bench`](https://github.com/jamesgober/http-net-bench),
results `2026-10-29-c1255d143e57`). The machine was shared with fuzzers
(load average 6 to 12), and every time rose by about half on both sides
against the 0.6 run, so only the ratios are reported; they are those of
0.6:

| Id | http-net against the competitor |
|---|---|
| H1 head and framing | 8% behind httparse with SIMD, 20% behind its scalar build |
| H2 full server exchange | 5.4x faster than hyper (prebuilt `Response`) |
| H3 response head and framing | at parity with httparse |
| H3 full client exchange | 11.8x faster than hyper |
| H4 chunked framing, data in place | 40% behind httparse's `parse_chunk_size` loop |
| H4 the same with the body copied out | 9% ahead |
| H5 100,000 pipelined requests | 3.0x faster than hyper |

The quiet-machine run of 2026-11-04 above replaces these figures.

**aarch64.** `.github/workflows/bench.yml` runs `cargo bench` on GitHub's
Linux arm64 and macOS runners on demand. Shared runners are noisy, so
those numbers are indicative only; the regression gate stays the
interleaved A/B on one machine. One run of 0.9.1, medians, with the x86_64
runner for scale:

| Bench | Linux arm64 | macOS arm64 | Linux x86_64 |
|---|---:|---:|---:|
| browser GET, parsed and answered | 417 ns | 511 ns | 577 ns |
| 100,000 pipelined GETs | 15.3 ms | 15.8 ms | 18.0 ms |
| 1 MiB body, `Content-Length` | 40.5 µs | 53.5 µs | 48.1 µs |
| 1 MiB body, chunked | 44.5 µs | 62.8 µs | 50.1 µs |
| response with five fields and 1 KiB | 143 ns | 150 ns | 167 ns |
| `write_head`, the same fields | 221 ns | 292 ns | 267 ns |
| client parsing a 1 KiB response | 166 ns | 205 ns | 205 ns |

The SWAR scanners behave the same on aarch64: no bench stands out against
the x86_64 runner.

## Where the time goes

Head parsing of the 12-field browser GET, measured by component during
0.6 (single runs): the line scanner about 110 ns before the fast path
(about 85 after), interpretation about 60 ns (field facts about 27 of it;
the request line, target, and `Host` checks the rest).

What 0.6 changed, each change measured by interleaved A/B and kept only if
it helped ([`dev/PLAN.md`](https://github.com/jamesgober/http-net/blob/main/dev/PLAN.md), decisions D-45 to D-53):

| Change | Result |
|---|---|
| One pass for the common field line (name to colon, spaces, printable value, CR LF); every other shape through the general path | head -20%, client parse -15%, pipelined -12% (kept, D-48) |
| One pass for the common chunk line (hex digits, CR LF) | chunked body -9%, `ChunkedDecoder` -36% (kept, D-52) |
| Status line from a compile-time table | response write -10% (kept, D-49) |
| Field facts rule out names by length with one bitmask test | client parse -10%, head within noise (kept, D-53) |
| `respond_head_only` and vectored writes for bodies over 4 KiB | saves the body copy (kept, D-50) |
| LF search 16 bytes per step | +12% (rejected, D-45) |
| LF search and value validation in one pass over whole lines | +4 to +9% (rejected, D-46) |
| `match` on name length for field facts | +6% (rejected, D-47) |
