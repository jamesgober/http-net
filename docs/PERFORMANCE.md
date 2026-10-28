# http-net - Performance

How fast http-net is, how that is measured, how it compares with httparse
and hyper, and the decisions behind the code that makes it fast. Numbers
are for 0.6.0. 0.7.0 and 0.8.0 were measured against their predecessors
with no measurable difference ([`release/v0.8.0.md`](./release/v0.8.0.md)),
so these 0.6.0 numbers stand.

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
| response with five fields and a 1 KiB body, serialized | 89 ns | 74 ns | -17% |
| 1 MiB body, `Content-Length`, 16 KiB reads | 14.0 µs | 13.5 µs | -4% |
| 1 MiB body, chunked in 4 KiB chunks | 17.6 µs | 17.0 µs | -3% (-9% in a separate run) |
| `write_head`, the same five fields borrowed | | 128 ns | new in 0.5 |

Windows x86_64, the same machine, single runs: browser GET 243 ns,
pipelined 7.8 ms, client parse 97 ns, response write 72 ns, `write_head`
110 ns, 1 MiB bodies 13.9 and 17.3 µs. aarch64 has not been measured.

### Against the targets

| Workload | Target | 0.6.0 | |
|---|---|---|---|
| browser GET parse and 204 | 200 ns | 234 ns | not met |
| head parse, 12 fields (H1) | 1.20x faster than httparse with SIMD, or the SIMD question decided with the gap | parity with httparse with SIMD | decided (below) |
| pipelined small GETs | 15 M requests/s | 11.4 M | not met |
| 1 MiB `Content-Length` body | 10 µs | 13.5 µs | not met |
| 1 MiB chunked body | 12 µs | 17.0 µs | not met |
| response write, five fields, 1 KiB | 50 ns | 74 ns | not met |
| `write_head`, five fields | 40 ns, zero allocations | 128 ns, zero allocations | allocations met; time not met |
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
HTTP is measured separately.

Linux x86_64 (WSL2), medians of three rounds, http-net 0.6.0 (working
tree), httparse 1.10.1, hyper 1.12.0:

| Id | Workload | http-net | Competitor | |
|---|---|---:|---:|---|
| H1 | request head and framing, 12 fields | 177 ns | httparse with SIMD 172 ns; without SIMD 153 ns; parse only 104 to 114 ns | parity with SIMD, 16% behind without |
| H2 | full server exchange, five fields and 1 KiB body | 250 ns (prebuilt `Response`), 406 ns (built per request) | hyper 1,382 ns (of which about 310 ns is the runtime) | 3.4 to 5.5x faster |
| H3 | response head and framing | 50 ns | httparse 46 to 49 ns | parity to 8% behind |
| H3 | full client exchange | 95 ns | hyper 1,239 ns (about 300 ns runtime) | 13x faster |
| H4 | chunked framing of 1 MiB, data in place | 1.69 µs | httparse `parse_chunk_size` loop 1.22 µs | 38% behind |
| H4 | the same with the body copied out | 17.5 µs | 17.1 µs | parity |
| H5 | 100,000 pipelined requests | 7.32 ms | hyper with `pipeline_flush` 23.6 ms | 3.2x faster |

httparse's SIMD path is slower than its own scalar path on this head: its
lines are short (about 30 bytes), and SIMD setup does not pay off below a
few dozen bytes per line. H6 (plaintext over sockets) is not measured
yet; it will run through serve-net;
the C harnesses the specification lists as report-only (picohttpparser,
llhttp) are not run.

### What the comparison means

- **On the work a server does** (H2, H5) and a client does (H3 exchange),
  http-net is three to thirteen times faster than hyper, most of which is
  hyper's own HTTP work, not its runtime.
- **On parsing a head alone** (H1, H3 head), http-net is level with
  httparse, while doing more: it validates the `Host` value, the target's
  characters and escapes, every field value byte, and the framing rules
  above, all included in its time, and it does so without `unsafe` code.
- **On chunk framing alone** (H4, in place), httparse's minimal loop is
  faster; once the body bytes are moved, the two are level.

### Decisions

- **SIMD: stay with SWAR, no `unsafe`.** The specification's rule
  is to stay safe while the SWAR scanners are within 20% of httparse's
  SIMD path on H1. They are at parity, and httparse's own scalar path is
  faster than its SIMD path on this workload.
- **20% faster than the best competitor at equal or stronger security:
  met on the full exchanges (H2: 3.4x; H5: 3.2x), not met on head parsing
  (H1: parity with httparse's default configuration, 16% behind its scalar
  build).** The cause is the extra validation listed
  above, which the comparison counts in http-net's time but which httparse
  leaves to its caller. Reaching 20% ahead on H1 would need SIMD scanning
  with `unsafe` intrinsics or dropping checks; neither is
  taken. Recorded as decision D-54.

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
