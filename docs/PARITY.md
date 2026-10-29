# http-net - Parity

> How http-net compares, feature by feature, with the other HTTP/1.1
> implementations it is measured against: hyper, httparse, h11, llhttp,
> picohttpparser, and the `http` crate. Every cell was checked for 0.9.0,
> by running the implementation where it could be run and by reading its
> source otherwise.

## Versions checked

| Implementation | Version | How |
|---|---|---|
| http-net | 0.9.0 (the 1.0 candidate) | its own tests, cited per row in the evidence |
| hyper | 1.12.0 (`server`, `client`, `http1`) | a real hyper server and client on localhost fed each input |
| httparse | 1.10.1 (default `ParserConfig`) | each input parsed directly |
| llhttp | 9.3.0, as shipped in Node.js 24.14.1 | Node's own parser binding, every lenient flag off |
| h11 | 0.16.0 | source |
| picohttpparser | master `dd573d8` (2026-10-27) | source |
| `http` crate | 1.5.0 | source |

The per-cell evidence (the probe result, or the file and line at the
version above) is in
[`dev/PARITY-EVIDENCE.md`](https://github.com/jamesgober/http-net/blob/main/dev/PARITY-EVIDENCE.md).

## Legend

**Y** yes; **N** no; **P** partial; **opt** opt-in; **-** not applicable.
A note in brackets qualifies the value.

## Matrix

| Feature | http-net | hyper 1.x | httparse | h11 | llhttp | picohttpparser | `http` crate |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Sans-IO core (bytes in, events out, no runtime) | Y | N (async I/O traits) | Y (head only) | Y | Y (callbacks) | Y (head only) | - |
| Server side | Y | Y | Y | Y | Y | Y | - |
| Client side | Y | Y | Y | Y | Y | Y | - |
| Zero-copy head views | Y | P (values and URI are shared `Bytes` slices; one `HeaderMap` per request) | Y | N (Python objects) | Y (callbacks with pointers) | Y | - |
| Linear incremental head parsing (no re-scan on split input) | Y | Y (end-of-head scan resumes; httparse once) | N (re-parses from start) | Y (saved search offsets) | Y | P (prevbuflen hint) | - |
| Body decoding (CL, chunked, until close) | Y | Y | N (chunk-size helper only) | Y | Y | chunked only | - |
| Serialization with connection-owned framing | Y | Y | N | Y | N | N | - |
| Bare LF refused | Y | N (httparse accepts) | N | N (chunk-size lines need CRLF) | Y (default) | N | - |
| obs-fold refused in requests | Y | Y | Y | N (unfolded) | Y | N (returned as name-less line) | - |
| Whitespace before colon refused | Y | Y (requests) | Y (requests; opt-in allowed in responses) | Y | Y | Y | - |
| CL + TE refused | Y | N (TE wins, CL dropped, connection closed) | - | N (TE wins) | Y (lenient flag to allow) | - | - |
| Duplicate equal CL refused | Y | N (collapsed) | - | N (collapsed) | Y | - | - |
| TE must end in single `chunked` | Y | P (last must be chunked; `chunked, chunked` and `gzip, chunked` pass) | - | Y (only chunked supported) | Y (lenient flag to relax) | - | - |
| Chunk extension grammar validated (Funky Chunks class) | Y | P (refuses bare LF and lone CR only) | - | N (skipped) | P (refuses all line-terminator vectors; accepts empty name) | N (skipped to CR) | - |
| Chunk extension byte budget per message | Y (shares `max_header_bytes`) | Y (16 KiB) | - | N (16 KiB per line via event size) | N (Node.js adds 16 KiB per chunk line) | P (overhead-ratio heuristic) | - |
| Host required and single (HTTP/1.1) | Y | N (application's job) | N | Y (required) | N | N | - |
| Request-target form checked against method | Y | N | N | N | P (authority-form refused outside CONNECT) | N | - |
| Trailers received | Y (opt-in) | Y (forbidden fields not filtered) | - | Y | Y | Y (raw) | - |
| Trailers sent | Y | Y (only fields named in `Trailer`) | - | Y | - | - | - |
| `Expect: 100-continue` server | Y | Y (sent when body is polled) | - | Y | - | - | - |
| `Expect: 100-continue` client | Y | N (body sent at once) | - | Y | - | - | - |
| Interim 1xx sent (103) | Y | N (automatic 100 and 101 only) | - | Y | - | - | - |
| Interim 1xx received and reported | Y (opt-in) | Y (opt-in `ext::on_informational`) | Y | Y | Y | Y | - |
| Upgrade hand-off with leftover bytes | Y | Y | - | Y (`trailing_data`) | Y (`HPE_PAUSED_UPGRADE`) | - | - |
| 101 checked against offered protocols | Y | N | - | P (an offer must exist; names not compared) | - | - | - |
| h2c upgrade ignored | Y | Y (served as HTTP/1.1 unless the application answers 101) | - | - | - | - | - |
| HTTP/2 preface detection | Y | Y (served with `http2` feature; detected and closed in http1-only) | - | - | - | - | - |
| Server pipelining, in-order responses | Y | Y | - | Y | Y (parser) | - | - |
| Client pipelining | Y (depth N) | N | - | N | Y (parser) | - | - |
| Keep-alive rules (1.0 / 1.1) | Y | Y | - | Y | Y | - | - |
| Early response closes when body unread | Y | Y (closes if body not yet received) | - | P (no auto close; reuse refused until body done) | - | - | - |
| Header count limit | Y (100) | Y (100) | Y (caller array) | N | N | Y (caller array) | - |
| Header bytes limit | Y (16 KiB) | Y (`max_header_size`, `max_buf_size`) | N | Y (16 KiB event size) | N (application; Node.js 16 KiB) | N | - |
| Per-field line limit | Y (always on, 8 KiB default) | N | N | N | N | N | - |
| Body limit checked before reading | Y | N (application) | - | N | N | - | - |
| Date header cache | Y | Y (`auto_date_header`) | - | N | - | - | - |
| Method registry with safe/idempotent | Y | Y (`http::Method`, `is_safe`, `is_idempotent`) | - | N | Y (method enum) | N | Y |
| Status registry with reasons | Y (61 codes) | Y (`http::StatusCode`) | - | N | Y (`HTTP_STATUS_MAP`, `llhttp_status_name`) | - | Y |
| Lenient switches | client-only, one switch | Y (several) | Y (several) | N | Y (eleven in 9.4.3; ten in 9.3.0) | N | - |
| Header case preserved | Y | opt (`preserve_header_case`) | Y | N (lowercased) | Y | Y | N (lowercased) |
| `no_std` | Y (+alloc), CI target | N | Y | - | Y (C) | Y (C) | N |
| Zero runtime dependencies | Y (first-party parse-net only) | N | Y | Y | Y | Y | N (`bytes`, `itoa`) |
| Credential redaction in `Debug` | Y | N | - | - | - | - | P (`HeaderValue::set_sensitive`) |
| Allocation-free response writer | Y | N | - | N | - | - | - |
| Standalone chunked decoder | Y | N (internal) | P (size only) | N | Y | Y | - |
| Fuzzed | Y | N (httparse underneath is) | Y | Y | Y | P (indirectly, via h2o on OSS-Fuzz) | Y (OSS-Fuzz `fuzz_http`) |

## What the matrix shows

- **Framing refusals.** http-net refuses every message two implementations
  could frame differently. hyper lets `Transfer-Encoding` win over
  `Content-Length` (dropping the length and closing the connection),
  collapses duplicate equal `Content-Length` fields, and accepts
  `chunked, chunked` and `gzip, chunked`. h11 accepts bare LF and obs-fold
  (unfolding it) and also lets `Transfer-Encoding` win. httparse and
  picohttpparser accept bare LF line endings.
- **Request checks.** Of the implementations here, only http-net and h11
  require a single `Host` in HTTP/1.1, and only http-net checks the
  request-target form against the method throughout.
- **Chunk extensions.** http-net validates the extension grammar and
  bounds the extension bytes of a whole message. llhttp refuses every
  line-ending trick but accepts an empty extension name; its size limit
  lives in Node.js (16 KiB per chunk line, reset at every chunk), so many
  small extensions across many chunks pass. h11 and picohttpparser skip
  extensions without checking them.
- **Client side.** hyper's client sends the body at once despite
  `Expect: 100-continue` and accepts a `101` that names a protocol the
  request never offered; http-net waits for `100` (or a final status) and
  refuses the unoffered switch.
- **Logging.** hyper's `Debug` prints `Authorization` and `Cookie` values;
  http-net redacts credential values in every `Debug` output.
- **Where others go further.** hyper serves HTTP/2 with its `http2`
  feature; http-net is HTTP/1.1 only and refuses the HTTP/2 preface with a
  specific error (HTTP/2 is a separate crate's job). hyper, httparse, and llhttp offer several
  lenient switches; http-net has one, on the client.
