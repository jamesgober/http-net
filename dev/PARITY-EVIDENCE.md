# Parity matrix: evidence

The evidence behind [`docs/PARITY.md`](../docs/PARITY.md): every cell the specification left unverified, how it was checked, and the source. Recorded for 0.9.0 (D-67).

Date: 2026-10-28. Target: the specification's parity matrix (section 9) and its list of facts to check (section 18.4).

## Versions tested and sources

| Subject | Version or revision | How it was checked |
|---|---|---|
| hyper | 1.12.0 (features server, client, http1), with hyper-util 0.1.21, http-body-util 0.1.5, tokio 1.54.1 | Empirical probes, a scratch probe project, plus source read in the cargo registry copy of hyper-1.12.0 |
| httparse | 1.10.1 | Direct probe in the same project (default `ParserConfig`) |
| `http` crate | 1.5.0 (tag v1.5.0, 16fc9a7b840c2181e7f8b37397c107b0ffcd050d) | Source: `Cargo.toml`, `src/lib.rs`, `src/header/value.rs` |
| llhttp | 9.3.0 as bundled in Node.js 24.14.1 (`process.versions.llhttp`); upstream latest release 9.4.3 (2026-07-30) | Empirical probes through Node's own parser binding (`require('_http_common').HTTPParser`, lenient flags 0, default max header size), a probe script; source `deps/llhttp/include/llhttp.h` and `src/node_http_parser.cc` at nodejs/node v24.14.1 |
| h11 | 0.16.0 (tag commit 1c5b07581f058886c8bdd87adababd7d959dc7ca) | Source read (python-hyper/h11) |
| picohttpparser | master dd573d8fa9264c646a400e96ce9f07dea6f156e4 (2026-10-27); newest tag v1.5 is 54413dc6 | Source read (h2o/picohttpparser); line numbers below are at master |
| http-net | 0.8.0 (`Cargo.toml`), this repository | Code and test read; full `cargo test --tests` run (results at the end) |

hyper probes ran a real `hyper::server::conn::http1::Builder::new()` (defaults, `with_upgrades`) or `hyper::client::conn::http1::handshake` over a localhost TCP socket, with a raw peer writing the attack bytes. Every request probe that could desync was followed by a pipelined `GET /second` so a framing disagreement would be visible.

In the evidence columns, "probe:" means observed behaviour in the probe output; `file:line` refers to the source revision in the table above.

---

## 1. Resolved cells, per competitor column

### hyper 1.x (1.12.0)

| Feature | Old | Resolved | Evidence |
|---|---|---|---|
| Zero-copy head views | P [u] | P | Source: header values are `Bytes` slices of the read buffer (`src/proto/h1/role.rs:47-58` `header_value!` with `HeaderValue::from_maybe_shared_unchecked`, `role.rs:271` `slice.slice(..)`), URI is `slice_ref` of the same buffer (`role.rs:226-229`). A `HeaderMap` is still built per request (`role.rs:263-265`, reused through `cached_headers`). |
| Linear incremental head parsing | P [u] | Y | Source: after a partial parse hyper records `partial_len` (`src/proto/h1/io.rs:204-218`) and `parse_headers` first runs `is_complete_fast(bytes, prev_len)`, which scans only from `prev_len - 3` for the blank line (`role.rs:88-92`, `role.rs:100-117`); httparse runs on the whole head only once the end is in the buffer. Probe: head fed one byte per read (tokio `duplex(1)`): 8019 B 3.4 ms, 17010 B 9.1 ms, 32994 B 14.7 ms, 65961 B 30.5 ms (8x bytes, about 8x time). |
| CL + TE refused | [u] | N | Probe: `Content-Length: 5` + `Transfer-Encoding: chunked` (either order) is accepted, body decoded as chunked, Content-Length removed from the map, response carries `connection: close` and the connection closes. Source: `role.rs:283-287` (CL dropped when TE seen), `role.rs:296-298` (CL after TE ignored), `role.rs:358-360` (`keep_alive = false`). |
| Duplicate equal CL refused | [u] | N | Probe: two `Content-Length: 5` fields accepted, second request on the same connection served. Differing values and the list form `5, 5` get 400. Source: `role.rs:300-310`. |
| TE must end in single `chunked` | Y [u] | P | Probe: `chunked, gzip` and `identity` get 400 (`TransferEncodingInvalid`), but `chunked, chunked`, `chunked` in two fields, and `gzip, chunked` are accepted (gzip is left undecoded for the application). Source: `src/headers.rs:159-168` checks only the last coding; `role.rs:353-356`. |
| Chunk extension grammar validated | [u] | P | Probe: refused: extension ending in bare LF ("invalid chunk extension contains newline"), lone CR inside an extension ("Invalid chunk size LF"). Accepted: NUL in extension, empty name `;=`, space inside `a b`, control byte 0x01 inside a quoted value. Source: `src/proto/h1/decode.rs:427-453` ("We don't care about extensions really at all. Just ignore them."). |
| Chunk extension byte budget per message | [u] | Y | Source: `decode.rs:20` `CHUNKED_EXTENSIONS_LIMIT = 16 KiB`, counter `extensions_cnt` lives in the decoder for the whole body (`decode.rs:44`, `decode.rs:103`) and is checked at `decode.rs:445-447`; upstream test `test_read_chunked_extensions_over_limit` (`decode.rs:935`). Probe: 40 chunks with 1000-byte extensions refused ("chunk extensions over limit"); 10 such chunks accepted. |
| Host required and single | N [u] | N | Probe: HTTP/1.1 request with no Host and with two Host fields both reach the handler and get 200. |
| Request-target form checked against method | P [u] | N | Probe: `GET *`, `CONNECT /x` (origin-form), `GET a:443` (authority-form) all reach the handler. No form check found in `role.rs` Server::parse. |
| `Expect: 100-continue` server | Y [u] | Y | Probe: `100 Continue` is written only when the handler polls the body; when the handler ignores the body no 100 is sent and the connection closes after the response. Source: `src/proto/h1/conn.rs:317-324`, `src/proto/h1/dispatch.rs:317`. |
| `Expect: 100-continue` client | [u] | N | Probe: client request with `Expect: 100-continue` wrote head and body in one segment at t=17 ms, before the server's 100 at t=524 ms. Source: the client parse path sets `expect_continue: false` (`role.rs:1193`); no wait exists. |
| Interim 1xx sent (103) | Y [u] | N | Source: a `Service` returning a 1xx response is turned into 500 with `new_user_unsupported_status_code` (`role.rs:400-416`, comment "hyper currently doesn't support returning 1xx status codes as a Response"). Only the automatic `100 Continue` and `101` are sent. |
| Interim 1xx received and reported | Y (client extension) [u] | Y (opt-in) | Source: `hyper::ext::on_informational(&mut req, callback)` (`src/ext/informational.rs:20`). Probe: 103 then 200; the callback fired with `103 Early Hints` and its `link` field, the final response was 200. Without the callback the 1xx is skipped (`role.rs:1297-1299`). |
| 101 checked against offered protocols | [u] | N | Probe: client offered `Upgrade: websocket`, server answered `101` with `Upgrade: foo`; accepted, upgrade completed, leftover `LEFTOVER` delivered. A 101 to a request that offered no upgrade was also accepted. Source: `role.rs:1294-1296` (any 101 is an upgrade). |
| h2c upgrade ignored | [u] | Y | Probe: `Upgrade: h2c` + `HTTP2-Settings` request served as plain HTTP/1.1 (200, keep-alive). hyper never switches by itself; an application could still answer 101. |
| Client pipelining | N [u] | N | Probe: after the first `send_request`, `SendRequest::ready()` stayed pending until the first response; the second `send_request` failed with "operation was canceled". The server saw only `GET /one` before it answered. |
| Early response closes when body unread | [u] | Y | Probe: handler answered without reading a 5-byte body that had not yet arrived: response then EOF (connection closed), same for a chunked body. When the unread body was already in the buffer, hyper consumed it and served the pipelined second request (correct, no desync). |
| Per-field line limit | N [u] | N | Probe: a single 300 KiB field line was accepted with default settings (only the about 400 KB `max_buf_size` bounds it). |
| Credential redaction in `Debug` | N [u] | N | Probe: `format!("{:?}", req)` printed `"authorization": "Bearer SECRET-TOKEN"` and `"cookie": "sid=SECRET-COOKIE"` in clear; hyper does not mark parsed values sensitive. |
| Fuzzed | Y [u] | N | hyperium/hyper master tree has no fuzz path (`gh api repos/hyperium/hyper/git/trees/master?recursive=1`). OSS-Fuzz has no `projects/hyper`; `projects/hyperium` has `main_repo: https://github.com/hyperium/http` and its `build.sh` builds only http's `fuzz_http` and h2's `fuzz_client`, `fuzz_e2e`, `fuzz_hpack` (google/oss-fuzz at ea7eeb3e). hyper's HTTP/1 head parsing goes through httparse, which is fuzzed. |

### httparse (1.10.1)

| Feature | Old | Resolved | Evidence |
|---|---|---|---|
| Fuzzed | Y [u] | Y | seanmonstar/httparse at a0fa552e: `fuzz/fuzz_targets/` has parse_request, parse_response, parse_headers, parse_chunk_size, parse_request_multspaces, parse_response_multspaces; `.github/workflows/cifuzz.yml`; OSS-Fuzz `projects/httparse/build.sh` builds all six. |

(Probe confirmation of existing httparse cells, default `ParserConfig`: `GET / HTTP/1.1\nHost: a\n\n` returns `Complete(24)` (bare LF accepted); obs-fold and space before colon return `Err(HeaderName)`.)

### h11 (0.16.0)

| Feature | Old | Resolved | Evidence |
|---|---|---|---|
| Linear incremental head parsing | P [u] | Y | `h11/_receivebuffer.py:50-51` keeps `_next_line_search` and `_multiple_lines_search`; `:118` resumes the blank-line search from the saved offset and `:120` advances it to `len - 2`; file header comment at `:14` states the O(n) goal. |
| Bare LF refused | [u] | N | `_receivebuffer.py:44` `blank_line_regex = re.compile(b"\n\r?\n")`; lines split on `\n` with optional `\r` stripped (`:126-130`). Exception: chunk-size lines need CRLF (`_receivebuffer.py:93`, `_abnf.py:128`). |
| obs-fold refused in requests | [u] | N | `_readers.py:40-61`: continuation lines are joined to the previous value with a space (accepted, unfolded) for requests, responses and trailers; only a continuation as the first line is refused (`:50`). Also `docs/source/supported-http.rst:65-76`. |
| CL + TE refused | [u] | N | `_connection.py:126-130` "T-E beats C-L": the message is framed as chunked; `_headers.py:152-206` does not reject the pair. |
| Duplicate equal CL refused | [u] | N | `_headers.py:173-184`: equal values (repeated fields or a comma list) are collapsed to one; differing values raise "conflicting Content-Length headers". |
| Chunk extension grammar validated | [u] | N | `_abnf.py:121-124` `chunk_ext = r";.*"` with the comment "we aren't parsing the things"; any byte except LF passes, including CR and NUL. |
| Chunk extension byte budget per message | [u] | N | No extension counter. The only bound is `max_incomplete_event_size` (default 16 KiB, `_connection.py:69`), checked against the receive buffer whenever a reader needs more data (`_connection.py:484-490`, 431). That bounds one chunk line, not the message total. |
| Request-target form checked against method | [u] | N | `_abnf.py:83` `request_target = r"{vchar}+"`, enforced at `_events.py:122`; no method-dependent form check. |
| 101 checked against offered protocols | [u] | P | Any 101 counts as `_SWITCH_UPGRADE` (`_connection.py:261-262`); h11 only requires that the client sent some `Upgrade` header (pending proposal, `_connection.py:279-280`, `_state.py:284-287`). Protocol names are never compared. |
| Early response closes when body unread | Y (MUST_CLOSE) [u] | P | No automatic close: keep-alive is disabled only by `Connection: close` or HTTP/1.0 (`_connection.py:84-90`, `:305-308`). The connection cannot be reused while the client side is still in SEND_BODY because `start_next_cycle` raises unless both sides are DONE (`_state.py:356-360`); draining or closing is left to the caller (`docs/source/api.rst:638-643`). |
| Header count limit | N [u] | N | No count; only the 16 KiB `max_incomplete_event_size` total. `Connection.__init__` takes only `our_role` and `max_incomplete_event_size` (`_connection.py:167-171`). |
| Per-field line limit | N [u] | N | Same: only the 16 KiB whole-event bound. |
| Lenient switches | N [u] | N | `_connection.py:167-171`: no options besides `max_incomplete_event_size`. |
| Fuzzed | Y [u] | Y | In-repo AFL harness `fuzz/afl-server.py` and `fuzz/README.rst`; OSS-Fuzz `projects/h11` (fuzz_h11.py, libFuzzer with ASan and UBSan) at google/oss-fuzz fd3ab601. |

(Existing h11 cells confirmed: whitespace before colon refused, `_abnf.py:64-70` with `fullmatch` at `_util.py:87`; Host required and duplicates refused, `_events.py:112-119`; only exactly `chunked`, `gzip, chunked` refused with 501 and multiple TE fields refused, `_headers.py:186-201`.)

### llhttp (9.3.0 in Node.js 24.14.1)

All probes call the parser through Node's binding with lenient flags 0. Two behaviours below come from Node's binding (`src/node_http_parser.cc`), not from llhttp itself, and are marked as such.

| Feature | Old | Resolved | Evidence |
|---|---|---|---|
| obs-fold refused in requests | Y [u] | Y | Probe: `X: b\r\n c` gives `HPE_INVALID_HEADER_TOKEN` "Unexpected whitespace after header value"; same in responses. |
| Whitespace before colon refused | Y [u] | Y | Probe: `Host : a` and `X\t: b` give `HPE_INVALID_HEADER_TOKEN` "Invalid header token". |
| Duplicate equal CL refused | [u] | Y | Probe: two `Content-Length: 5` give `HPE_UNEXPECTED_CONTENT_LENGTH` "Duplicate Content-Length" (requests and responses); `5, 5` gives `HPE_INVALID_CONTENT_LENGTH`. |
| Chunk extension grammar validated | Y [u] | P | Probe refused: extension ending in bare LF (`HPE_CR_EXPECTED`), lone CR inside (`HPE_STRICT` "Expected LF after chunk size"), NUL (`HPE_STRICT` "Invalid character in chunk extensions value"), space inside a name, control byte in a quoted value, BWS `5 ;a` (`HPE_INVALID_CHUNK_SIZE`). Accepted: an empty extension name `5;=`. Every Funky Chunks line-terminator vector is refused; the one grammar gap is the empty name. |
| Chunk extension byte budget per message | Y (Node.js fix for CVE-2024-22019) [u] | N (llhttp); Node.js: 16 KiB per chunk line | llhttp has no counter. Node's binding adds `kMaxChunkExtensionsSize = 16384` (`node_http_parser.cc:86`), counted in `on_chunk_extension` (`:576-585`, `HPE_CHUNK_EXTENSIONS_OVERFLOW`) but reset in `on_chunk_header` for every chunk (`:587-592`) and per message (`:319`). Probe: one 20000-byte extension refused; 40 chunks with 1000-byte extensions (40 KB total) accepted. So the CVE-2024-22019 fix is a per-chunk-line limit in Node, not a per-message budget, and not in llhttp. |
| Request-target form checked against method | P [u] | P | Probe: `GET a:443` (authority-form with GET) refused, `HPE_INVALID_URL`; `GET *` and `CONNECT /x` accepted. |
| Upgrade hand-off with leftover bytes | Y (`HPE_PAUSED_UPGRADE`) [u] | Y | `llhttp.h:82` `HPE_PAUSED_UPGRADE = 22`, documented at `llhttp.h:669`. Probe: Upgrade request followed by `LEFTOVER` returned consumed=68 (exactly the head) with `upgrade=true`; CONNECT followed by `TUNNEL` stopped at the head (39 bytes). |
| Header count limit | N [u] | N | Probe: 1001 header fields accepted. llhttp has no field counter; Node's binding limits only bytes (`node_http_parser.cc:1021-1023`, `HPE_HEADER_OVERFLOW`, default 16 KiB; probe: 3001 fields and one 20 KiB line refused, one 12 KiB line accepted). |
| Status registry with reasons | Y [u] | Y | `llhttp.h:438` `HTTP_STATUS_MAP(XX)` (includes 103 EARLY_HINTS and unofficial codes) and `llhttp.h:766` `llhttp_status_name()`, at 9.3.0. |
| Fuzzed | Y [u] | Y | nodejs/llhttp at 69936dbc: `test/fuzzers/fuzz_parser.c`; OSS-Fuzz `projects/llhttp/build.sh` builds `fuzz_parser`. |

(Existing llhttp cells confirmed by probe: bare LF refused, `HPE_INVALID_VERSION` / `HPE_CR_EXPECTED` in requests and responses; CL + TE refused in both orders and in responses; `chunked, gzip`, `chunked, chunked`, two TE fields and `identity` refused; 103 then 200 reported as two messages.)

### picohttpparser (master dd573d8f)

| Feature | Old | Resolved | Evidence |
|---|---|---|---|
| Bare LF refused | [u] | N | `picohttpparser.c:193-195` (`get_token_to_eol`, `else if (*buf == '\012')`), `:315-317` (`parse_headers`), `:372-374` and `:399-400` (`parse_request`), `:217-219` (`is_complete`). |
| obs-fold refused in requests | [u] | N | A line starting with SP or HTAB after the first field is returned as an entry with `name = NULL` (`:323`, `:340-342`; documented `picohttpparser.h:47-48`); not refused and not unfolded, the caller must decide. A fold on the first field line is refused by `parse_token`. |
| Whitespace before colon refused | [u] | Y | `parse_token(..., ':')` rejects any non-token byte (`:275-277`); comment at `:324-325` "do not discard SP before colon" (mfsa2006-33). |
| Chunk extension grammar validated | [u] | N | `CHUNKED_IN_CHUNK_EXT` (`:596-607`) skips every byte up to CR; only a bare LF there is refused (`:603-605`). |
| Chunk extension byte budget per message | N [u] | P | No extension limit, but a decoder-lifetime heuristic (`:699-703`): when incomplete, error once total chunked overhead reaches 102400 bytes and payload is under a quarter of the bytes read. It bounds extension floods indirectly, by ratio, not by a byte budget. |
| Fuzzed | Y [u] | P | No fuzzer in the repository at dd573d8f and no `projects/picohttpparser` in OSS-Fuzz. Covered indirectly: h2o vendors it as `deps/picohttpparser` and OSS-Fuzz `projects/h2o/build.sh` builds `h2o-fuzzer-http1`. |

### `http` crate (1.5.0)

| Feature | Old | Resolved | Evidence |
|---|---|---|---|
| `no_std` | N [u] | N | `src/lib.rs:158` the `no_std` attribute is commented out and `:159-160` is `compile_error!("`std` feature currently required, support for `no_std` may be added later")`; `Cargo.toml:34-36` `default = ["std"]`. Open issues #749, #740, #563, #551, #472. |
| Zero runtime dependencies | N (`bytes`, `itoa`, `fnv`) [u] | N (`bytes`, `itoa`) | `Cargo.toml:38-40` at v1.5.0: `bytes = "1"`, `itoa = "1"`. `fnv` is not a dependency. |

---

## 2. Section 18.4 facts

1. **hyper CL + TE:** not refused. Transfer-Encoding wins, Content-Length is removed, the body is decoded as chunked and the connection is closed after the response (probe; `role.rs:283-287`, `:358-360`). The client side also accepts a response with both and decodes it as chunked (probe).
2. **hyper duplicate equal CL:** accepted and collapsed on the server (`role.rs:300-310`) and on the client (probe: `Content-Length: 2` twice accepted); differing values and the list form `5, 5` are refused with 400.
3. **hyper chunk extensions:** contents ignored; a bare LF or a lone CR in an extension is refused; total extension bytes are capped at 16 KiB per message (`decode.rs:20`, `:427-453`). No grammar check (NUL, empty name, spaces, control bytes in quoted strings all pass).
4. **hyper trailers:** received trailers are delivered to the application through the body's trailer frame (probe, server and client), including fields that RFC 9110 forbids in trailers (probe: `Content-Length: 3` in trailers passed through); obs-fold in trailers is refused (probe). Trailer section capped at 16 KiB (`decode.rs:25`). Sent trailers are written only for fields named in the message's `Trailer` header, and forbidden names are dropped (`encode.rs:175-195`, `encode.rs:270-286`).
5. **hyper client informational API:** `hyper::ext::on_informational(&mut req, |res: hyper::ext::informational::Response<'_>| ...)` (`src/ext/informational.rs:20`), a per-request callback; without it 1xx responses are skipped (`role.rs:1297-1299`). The server side cannot send 1xx other than the automatic 100 Continue and 101 (`role.rs:400-416`).
6. **hyper re-scan on split input:** no. After a partial parse hyper only scans the new bytes for the end of the head (`is_complete_fast`, `role.rs:88-117`; `io.rs:204-218`) and calls httparse once the head is complete. Byte-at-a-time timing was linear (see the hyper table).
7. **h11 bare LF:** accepted in heads and trailers; chunk-size lines need CRLF (`_receivebuffer.py:44`, `:93`, `:126-130`).
8. **h11 obs-fold:** accepted and unfolded with a single space, requests and responses (`_readers.py:40-61`).
9. **h11 CL + TE:** accepted; TE wins (`_connection.py:126-130`).
10. **h11 duplicate CL:** equal values collapsed, differing values refused (`_headers.py:173-184`).
11. **llhttp obs-fold and whitespace before colon by default:** both refused with `HPE_INVALID_HEADER_TOKEN` (probe, llhttp 9.3.0, no lenient flags).
12. **llhttp chunk-extension size limit for CVE-2024-22019:** not in llhttp. It is in Node's binding, `kMaxChunkExtensionsSize = 16384` bytes per chunk line, reset at every chunk header (`node_http_parser.cc:86`, `:576-592`). A body with many chunks each under 16 KiB of extensions is accepted (probe: 40 KB total).
13. **picohttpparser SSE4.2:** yes. `#ifdef __SSE4_2__` includes `nmmintrin.h` (`picohttpparser.c:30-36`); `findchar_fast` uses `_mm_cmpestri` with `_SIDD_CMP_RANGES` (`:113-140`, call at `:123`), used by `ADVANCE_TOKEN` (`:82-84`), `get_token_to_eol` (`:146-153`) and `parse_token` (`:256-268`). No AVX2 code.
14. **picohttpparser LF-only lines:** accepted (see the bare LF row).
15. **`http` crate:** 1.5.0 depends on `bytes` and `itoa` only; not `no_std` (compile error without `std`). `HeaderValue::set_sensitive` makes `Debug` print `Sensitive` (`src/header/value.rs:363-367`).
16. **TechEmpower Round 23 plaintext, may-minihttp:** primary source found: https://www.techempower.com/benchmarks/results/round23/ph.json (run UUID 91a66052-9d86-446c-b31a-eadbd669ed08, "Continuous Benchmarking Run 2025-01-30 18:47:41", environment "Citrine", duration 15 s; the site's JS bundle maps that UUID to Round 23). Best may-minihttp plaintext run: 418,596,352 requests in 15 s = **27,906,423 requests/s**, verification passed. **Rank 10** of 530 frameworks that passed plaintext verification (1 mrhttp 28,384,305; 2 faf; 3 libreactor; 4 pico.v; 5 silverlining-prefork; 6 uwebsockets.js; 7 xitca-web-unrealistic; 8 lithium; 9 libreactor-server; 11 aspnetcore-aot 27,770,995). Caveat: the rank is computed from the raw JSON (max totalRequests / duration, plaintext verify = pass), not read off the rendered page, whose extra display filters could shift it by a place or two. The top ten are within 1.7% of each other, at what looks like the network ceiling of that hardware.

---

## 3. "http-net 1.0" column against the code (crate version 0.8.0)

Every row is implemented in 0.8.0. The claimed Y holds for all 46 rows, with two value refinements (per-field line limit is always on, not opt-in; chunk-extension budget reuses `max_header_bytes`). `cargo test --tests` result: see the end of this file. Paths are relative to the repository root; conformance rows are run by `test_conformance_table_every_row_holds` (`tests/conformance.rs:946`).

| Feature | Verdict | Proving test | Implementation |
|---|---|---|---|
| Sans-IO core | Y | `tests/alloc.rs:187` `test_server_keep_alive_steady_state_allocates_nothing` (socketless `ServerConn`) | `src/server.rs:182`, `src/client.rs:325`; `no_std` without `std` at `src/lib.rs:89` |
| Server side | Y | `tests/rfc_cases.rs:203` `test_rfc_accept_cases_parse_whole_and_bytewise` | `src/server.rs:182`, `:396` |
| Client side | Y | `tests/rfc_cases.rs:816` `test_response_cases` | `src/client.rs:283`, `:978` |
| Zero-copy head views | Y | `tests/alloc.rs:187`; `src/raw.rs:813` `test_owned_head_view_equals_original` | `src/head.rs:1305` `RequestHead<'a>` |
| Linear incremental head parsing | Y | `tests/linearity.rs:58` `test_byte_at_a_time_cost_grows_linearly_with_the_head` (timing), `src/head.rs:2174` `test_scanner_resumes_without_rescanning` (deterministic) | `src/head.rs:212-232` |
| Body decoding (CL, chunked, close) | Y | `tests/rfc_cases.rs:203` ACCEPT table; conformance row at `tests/conformance.rs:465` (until close) | `src/body.rs:17-32`, `:113`, `:183` |
| Connection-owned framing | Y | `tests/smuggling.rs:194` `test_outgoing_messages_cannot_inject_framing`, `:312` | `src/message.rs:134` |
| Bare LF refused | Y | `tests/rfc_cases.rs:600` `test_rfc_reject_cases_produce_exact_errors` (bare LF cases), `tests/smuggling.rs:141`, chunk lines `tests/smuggling.rs:427` | `src/head.rs:227-228` |
| obs-fold refused in requests | Y | `tests/forwarding.rs:133` `test_server_never_tolerates_obs_fold`; `tests/rfc_cases.rs:600` | `src/head.rs:424-425` |
| Whitespace before colon refused | Y | `tests/rfc_cases.rs:600` (space and tab); `tests/smuggling.rs:141` | `src/head.rs:435-436` |
| CL + TE refused | Y | `tests/smuggling.rs:141` (CL.TE, TE.CL); `tests/rfc_cases.rs:600` | `src/head.rs:750-751` `ConflictingFraming` |
| Duplicate equal CL refused | Y | `tests/smuggling.rs:141` "duplicate Content-Length with equal values" | `src/head.rs:682-683` |
| TE must end in single `chunked` | Y | `tests/rfc_cases.rs:600`; `tests/smuggling.rs:356` `test_transfer_encoding_split_across_fields_is_refused` | `src/head.rs:753-757` |
| Chunk extension grammar validated | Y | `tests/smuggling.rs:427` `test_funky_chunks_vectors_split_anywhere_are_refused`; `src/body.rs:565` `test_chunk_line_grammar` | `src/body.rs:321-390` |
| Chunk extension byte budget per message | Y | `tests/adversarial.rs:343` `test_chunk_extensions_are_budgeted_across_the_message`; `tests/alloc.rs:402` | `src/body.rs:230-233` (cumulative, limit is `max_header_bytes`, 16 KiB default) |
| Host required and single | Y | `tests/rfc_cases.rs:600`; `tests/adversarial.rs:114` `test_host_name_case_and_duplicates` | `src/head.rs:914-922` |
| Request-target form vs method | Y | `tests/rfc_cases.rs:600`, `:917`; `src/head.rs:2373` `test_target_forms_follow_method` | `src/head.rs:807-826` `check_target` |
| Trailers received (opt-in) | Y | `tests/trailers.rs:81`, `:98` (off by default), `:213` (client) | `src/server.rs:929`, `src/client.rs:1273` |
| Trailers sent | Y | `tests/trailers.rs:407` `test_trailers_written_by_client_parse_on_server`; `tests/prop_roundtrip.rs:590`, `:622` | `src/server.rs:1364`, `src/client.rs:936` |
| Expect 100-continue server | Y | `tests/adversarial.rs:232` `test_send_continue_then_body_then_final_response` | `src/server.rs:1252` |
| Expect 100-continue client | Y | `tests/interim.rs:214` `test_client_expect_continue_then_body_then_final`, `:254` | `src/client.rs:1326` |
| Interim 1xx sent (103) | Y | `tests/interim.rs:26` `test_server_send_informational_then_final_are_written_in_order` | `src/server.rs:755` |
| Interim 1xx received (opt-in) | Y | `tests/interim.rs:133` `test_client_interim_responses_reported_when_on_skipped_when_off` | `src/client.rs:1244` (budget `max_interim`, default 16) |
| Upgrade hand-off with leftover bytes | Y | `src/server.rs:1661` `test_connect_tunnel` (asserts `remaining_input() == b"TLS"`); `tests/localhost.rs:260` | `src/server.rs:592`, `src/client.rs:1219` |
| 101 checked against offered protocols | Y | `src/client.rs:1434` `test_switching_protocols_must_name_an_offered_protocol`; `tests/adversarial.rs:939`; server side `tests/adversarial.rs:826` | `src/client.rs:1058-1067`, `src/head.rs:615` |
| h2c upgrade ignored | Y | `tests/adversarial.rs:756` `test_h2c_upgrade_is_served_as_http11` | `src/head.rs:585`, `:721` |
| HTTP/2 preface detection | Y | `tests/forwarding.rs:155` `test_h2_preface_at_connection_start_at_every_split` | `src/preface.rs:29`, `src/server.rs:434` |
| Server pipelining, in order | Y | `tests/smuggling.rs:176`; `tests/prop_roundtrip.rs:333` `test_hundred_thousand_pipelined_requests` | `src/server.rs:396` |
| Client pipelining (depth N) | Y | `tests/pipelining_reuse.rs:53` `test_pipelined_gets_responses_match_requests_in_order` | `src/limits.rs:326` (depth 1..=32, default 1; idempotent requests with full bodies only) |
| Keep-alive rules (1.0 / 1.1) | Y | `tests/rfc_cases.rs:203`; conformance rows `tests/conformance.rs:545`, `:563` | `src/head.rs:924-925` |
| Early response closes when body unread | Y | `tests/adversarial.rs:324` `test_answer_at_request_event_with_unread_body_still_closes`; `src/server.rs:1504` | `src/server.rs:529` |
| Header count limit | Y (100) | `tests/rfc_cases.rs:615` `test_limit_cases_at_the_boundary` (100 pass, 101 fail) | `src/limits.rs:79` |
| Header bytes limit | Y (16 KiB) | `tests/rfc_cases.rs:615` | `src/limits.rs:78` |
| Per-field line limit | Y (always on, default 8 KiB, configurable) | `tests/connection_control.rs:377` `test_field_line_at_budget_passes_one_more_is_field_line_too_long` | `src/limits.rs:149`, `src/head.rs:347` |
| Body limit checked before reading | Y | `tests/alloc.rs:433` `test_huge_declared_body_is_refused_on_the_header_line`; `src/body.rs:601` | `src/head.rs:909`, `src/body.rs:196` |
| Date header cache | Y | `src/date.rs:337` `test_date_cache_reformats_only_on_a_new_second`; `tests/connection_control.rs:230` | `src/date.rs:131`, `src/server.rs:659` (caller passes it to `respond_with_date`; the blocking adapter adds it automatically, `src/blocking.rs:2036`) |
| Method registry with safe/idempotent | Y | `src/method.rs:331` `test_method_properties_match_rfc_9110` | `src/method.rs:120`, `:136` |
| Status registry with reasons | Y (61 codes) | `src/status.rs:264` `test_reason_phrase_registry_has_every_iana_code` | `src/status.rs:50` |
| Lenient switches: client-only, one | Y | `tests/forwarding.rs:72` `test_obs_fold_in_response_refused_by_default_replaced_when_lenient` | `src/client.rs:123-155` `ClientLeniency::obs_fold_in_responses` |
| Header case preserved | Y | `tests/rfc_cases.rs:240` `test_header_values_are_trimmed_and_kept_as_bytes` | `src/head.rs:1471` |
| `no_std` (+alloc), CI target | Y | `.github/workflows/ci.yml:54-70` (`--no-default-features --target thumbv7em-none-eabihf`, build only); `ci.yml:39`, `:45` | `src/lib.rs:89`, `:102` |
| Zero runtime deps (parse-net only) | Y | `Cargo.toml` `[dependencies]` is only `parse-net = { version = "0.7", default-features = false }` | |
| Credential redaction in `Debug` | Y | `tests/redaction.rs:59` `test_request_head_headers_and_event_debug_redact_every_spelling` | `src/redact.rs:14-22` (authorization, proxy-authorization, cookie, set-cookie) |
| Allocation-free response writer | Y | `tests/alloc.rs:523` `test_write_head_into_reused_vec_allocates_nothing`, `:570` | `src/write.rs:164`, `:244`, `:292` |
| Standalone chunked decoder | Y | `tests/alloc.rs:608` `test_chunked_decoder_allocates_nothing`; `src/chunked.rs:279` | `src/chunked.rs:94`, `:167`, exported `src/lib.rs:123` |
| Fuzzed | Y | 8 targets in `fuzz/fuzz_targets/` (server_conn, client_conn, chunk_line, reference_diff, httparse_diff, builders, stateless_parse, chunked_decoder); `ci.yml:72-115` runs a 60 s smoke per target on nightly | ROADMAP v0.7.0 records a local 24 CPU-hour campaign per target |

---

## 4. Corrected full matrix

Legend as in the spec. "http-net 0.2.0" column copied unchanged (not in scope). Values marked with a note in brackets carry the qualification found above.

| Feature | http-net 0.2.0 | http-net 1.0 | hyper 1.x | httparse | h11 | llhttp | picohttpparser | `http` crate |
|---|---|---|---|---|---|---|---|---|
| Sans-IO core (bytes in, events out, no runtime) | Y | Y | N (async I/O traits) | Y (head only) | Y | Y (callbacks) | Y (head only) | - |
| Server side | Y | Y | Y | Y | Y | Y | Y | - |
| Client side | Y | Y | Y | Y | Y | Y | Y | - |
| Zero-copy head views | Y | Y | P (values and URI are shared `Bytes` slices; one `HeaderMap` per request) | Y | N (Python objects) | Y (callbacks with pointers) | Y | - |
| Linear incremental head parsing (no re-scan on split input) | Y | Y | Y (end-of-head scan resumes; httparse once) | N (re-parses from start) | Y (saved search offsets) | Y | P (prevbuflen hint) | - |
| Body decoding (CL, chunked, until close) | Y | Y | Y | N (chunk-size helper only) | Y | Y | chunked only | - |
| Serialization with connection-owned framing | Y | Y | Y | N | Y | N | N | - |
| Bare LF refused | Y | Y | N (httparse accepts) | N | N (chunk-size lines need CRLF) | Y (default) | N | - |
| obs-fold refused in requests | Y | Y | Y | Y | N (unfolded) | Y | N (returned as name-less line) | - |
| Whitespace before colon refused | Y | Y | Y (requests) | Y (requests; opt-in allowed in responses) | Y | Y | Y | - |
| CL + TE refused | Y | Y | N (TE wins, CL dropped, connection closed) | - | N (TE wins) | Y (lenient flag to allow) | - | - |
| Duplicate equal CL refused | Y | Y | N (collapsed) | - | N (collapsed) | Y | - | - |
| TE must end in single `chunked` | Y | Y | P (last must be chunked; `chunked, chunked` and `gzip, chunked` pass) | - | Y (only chunked supported) | Y (lenient flag to relax) | - | - |
| Chunk extension grammar validated (Funky Chunks class) | Y | Y | P (refuses bare LF and lone CR only) | - | N (skipped) | P (refuses all line-terminator vectors; accepts empty name) | N (skipped to CR) | - |
| Chunk extension byte budget per message | Y | Y (shares `max_header_bytes`) | Y (16 KiB) | - | N (16 KiB per line via event size) | N (Node.js adds 16 KiB per chunk line) | P (overhead-ratio heuristic) | - |
| Host required and single (HTTP/1.1) | Y | Y | N (application's job) | N | Y (required) | N | N | - |
| Request-target form checked against method | Y | Y | N | N | N | P (authority-form refused outside CONNECT) | N | - |
| Trailers received | P (validated, discarded) | Y (opt-in) | Y (forbidden fields not filtered) | - | Y | Y | Y (raw) | - |
| Trailers sent | N | Y | Y (only fields named in `Trailer`) | - | Y | - | - | - |
| `Expect: 100-continue` server | Y | Y | Y (sent when body is polled) | - | Y | - | - | - |
| `Expect: 100-continue` client | N | Y | N (body sent at once) | - | Y | - | - | - |
| Interim 1xx sent (103) | N (100, 101 only) | Y | N (automatic 100 and 101 only) | - | Y | - | - | - |
| Interim 1xx received and reported | P (skipped) | Y (opt-in) | Y (opt-in `ext::on_informational`) | Y | Y | Y | Y | - |
| Upgrade hand-off with leftover bytes | Y | Y | Y | - | Y (`trailing_data`) | Y (`HPE_PAUSED_UPGRADE`) | - | - |
| 101 checked against offered protocols | N | Y | N | - | P (an offer must exist; names not compared) | - | - | - |
| h2c upgrade ignored | N | Y | Y (served as HTTP/1.1 unless the application answers 101) | - | - | - | - | - |
| HTTP/2 preface detection | N (505) | Y | Y (served with `http2` feature; detected and closed in http1-only) | - | - | - | - | - |
| Server pipelining, in-order responses | Y | Y | Y | - | Y | Y (parser) | - | - |
| Client pipelining | N | Y (depth N) | N | - | N | Y (parser) | - | - |
| Keep-alive rules (1.0 / 1.1) | Y | Y | Y | - | Y | Y | - | - |
| Early response closes when body unread | Y | Y | Y (closes if body not yet received) | - | P (no auto close; reuse refused until body done) | - | - | - |
| Header count limit | Y (100) | Y (100) | Y (100) | Y (caller array) | N | N | Y (caller array) | - |
| Header bytes limit | Y (16 KiB) | Y (16 KiB) | Y (`max_header_size`, `max_buf_size`) | N | Y (16 KiB event size) | N (application; Node.js 16 KiB) | N | - |
| Per-field line limit | N | Y (always on, 8 KiB default) | N | N | N | N | N | - |
| Body limit checked before reading | Y | Y | N (application) | - | N | N | - | - |
| Date header cache | P (per response, blocking only) | Y | Y (`auto_date_header`) | - | N | - | - | - |
| Method registry with safe/idempotent | P (enum) | Y | Y (`http::Method`, `is_safe`, `is_idempotent`) | - | N | Y (method enum) | N | Y |
| Status registry with reasons | P (47 codes) | Y (61 codes) | Y (`http::StatusCode`) | - | N | Y (`HTTP_STATUS_MAP`, `llhttp_status_name`) | - | Y |
| Lenient switches | N | client-only, one switch | Y (several) | Y (several) | N | Y (eleven in 9.4.3; ten in 9.3.0) | N | - |
| Header case preserved | Y (views) | Y | opt (`preserve_header_case`) | Y | N (lowercased) | Y | Y | N (lowercased) |
| `no_std` | Y (+alloc) | Y (+alloc), CI target | N | Y | - | Y (C) | Y (C) | N |
| Zero runtime dependencies | Y | Y (first-party parse-net only) | N | Y | Y | Y | Y | N (`bytes`, `itoa`) |
| Credential redaction in `Debug` | N | Y | N | - | - | - | - | P (`HeaderValue::set_sensitive`) |
| Allocation-free response writer | N | Y | N | - | N | - | - | - |
| Standalone chunked decoder | N | Y | N (internal) | P (size only) | N | Y | Y | - |
| Fuzzed | N (property tests) | Y | N (httparse underneath is) | Y | Y | Y | P (indirectly, via h2o on OSS-Fuzz) | Y (OSS-Fuzz `fuzz_http`) |

No [u] is left. Nothing was undeterminable.

---

## 5. Existing (non-[u]) values that turned out wrong or need qualification

1. **`http` crate, Fuzzed: "-" should be Y.** The `http` crate is fuzzed on OSS-Fuzz: `projects/hyperium` has `main_repo: https://github.com/hyperium/http` and its `build.sh` builds `fuzz_http` from http's `fuzz/` directory (google/oss-fuzz at ea7eeb3e). It parses URIs, header names and values, so fuzzing applies.
2. **http-net 1.0, Per-field line limit: "Y (opt)" should be "Y (always on)".** The limit is not opt-in: it is enforced by default at 8 KiB and only its size is configurable (`src/limits.rs:149`, `src/head.rs:347`; `tests/connection_control.rs:377`).
3. **llhttp, Lenient switches: "Y (eleven)" is version-dependent.** Eleven `llhttp_set_lenient_*` functions exist in llhttp 9.4.3 (`include/llhttp.h`, `header_value_relaxed` at line 917); llhttp 9.3.0, which Node.js 24.14.1 ships, has ten (no `header_value_relaxed`; `deps/llhttp/include/llhttp.h:779-899` and the `llhttp_lenient_flags` enum at `:111-122`). Section 9's prose list of eleven matches 9.4.x.
4. **hyper, HTTP/2 preface detection: "Y (with `http2` feature)" is incomplete.** Without the `http2` feature, hyper's http1 server still detects the preface and closes the connection with `Parse(VersionH2)` and no response (probe). With the feature (and hyper-util's auto builder) it serves HTTP/2.
5. **hyper, Trailers received: Y is right, but hyper does not filter fields that RFC 9110 forbids in trailers** (probe: `Content-Length: 3` in a trailer section reached the application). Worth a note if the matrix is used to argue strictness.
6. **hyper, Header bytes limit: Y is right, but the default `max_header_size` is unset;** the effective default bound is `max_buf_size` (about 400 KB). Probe: a single 300 KiB field line was accepted.
7. **http-net 1.0, Chunk extension byte budget: Y is right, but there is no separate knob;** the cumulative budget reuses `max_header_bytes` (16 KiB default; `src/body.rs:230-233`).

The cells the previous draft marked Y [u] that turned out not Y are listed in section 1 (hyper: interim 1xx sent is N, TE single chunked is P, fuzzed is N; llhttp: chunk extension budget is N in llhttp itself, chunk extension grammar is P). They were unverified, so they are not repeated here.


## 6. http-net test run

`cargo test -j 4 --tests` on http-net 0.8.0 (Windows): all passed. 116 unit tests in `src/`, and 245 integration tests across 20 files (adversarial 36, alloc 21, conformance 2, connection_control 15, forwarding 11, head_only 3, interim 13, linearity 2, localhost 30, pipelining_reuse 14, prop_httparse 7, prop_httparse_response 9, prop_reference 3, prop_roundtrip 17, prop_stateless 5, prop_writer 3, redaction 7, rfc_cases 19, smuggling 8, trailers 20). 361 tests in total, 0 failed, 0 ignored. Fuzz targets were not run.
