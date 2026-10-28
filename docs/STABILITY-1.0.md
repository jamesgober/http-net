# http-net - Stability (1.0)

> What http-net 1.0.0 commits to, what a 1.x release may change, what only a
> 2.0 may change, and the audit that 1.0.0 is released on. **Draft (0.9.0):**
> the API is frozen as the 1.0 candidate; the audit record at the end is
> filled in as each part is done, and 1.0.0 ships only when every part is
> recorded and James approves the release.

## What 1.0 means here

From 1.0.0, every public item in [`docs/API.md`](API.md) marked "exists" is
under semantic versioning:

- **Patch (`1.0.x`):** fixes only. No API change. A fix may refuse a message
  that was accepted before when accepting it is a security defect (a message
  two implementations could frame differently, a limit that was not
  enforced); every such change is listed under **Security** in
  `CHANGELOG.md`.
- **Minor (`1.x.0`):** additions only: new functions, methods, types,
  `HttpError` variants, `Limits` settings, enum variants of the
  `#[non_exhaustive]` enums, and the items `docs/API.md` lists as "after
  1.0". Existing items keep their signatures, their defaults, and their
  behaviour.
- **Major (`2.0.0`):** anything else: a removed or renamed item, a changed
  signature, a changed default limit, a message accepted in 1.x that a
  2.0 refuses for a reason other than security, a raised MSRV.

A deprecated item stays for the whole 1.x series and names its replacement.

## The frozen surface

The complete list, with signatures, errors, and examples, is
[`docs/API.md`](API.md). In summary:

| Area | Items |
|---|---|
| Connections | `ServerConn`, `ServerEvent`, `Progress`; `ClientConn`, `ClientEvent`, `ClientLeniency` |
| Views | `RequestHead`, `ResponseHead`, `Headers`, `HeaderValues`, `ListElements`, `Version`, `BodyFraming`, `TargetForm` |
| Builders | `Request`, `Response` |
| Allocation-free tier | `RawHead`, `Span`, `FieldSpan`, `HeadFacts`, `OwnedRequestHead`, `parse_request_head`, `parse_response_head`, `Asked`, `Parsed`, `ParsedRequest`, `ParsedResponse`, `ChunkedDecoder`, `ChunkStep`, `Output`, `ResponseHeadRef`, `OutgoingBody`, `BodyPlan` |
| Vocabulary | `Method`, `MethodSet`, `status` (constants, `StatusClass`, `reason_phrase`, `status_class`, `status_allows_body`), `HttpDate`, `DateCache`, `is_hop_by_hop`, `is_h2_preface`, `VERSION` |
| Configuration and errors | `Limits` (every setting and its default), `HttpError` (every variant, `is_peer_error`, `is_usage_error`, `status`) |
| `blocking` (feature `std`) | `Server`, `ServerConfig`, `ShutdownHandle`, `Incoming`, `Connection`, `Upgraded`, `Client`, `ClientResponse`, `Error`, `get`, `post`, `serve`, `now_date` |

Which types may grow in 1.x is decided at the freeze (`dev/PLAN.md` D-63):

- Every public enum is `#[non_exhaustive]`: a match needs a wildcard arm,
  and a new variant is a minor release.
- `ClientLeniency` and `blocking::Upgraded` are `#[non_exhaustive]` structs:
  a new field is a minor release.
- `Asked`, `ResponseHeadRef`, `Span`, and `FieldSpan` are built by callers
  with struct literals and stay exactly as they are for all of 1.x.
- Every other public struct has private fields; new methods are a minor
  release.

## Behaviour guarantees

- **Strict framing.** A message that two conforming implementations could
  frame differently is refused with a specific `HttpError`, never repaired.
  The table of such refusals is in [`docs/SECURITY.md`](SECURITY.md). A 1.x
  release never starts accepting one of them.
- **Bounded memory.** Every buffer is bounded by a `Limits` setting, checked
  before the bytes it governs are buffered. Defaults change only in 2.0.
- **No panics on input.** No byte sequence from a peer makes the crate
  panic; refused input is an `Err`. Checked by eight fuzz targets (24
  CPU-hours each in 0.7, 60 seconds each on every CI run).
- **No `unsafe` code** (`#![forbid(unsafe_code)]`) in the crate, for all of
  1.x.
- **Allocation.** The core allocates nothing per request after warm-up on a
  keep-alive connection, and the allocation-free tier allocates nothing
  ever; both are proved by counting-allocator tests (`tests/alloc.rs`).
- **Output bytes.** The bytes the crate writes for a given response or
  request are stable within a minor series; a minor release may change
  them only in ways RFC 9112 makes equivalent (field order of the crate's
  own fields, for example), and says so in `CHANGELOG.md`.

## Dependencies and platforms

- **Runtime dependencies:** the first-party crate `parse-net` only, by
  published version, with no features. A third-party runtime dependency is
  a 2.0 change, except the optional `http-types` feature planned after 1.0,
  which is never a default.
- **`no_std`:** the crate builds without `std` (it needs `alloc`), checked
  in CI on `thumbv7em-none-eabihf`. The `blocking` module needs `std`.
- **Platforms:** tested in CI on Linux x86_64, Windows x86_64, and macOS
  (the runners' aarch64), stable and the MSRV. The core is portable Rust
  with no platform code; only `blocking` touches the operating system,
  through `std::net`.

## MSRV policy

The minimum supported Rust version is 1.85. It is tested in CI on every
platform. Raising it is a 2.0 change.

## Support

**Open, for James's decision at 1.0:** how long a 1.x minor release
receives security fixes after its successor ships, and the private channel
for reporting a security problem (for example GitHub's private
vulnerability reporting on the repository). Until then, fixes go to the
latest release only.

## How this contract is checked

- `cargo semver-checks` against the previous release before every release
  from 0.9.1 on; a patch release must report no semver change.
- CI builds and tests every feature mode on Rust stable and 1.85 on Linux,
  macOS, and Windows, and the `no_std` target.
- `docs/API.md` is checked against the build before every release.

## The 1.0 audit

Each part records what was checked, how, and the result. 1.0.0 ships when
every part says **done**, the 0.9 exit criteria hold (two consecutive weeks
without an API change after 0.9.0, D-66; the full documentation set; local
gate and CI green on every platform and the MSRV), and James approves.

### API

- Frozen at 0.9.0 (D-63). One change at the freeze: `blocking::Upgraded`
  became `#[non_exhaustive]`.
- Every public item has rustdoc with a runnable example, and an entry in
  `docs/API.md`.
- **Status:** freeze done; two-week clock running from the 0.9.0 release.

### Documentation

- Every factual claim in the README, `docs/`, the changelog, and the
  rustdoc was re-checked against the build at 0.9.0.
- **Status:** in progress for 0.9.0.

### Tests

- Unit, integration, property, differential (an independent reference
  parser, httparse on requests and responses), counting-allocator, and
  socket tests; every threat T-1 to T-42 has an attack test
  (`docs/SECURITY.md`).
- **Status:** green at 0.8.0; re-run for 0.9.0.

### Benchmarks

- Measured numbers, method, and hardware in
  [`docs/PERFORMANCE.md`](PERFORMANCE.md) (0.6.0); the comparison
  repository is [`http-net-bench`](https://github.com/jamesgober/http-net-bench).
  0.7 and 0.8 showed no measurable change against 0.6 (`dev/PLAN.md` D-61).
- Head parsing is at parity with httparse, not 20% ahead: the shortfall and
  its cause are published (D-54).
- **Status:** done for the frozen code; re-checked before 1.0.

### Security

- Fuzz campaign (24 CPU-hours per target, no finding), 8-hour soak (+3.4%
  memory after warm-up), threat audit (T-21 fixed), response-side
  differential: `docs/SECURITY.md`, hardening record.
- HTTP Garden: not yet run (D-58).
- **Status:** open until the Garden results are triaged.

### Parity with other implementations

- The parity matrix of the specification compared with hyper, httparse,
  h11, llhttp, picohttpparser, and the `http` crate.
- **Status:** in progress for 0.9.0.

### Consumers

- serve-net and LexerSketch Studio run end to end against 0.8 with no
  change (D-62). The WASP gateway skeleton and the first fetch-net do not
  exist yet. The specification also asks for LexerSketch Studio's publish
  step to use the API end to end before 1.0.
- **Status:** open.
