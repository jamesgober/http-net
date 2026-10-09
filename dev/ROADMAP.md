# http-net - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Master plan: C:/Dev/libraries/Rust/lang-collection/_lexersketch/ROADMAP.md and NEW-LIBS.md
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.

## v0.1.0 - Scaffold (DONE)
Compiles, CI green, structure correct, no domain logic.
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP.

## v0.2.0 - Foundation
- [ ] Sans-IO request/response parser and serializer, keep-alive, chunked bodies, server and client state machines, a blocking std adapter; smuggling and fuzz-style property tests.

## v0.5.0 - Implementation
- [ ] Pipelining, Expect: 100-continue, an async adapter, upgrade hand-off (for ws-net).

## v0.9.0 - Hardening
- [ ] Fuzzing; conformance tests.

## v1.0.0 - Stable
- [ ] Frozen after LexerSketch Studio and ls-publish use it (D18).
