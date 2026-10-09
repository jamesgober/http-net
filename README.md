<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>http-net</b>
    <br>
    <sub><sup>HTTP/1.1, SANS-IO</sup></sub>
</h1>

<div align="center">
    <a href="https://crates.io/crates/http-net"><img alt="Crates.io" src="https://img.shields.io/crates/v/http-net"></a>
    <a href="https://crates.io/crates/http-net"><img alt="Downloads" src="https://img.shields.io/crates/d/http-net?color=%230099ff"></a>
    <a href="https://docs.rs/http-net"><img alt="docs.rs" src="https://img.shields.io/docsrs/http-net"></a>
    <a href="https://github.com/jamesgober/http-net/actions"><img alt="CI" src="https://github.com/jamesgober/http-net/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</div>

<br>

<div align="left">
    <p>
        <strong>http-net</strong> is an HTTP/1.1 engine that does no I/O itself: feed it bytes, get requests or responses back, and hand it responses to serialize. Parsing is strict and every buffer is bounded, so hostile clients cannot exhaust memory. Keep-alive, chunked transfer encoding, and pipelining are handled; the caller owns sockets and threads.
    </p>
    <br>
    <hr>
    <p>
        <strong>MSRV is 1.85+</strong> (Rust 2024 edition).
    </p>
    <blockquote>
        <strong>Status: pre-1.0, in active development.</strong> The public API is being designed across the 0.x series and frozen at <code>1.0.0</code>. See <a href="./CHANGELOG.md"><code>CHANGELOG.md</code></a>.
    </blockquote>
</div>

<hr>
<br>

## Installation

```toml
[dependencies]
http-net = "0.1"
```

<br>

## Status

This is the <code>v0.1.0</code> scaffold: structure, tooling, and quality gates are in place; the implementation lands across the 0.x series per the <a href="./dev/ROADMAP.md"><code>ROADMAP</code></a> and <a href="./docs/API.md"><code>docs/API.md</code></a>.

<hr>
<br>

## Contributing

See <a href="./dev/DIRECTIVES.md"><code>dev/DIRECTIVES.md</code></a> for engineering standards and the definition of done. Before a PR: `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features` must be clean.

<br>

<div id="license">
    <h2>License</h2>
    <p>Licensed under either of</p>
    <ul>
        <li><b>Apache License, Version 2.0</b> &mdash; <a href="./LICENSE-APACHE">LICENSE-APACHE</a></li>
        <li><b>MIT License</b> &mdash; <a href="./LICENSE-MIT">LICENSE-MIT</a></li>
    </ul>
    <p>at your option.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
