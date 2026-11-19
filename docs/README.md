<div align="center">
        <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <h1>
        <strong>http-net</strong>
        <sup>
            <br>
            <sub>DOCUMENTATION</sub>
            <br>
        </sup>
    </h1>
</div>
<div align="center">
    <sup>
        <a href="../README.md" title="Project Home"><b>HOME</b></a>
        <span>&nbsp;│&nbsp;</span>
        <span>DOCS</span>
        <span>&nbsp;│&nbsp;</span>
        <a href="./API.md" title="API Reference"><b>API</b></a>
    </sup>
</div>
<br>

## Guides

- [API reference](./API.md): every public item, with examples.
- [Architecture](./ARCHITECTURE.md): modules, state machines, framing, and how memory is bounded.
- [Security](./SECURITY.md): the threat model, each threat with its defence and its test.
- [Performance](./PERFORMANCE.md): how it is measured, how it compares with httparse and hyper, and the decisions behind the numbers.
- [Parity](./PARITY.md): feature-by-feature comparison with hyper, httparse, h11, llhttp, picohttpparser and the `http` crate.
- [Platform notes](./PLATFORM-NOTES.md): what differs between operating systems and targets.
- [Stability](./STABILITY-1.0.md): what 1.0 commits to and the audit it ships on.
- [Migration guide](./MIGRATION.md): moving between versions.
- [Release notes](./release/): one file per release.
- [Changelog](../CHANGELOG.md)

## Help

- Issues: <https://github.com/jamesgober/http-net/issues>
- MSRV: Rust 1.85. The only feature flag is `std` (on by default); see
  [`Cargo.toml`](../Cargo.toml).

<br>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>JAMES GOBER.</strong></sup>
</div>
