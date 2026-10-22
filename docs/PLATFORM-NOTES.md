# http-net - Platform notes

What differs between operating systems and targets, and what the crate does
about it. The sans-IO core has no platform code at all; everything here is
about the `blocking` adapter (feature `std`), the build, and the tooling.

## The core is the same everywhere

The core (`ServerConn`, `ClientConn`, the Tier-3 parsers and writers) has no
`cfg(unix)` or `cfg(windows)` code, no I/O, and no clock: the same bytes
give the same events and errors on every platform and however they are
split (NFR-13). CI runs the whole test suite on Linux, macOS, and Windows,
each on Rust stable and the 1.85 MSRV.

## Socket timeouts

`blocking` sets read and write timeouts on its sockets. When one expires,
the error kind depends on the platform:

| Platform | Expired `SO_RCVTIMEO` / `SO_SNDTIMEO` reported as |
|---|---|
| Linux, macOS, other Unix | `io::ErrorKind::WouldBlock` (`EAGAIN`) |
| Windows | `io::ErrorKind::TimedOut` (`WSAETIMEDOUT`) |

`blocking` treats both as a timeout (`is_timeout`). A timeout that ran into
the request deadline is answered `408` (server) or reported as a timed-out
exchange (client); one that ran into the response deadline ends the
connection.

On Windows a socket whose send or receive timed out is, by the Winsock
documentation, in an indeterminate state. `blocking` never reuses one: a
timed-out connection is answered (at most the `408`) and closed.

## Closing with unread data: lingering close

When a socket is closed while received data is still unread, Linux, the
BSDs and macOS, and Windows all send a reset (RST) instead of a normal
close (RFC 1122 section 4.2.2.13 allows it). A reset can make the peer
discard a response it has not read yet, so a client that sent a request
body the server did not read would lose the server's answer.

`blocking` therefore closes the way RFC 9112 section 9.6 describes: it
shuts down its sending side, then reads and discards what the peer is still
sending, at most 256 KiB and at most one second in total (250 ms per read),
before closing. The refusal path of a full server (`503`) only drains what
has already arrived, without waiting, so it never stalls the accept loop.

## Ports and TIME_WAIT

The side that closes a TCP connection first keeps it in TIME_WAIT for twice
the maximum segment lifetime, holding the port pair:

| Platform | TIME_WAIT | Default client (ephemeral) ports |
|---|---|---|
| Linux | 60 s | 32768 to 60999 (about 28,000) |
| Windows | 120 s by default, up to 240 s on some versions | 49152 to 65535 (about 16,000) |

A client that opens and closes connections in a tight loop can exhaust its
ephemeral ports in well under a minute on Windows, after which `connect`
fails or stalls. This is a property of the client machine, not of the
server. Keep connections alive (`blocking::Client` and `ClientConn` reuse
them), and when load-testing, pace new connections; the soak test
(`examples/soak.rs`) runs most of its traffic on long keep-alive
connections for this reason.

## Memory measurements

The crate forbids `unsafe`, so it cannot query its own memory use on every
platform. The soak test reads its resident set from `/proc/self/statm` on
Linux; on Windows and macOS sample the process from outside (for example
`Get-Process` working set and private bytes on Windows, `ps -o rss` on
macOS).

## `no_std` targets

With default features off (`--no-default-features`) the crate builds for
`no_std` targets that have an allocator: it uses `core` and `alloc` only.
CI builds `thumbv7em-none-eabihf` (Cortex-M4F) on stable and 1.85 on every
push; any target with `alloc` should work. The binary still needs a
global allocator from the application. `blocking` and anything that touches
the clock or sockets need `std`.

## Fuzzing

The fuzz targets (`fuzz/`) use libFuzzer through `cargo fuzz` with
AddressSanitizer:

- **Linux** (CI and local): `cargo +nightly fuzz run --target
  x86_64-unknown-linux-gnu <target>`. CI uses this explicit target because
  a prebuilt `cargo-fuzz` may default to musl, which has no sanitizer
  runtime.
- **Windows**: works with the MSVC toolchain when the folder holding
  `clang_rt.asan_dynamic-x86_64.dll` (in the Visual Studio `VC\Tools\MSVC\
  <version>\bin\Hostx64\x64` folder) is on `PATH`. It runs about ten times
  slower per input than Linux. Each libFuzzer worker reserves a large
  amount of virtual memory, so many parallel workers can exhaust the
  system's commit limit when the page file cannot grow.

## Build caches on exFAT and FAT drives

Cargo hard-links its incremental compilation cache. On a drive that does
not support hard links (exFAT, FAT32) it prints a warning and copies
instead; builds are correct but slower. `CARGO_INCREMENTAL=0` avoids the
warning for release and benchmark builds.
