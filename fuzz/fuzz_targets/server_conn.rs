//! `ServerConn` on arbitrary bytes, split by a fuzzer-chosen schedule, under
//! fuzzer-chosen limits (start line, header section, field count, body,
//! field line, trailer section and count) and options (trailers reported,
//! keep-alive switched off, a `103` before each answer). Oracles: no panic;
//! the buffer never exceeds its capacity and never fills while the parser
//! waits; after an error only `Closed` is reported and exactly one response
//! can be sent; trailers are reported only when asked for; a `103` is
//! accepted for HTTP/1.1 and refused for HTTP/1.0; `requests_served` counts
//! every answer; the events are identical to those of the same input fed
//! whole.

#![no_main]

use arbitrary::Arbitrary;
use http_net_fuzz::{Options, RawLimits, drive_server_with, limits_from, split};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    limits: Option<RawLimits>,
    options: Options,
    cuts: Vec<u16>,
    data: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let limits = limits_from(input.limits);
    let whole = drive_server_with(&[&input.data], limits, input.options);
    let pieces = split(&input.data, &input.cuts);
    let split_run = drive_server_with(&pieces, limits, input.options);
    assert_eq!(whole, split_run, "events depend on how the input was split");
});
