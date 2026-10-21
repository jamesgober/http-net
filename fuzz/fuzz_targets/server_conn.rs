//! `ServerConn` on arbitrary bytes, split by a fuzzer-chosen schedule, under
//! fuzzer-chosen limits. Oracles: no panic; the buffer never exceeds its
//! capacity and never fills while the parser waits; after an error only
//! `Closed` is reported and exactly one response can be sent; the events
//! are identical to those of the same input fed whole.

#![no_main]

use arbitrary::Arbitrary;
use http_net_fuzz::{drive_server, limits_from, split};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    limits: Option<(u16, u16, u8, u16)>,
    cuts: Vec<u16>,
    data: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let limits = limits_from(input.limits);
    let whole = drive_server(&[&input.data], limits);
    let pieces = split(&input.data, &input.cuts);
    let split_run = drive_server(&pieces, limits);
    assert_eq!(whole, split_run, "events depend on how the input was split");
});
