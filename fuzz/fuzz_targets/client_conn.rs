//! `ClientConn` reading arbitrary response bytes after a request of a
//! fuzzer-chosen kind (GET, HEAD, CONNECT, or an upgrade), split by a
//! fuzzer-chosen schedule, under fuzzer-chosen limits. Oracles as for
//! `server_conn`: no panic, bounded buffer, only `Closed` after an error,
//! and events identical to the whole-input run.

#![no_main]

use arbitrary::Arbitrary;
use http_net::Request;
use http_net_fuzz::{drive_client, limits_from, split};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Kind {
    Get,
    Head,
    Connect,
    Upgrade,
}

#[derive(Arbitrary, Debug)]
struct Input {
    kind: Kind,
    limits: Option<(u16, u16, u8, u16)>,
    cuts: Vec<u16>,
    data: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let request = match input.kind {
        Kind::Get => Request::get("/").header("host", "a"),
        Kind::Head => Request::new("HEAD", "/").header("host", "a"),
        Kind::Connect => Request::new("CONNECT", "a:443").header("host", "a:443"),
        Kind::Upgrade => Request::get("/").header("host", "a").upgrade("websocket"),
    };
    let limits = limits_from(input.limits);
    let whole = drive_client(&request, &[&input.data], limits);
    let pieces = split(&input.data, &input.cuts);
    let split_run = drive_client(&request, &pieces, limits);
    assert_eq!(whole, split_run, "events depend on how the input was split");
});
