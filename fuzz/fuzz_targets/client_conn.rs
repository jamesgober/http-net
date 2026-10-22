//! `ClientConn` reading arbitrary response bytes after a request of a
//! fuzzer-chosen kind (GET, HEAD, CONNECT, an upgrade, or a 4-byte upload
//! with `Expect: 100-continue`), split by a fuzzer-chosen schedule, under
//! fuzzer-chosen limits (including the interim count and trailer budgets)
//! and options (interim responses and trailers reported). Oracles as for
//! `server_conn`: no panic, bounded buffer, only `Closed` after an error,
//! interim responses and trailers reported only when asked for, and events
//! identical to the whole-input run.

#![no_main]

use arbitrary::Arbitrary;
use http_net::Request;
use http_net_fuzz::{Options, RawLimits, drive_client_with, limits_from, split};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Kind {
    Get,
    Head,
    Connect,
    Upgrade,
    ExpectContinue,
}

#[derive(Arbitrary, Debug)]
struct Input {
    kind: Kind,
    limits: Option<RawLimits>,
    options: Options,
    cuts: Vec<u16>,
    data: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let request = match input.kind {
        Kind::Get => Request::get("/").header("host", "a"),
        Kind::Head => Request::new("HEAD", "/").header("host", "a"),
        Kind::Connect => Request::new("CONNECT", "a:443").header("host", "a:443"),
        Kind::Upgrade => Request::get("/").header("host", "a").upgrade("websocket"),
        Kind::ExpectContinue => Request::put("/")
            .header("host", "a")
            .content_length(4)
            .expect_continue(),
    };
    let limits = limits_from(input.limits);
    let whole = drive_client_with(&request, &[&input.data], limits, input.options);
    let pieces = split(&input.data, &input.cuts);
    let split_run = drive_client_with(&request, &pieces, limits, input.options);
    assert_eq!(whole, split_run, "events depend on how the input was split");
});
