//! Differential check against the independent reference parser: on any
//! input, the crate and the reference agree on whether the first request
//! is valid and, if it is, on its method, target, version, fields, and
//! body.

#![no_main]

use http_net_fuzz::reference::{crate_first, reference};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Below every byte budget, which the reference does not model.
    if data.len() >= 8000 {
        return;
    }
    assert_eq!(
        reference(data),
        crate_first(data),
        "input {:?}",
        String::from_utf8_lossy(data)
    );
});
