//! One chunk-size line, driven through a chunked request on `ServerConn`,
//! whole and one byte at a time. Oracles: no panic; the result does not
//! depend on the split; the crate accepts the line exactly when the
//! reference grammar does; an accepted line decodes to a body of the
//! declared size.

#![no_main]

use http_net::Limits;
use http_net_fuzz::{Ev, drive_server, reference::chunk_size};
use libfuzzer_sys::fuzz_target;

/// Larger declared sizes are not followed by data; the line is still
/// parsed and must not panic.
const MAX_DATA: u64 = 64 * 1024;

/// The decoded body length, if the request ended.
fn body_len(events: &[Ev]) -> Option<usize> {
    let mut len = 0;
    for e in events {
        match e {
            Ev::Body(b) => len += b.len(),
            Ev::End => return Some(len),
            _ => {}
        }
    }
    None
}

fuzz_target!(|line: &[u8]| {
    // A CRLF inside the input ends the line early, so it is no longer one
    // line; a bare LF or CR stays in and must be refused.
    if line.len() > 4096 || line.windows(2).any(|w| w == b"\r\n") {
        return;
    }
    let size = chunk_size(line);
    let mut input = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    input.extend_from_slice(line);
    input.extend_from_slice(b"\r\n");
    let data = size.filter(|&n| n > 0 && n <= MAX_DATA);
    if let Some(n) = data {
        input.extend(std::iter::repeat_n(b'x', n as usize));
        input.extend_from_slice(b"\r\n");
    }
    if size != Some(0) {
        input.extend_from_slice(b"0\r\n");
    }
    input.extend_from_slice(b"\r\n");

    let whole = drive_server(&[&input], Limits::new());
    let bytewise: Vec<&[u8]> = input.chunks(1).collect();
    assert_eq!(
        whole,
        drive_server(&bytewise, Limits::new()),
        "the split changed the result"
    );

    let body = body_len(&whole);
    match size {
        Some(0) => assert_eq!(body, Some(0), "a valid last-chunk line was refused"),
        Some(n) if n <= MAX_DATA => {
            assert_eq!(
                body,
                Some(n as usize),
                "a valid line decoded to the wrong size"
            );
        }
        // Valid but larger than the data fed: the body cannot complete.
        Some(_) => assert_eq!(body, None),
        None => assert_eq!(body, None, "the crate accepted a line the grammar refuses"),
    }
});
