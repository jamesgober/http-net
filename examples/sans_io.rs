//! The sans-IO core without any socket: bytes in, events out, response
//! bytes back. This is the loop every adapter (blocking, event loop, test)
//! wraps.
//!
//! ```sh
//! cargo run --example sans_io
//! ```

use http_net::{HttpError, Response, ServerConn, ServerEvent};

fn main() -> Result<(), HttpError> {
    // Two pipelined requests, arriving in awkward pieces.
    let wire: &[&[u8]] = &[
        b"POST /notes HTTP/1.1\r\nHost: local",
        b"host\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r",
        b"\n0\r\n\r\nGET /notes HTTP/1.1\r\nHost: localhost\r\n\r\n",
    ];
    let mut conn = ServerConn::new();
    let mut out = Vec::new();
    let mut body = Vec::new();
    let mut pieces = wire.iter();
    loop {
        match conn.poll()? {
            ServerEvent::Request(req) => println!("request: {} {}", req.method_str(), req.target()),
            ServerEvent::Body(chunk) => body.extend_from_slice(chunk),
            ServerEvent::RequestEnd => {
                println!("  body: {:?}", String::from_utf8_lossy(&body));
                body.clear();
                conn.respond(&Response::text(200, "ok"), &mut out)?;
            }
            ServerEvent::NeedInput => match pieces.next() {
                Some(piece) => {
                    let taken = conn.feed(piece);
                    assert_eq!(taken, piece.len());
                }
                None => conn.feed_eof(),
            },
            ServerEvent::Closed => break,
            other => println!("other event: {other:?}"),
        }
    }
    println!(
        "wrote {} response bytes:\n{}",
        out.len(),
        String::from_utf8_lossy(&out)
    );
    Ok(())
}
