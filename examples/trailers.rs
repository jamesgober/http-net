//! Trailer fields both ways, in memory: a client uploads a chunked body and
//! sends its digest as a trailer (it is known only at the end); the server
//! asks for trailers to be reported, reads the digest, and answers with a
//! streamed body whose timing goes in a trailer of its own.
//!
//! ```sh
//! cargo run --example trailers
//! ```

use http_net::{ClientConn, ClientEvent, HttpError, Request, Response, ServerConn, ServerEvent};

fn main() -> Result<(), HttpError> {
    let mut client = ClientConn::new();
    client.set_report_trailers(true);
    let mut to_server = Vec::new();
    let upload = Request::put("/files/log.txt")
        .header("host", "localhost")
        .header("te", "trailers")
        .chunked();
    client.send_request(&upload, &mut to_server)?;
    client.send_body(b"line 1\nline 2\n", &mut to_server)?;
    client.end_body_with_trailers(&[("content-digest", b"sha-256=:aGVsbG8=:")], &mut to_server)?;

    let mut server = ServerConn::new();
    server.set_report_trailers(true);
    let mut to_client = Vec::new();
    let _ = server.feed(&to_server);
    loop {
        match server.poll()? {
            ServerEvent::Request(head) => {
                println!("server: {} {}", head.method_str(), head.target())
            }
            ServerEvent::Body(chunk) => println!("server: {} body bytes", chunk.len()),
            ServerEvent::Trailers(fields) => {
                for (name, value) in fields {
                    println!("server: trailer {name}: {}", String::from_utf8_lossy(value));
                }
            }
            ServerEvent::RequestEnd => break,
            other => println!("server: other event: {other:?}"),
        }
    }
    server.respond(&Response::new(201).chunked(), &mut to_client)?;
    server.send_body(b"stored", &mut to_client)?;
    server.end_body_with_trailers(&[("server-timing", b"disk;dur=3")], &mut to_client)?;

    let _ = client.feed(&to_client);
    loop {
        match client.poll()? {
            ClientEvent::Response(head) => println!("client: {}", head.status()),
            ClientEvent::Body(chunk) => println!("client: {}", String::from_utf8_lossy(chunk)),
            ClientEvent::Trailers(fields) => {
                for (name, value) in fields {
                    println!("client: trailer {name}: {}", String::from_utf8_lossy(value));
                }
            }
            ClientEvent::ResponseEnd => break,
            other => println!("client: other event: {other:?}"),
        }
    }
    Ok(())
}
