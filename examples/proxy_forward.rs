//! A reverse proxy's forwarding step, in memory: a request arrives on a
//! server connection, is rebuilt for the upstream with
//! `Request::forward_from` (hop-by-hop fields dropped, framing kept), gets
//! a `via` field, and is written by a client connection. The upstream's
//! answer is read back and forwarded downstream the same way.
//!
//! ```sh
//! cargo run --example proxy_forward
//! ```

use http_net::{
    ClientConn, ClientEvent, HttpError, Request, Response, ServerConn, ServerEvent, is_hop_by_hop,
};

fn main() -> Result<(), HttpError> {
    // What the browser sent to the proxy.
    let from_client = b"POST /api/notes HTTP/1.1\r\nHost: app.local\r\nConnection: keep-alive, X-Debug\r\nX-Debug: 1\r\nKeep-Alive: timeout=5\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";

    let mut downstream = ServerConn::new();
    let _ = downstream.feed(from_client);
    let ServerEvent::Request(head) = downstream.poll()? else {
        return Err(HttpError::InvalidState("expected a request"));
    };
    for (name, _) in head.headers() {
        let hop = is_hop_by_hop(name, head.connection_options());
        println!(
            "{name}: {}",
            if hop {
                "dropped (hop-by-hop)"
            } else {
                "forwarded"
            }
        );
    }
    let forwarded = Request::forward_from(&head).header("via", "1.1 proxy.local");

    // Write it to the upstream; the body follows as it arrives.
    let mut upstream = ClientConn::new();
    let mut to_upstream = Vec::new();
    upstream.send_request(&forwarded, &mut to_upstream)?;
    loop {
        match downstream.poll()? {
            ServerEvent::Body(chunk) => upstream.send_body(chunk, &mut to_upstream)?,
            ServerEvent::RequestEnd => break,
            _ => {}
        }
    }
    upstream.end_body(&mut to_upstream)?;
    println!(
        "--- to upstream ---\n{}",
        String::from_utf8_lossy(&to_upstream)
    );

    // The upstream answers; the proxy relays status, fields, and body.
    let _ = upstream.feed(
        b"HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nsaved",
    );
    let mut relayed = None;
    let mut body = Vec::new();
    loop {
        match upstream.poll()? {
            ClientEvent::Response(r) => {
                let mut response = Response::new(r.status());
                for (name, value) in r.headers() {
                    if !name.eq_ignore_ascii_case("content-length") {
                        response = response.header(name, value);
                    }
                }
                relayed = Some(response);
            }
            ClientEvent::Body(chunk) => body.extend_from_slice(chunk),
            ClientEvent::ResponseEnd => break,
            _ => {}
        }
    }
    let mut to_client = Vec::new();
    if let Some(response) = relayed {
        downstream.respond(
            &response.header("via", "1.1 proxy.local").body(body),
            &mut to_client,
        )?;
    }
    println!("--- to client ---\n{}", String::from_utf8_lossy(&to_client));
    Ok(())
}
