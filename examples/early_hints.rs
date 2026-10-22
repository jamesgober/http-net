//! `103 Early Hints` end to end in memory: the server tells the client
//! which stylesheet to preload before it has the page, then sends the page;
//! the client reports the hint as an interim response, then the final one.
//!
//! ```sh
//! cargo run --example early_hints
//! ```

use http_net::{ClientConn, ClientEvent, HttpError, Request, Response, ServerConn, ServerEvent};

fn main() -> Result<(), HttpError> {
    let mut client = ClientConn::new();
    client.set_report_informational(true);
    let mut to_server = Vec::new();
    client.send_request(
        &Request::get("/").header("host", "localhost"),
        &mut to_server,
    )?;

    let mut server = ServerConn::new();
    let mut to_client = Vec::new();
    let _ = server.feed(&to_server);
    while !matches!(server.poll()?, ServerEvent::RequestEnd) {}
    // The hint goes out first, while the page is still being built.
    let hints = Response::new(103).header("link", "</style.css>; rel=preload; as=style");
    server.send_informational(&hints, &mut to_client)?;
    server.respond(
        &Response::text(200, "<!doctype html><title>page</title>"),
        &mut to_client,
    )?;

    let _ = client.feed(&to_client);
    loop {
        match client.poll()? {
            ClientEvent::Informational(head) => println!(
                "interim {}: preload {}",
                head.status(),
                head.header_str("link").unwrap_or("")
            ),
            ClientEvent::Response(head) => println!("final {}", head.status()),
            ClientEvent::Body(chunk) => println!("  {}", String::from_utf8_lossy(chunk)),
            ClientEvent::ResponseEnd => break,
            other => println!("other event: {other:?}"),
        }
    }
    Ok(())
}
