//! Client pipelining in memory: four GETs go out before any response comes
//! back, the server answers them in order, and the client matches each
//! response to its request.
//!
//! ```sh
//! cargo run --example pipelined_client
//! ```

use http_net::{
    ClientConn, ClientEvent, HttpError, Limits, Request, Response, ServerConn, ServerEvent,
};

fn main() -> Result<(), HttpError> {
    let mut client = ClientConn::with_limits(Limits::new().with_pipeline_depth(4));
    let mut to_server = Vec::new();
    let paths = ["/users/1", "/users/2", "/users/3", "/users/4"];
    for path in paths {
        client.send_request(
            &Request::get(path).header("host", "api.local"),
            &mut to_server,
        )?;
    }
    println!("client: {} requests outstanding", client.outstanding());

    // The server sees four requests in one read and answers each in turn.
    let mut server = ServerConn::new();
    let mut to_client = Vec::new();
    let _ = server.feed(&to_server);
    let mut target = String::new();
    loop {
        match server.poll()? {
            ServerEvent::Request(head) => target = head.target().to_string(),
            ServerEvent::RequestEnd => {
                server.respond(
                    &Response::text(200, &format!("user at {target}")),
                    &mut to_client,
                )?;
            }
            ServerEvent::NeedInput => break,
            other => println!("server: other event: {other:?}"),
        }
    }

    let _ = client.feed(&to_client);
    let mut answered = 0;
    loop {
        match client.poll()? {
            ClientEvent::Response(head) => print!("{} {}: ", paths[answered], head.status()),
            ClientEvent::Body(body) => println!("{}", String::from_utf8_lossy(body)),
            ClientEvent::ResponseEnd => answered += 1,
            ClientEvent::Idle => break,
            other => println!("client: other event: {other:?}"),
        }
    }
    println!(
        "client: {answered} responses, {} outstanding",
        client.outstanding()
    );
    Ok(())
}
