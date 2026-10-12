//! The Tier-1 path end to end: serve a handler on an ephemeral localhost
//! port, fetch from it with the blocking client, and shut down.
//!
//! ```sh
//! cargo run --example localhost
//! ```

use http_net::{Response, blocking};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = blocking::Server::bind("127.0.0.1:0")?;
    let addr = server.local_addr();
    let stop = server.shutdown_handle();
    let thread = std::thread::spawn(move || {
        server.serve(|req, body| match req.path() {
            "/" => Response::text(200, "hello from http-net\n"),
            "/echo" => Response::new(200).body(body.to_vec()),
            _ => Response::text(404, "not found\n"),
        })
    });

    for path in ["/", "/missing"] {
        let resp = blocking::get(&format!("http://{addr}{path}"))?;
        println!(
            "GET {path} -> {} {:?}",
            resp.status(),
            resp.text().unwrap_or("")
        );
    }

    stop.shutdown();
    thread.join().map_err(|_| "server thread panicked")??;
    Ok(())
}
