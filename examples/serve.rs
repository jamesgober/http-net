//! A localhost server that serves until it is stopped with Ctrl+C.
//!
//! ```sh
//! cargo run --example serve -- 127.0.0.1:8080
//! curl -i http://127.0.0.1:8080/
//! ```

use http_net::{Response, blocking::Server};

fn main() -> std::io::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".into());
    let server = Server::bind(&addr)?;
    println!(
        "serving on http://{}/ (Ctrl+C to stop)",
        server.local_addr()
    );
    server.serve(|req, body| {
        let text = format!(
            "{} {} ({} header fields, {} body bytes)\n",
            req.method_str(),
            req.target(),
            req.headers().len(),
            body.len()
        );
        Response::text(200, &text)
    })
}
