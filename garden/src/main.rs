//! The http-net origin for the HTTP Garden.
//!
//! ```sh
//! http-net-garden [ADDR]   # ADDR defaults to 0.0.0.0:80
//! ```
//!
//! One thread per connection over `std::net`, each driving a
//! [`http_net::ServerConn`] through [`http_net_garden::serve_connection`].

use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

/// A connection the peer abandons without closing is dropped after this.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

fn handle(mut stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(IDLE_TIMEOUT));
    let _ = http_net_garden::serve_connection(&mut stream);
}

fn main() -> std::io::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:80".to_owned());
    let listener = TcpListener::bind(&addr)?;
    eprintln!(
        "http-net-garden: http-net {} listening on {}",
        http_net::VERSION,
        listener.local_addr()?
    );
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // A panic stays in its connection's thread; the default hook
                // prints it, and the Garden job scans the log for it.
                let _ = thread::Builder::new().spawn(move || handle(stream));
            }
            Err(e) => eprintln!("http-net-garden: accept failed: {e}"),
        }
    }
    Ok(())
}
