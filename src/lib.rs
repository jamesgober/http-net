//! # http_net
//!
//! An HTTP/1.1 engine that does no I/O itself. Feed it the bytes a socket
//! delivered; it hands back requests (or responses) as borrowed views of
//! those bytes, decodes their bodies, and serializes what you send back.
//! The caller owns sockets, threads, and timers, so the same core runs
//! under a blocking loop, an event loop, or a test that never opens a
//! socket.
//!
//! Parsing follows RFC 9112 strictly. Messages that recipients could
//! disagree about are refused rather than repaired: conflicting
//! `Content-Length` / `Transfer-Encoding`, duplicate `Content-Length`,
//! obsolete line folding, bare CR or LF, whitespace before a colon, and
//! control characters in field values each have their own [`HttpError`].
//! Every buffer is bounded by [`Limits`], and each limit is checked before
//! the bytes it governs are buffered.
//!
//! ## Tier 1: serve and fetch (blocking, `std`)
//!
//! ```
//! # #[cfg(feature = "std")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use http_net::{blocking, Response};
//!
//! let server = blocking::Server::bind("127.0.0.1:0")?;
//! let addr = server.local_addr();
//! let stop = server.shutdown_handle();
//! let t = std::thread::spawn(move || server.serve(|req, _body| Response::text(200, req.path())));
//!
//! let resp = blocking::get(&format!("http://{addr}/hi"))?;
//! assert_eq!(resp.text(), Some("/hi"));
//!
//! stop.shutdown();
//! t.join().unwrap()?;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "std"))]
//! # fn main() {}
//! ```
//!
//! ## Tier 2: the sans-IO connection
//!
//! ```
//! use http_net::{Response, ServerConn, ServerEvent};
//!
//! let mut conn = ServerConn::new();
//! let mut out = Vec::new();
//! let _ = conn.feed(b"GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n");
//! loop {
//!     match conn.poll()? {
//!         ServerEvent::Request(req) => assert_eq!(req.path(), "/status"),
//!         ServerEvent::Body(_) => {}
//!         ServerEvent::RequestEnd => conn.respond(&Response::text(200, "up"), &mut out)?,
//!         _ => break, // NeedInput: read more from the socket
//!     }
//! }
//! assert!(out.starts_with(b"HTTP/1.1 200 OK\r\n"));
//! # Ok::<(), http_net::HttpError>(())
//! ```
//!
//! [`ClientConn`] is the mirror image for the client side, and the
//! `blocking` module shows how either is driven over `std::net`.
//!
//! ## Protocol upgrades
//!
//! A request with `Connection: upgrade` and an `Upgrade` field offering a
//! protocol other than `h2c` reports [`RequestHead::is_upgrade`]. Answering
//! it with [`Response::switching_protocols`] naming an offered protocol
//! moves the connection to [`ServerEvent::Upgraded`], after which
//! [`ServerConn::remaining_input`] holds any bytes of the new protocol that
//! arrived with the request. This is the hand-off point for a WebSocket
//! engine such as `ws-net`.
//!
//! ## Feature flags
//!
//! | Feature | Default | Description |
//! |---|---|---|
//! | `std` | yes | The `blocking` adapter over `std::net`. Without it the crate is `no_std` and needs only `alloc` (built in CI for `thumbv7em-none-eabihf`). |
//!
//! ## Credentials in `Debug` output
//!
//! Every `Debug` implementation in the crate prints the values of
//! `authorization`, `proxy-authorization`, `cookie`, and `set-cookie` as
//! `<redacted N bytes>`, so logging a request with `{:?}` never leaks a
//! session cookie or a bearer token. The accessors return the real values.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(unused_must_use)]
#![deny(unused_results)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::print_stdout)]
#![deny(clippy::print_stderr)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::unreachable)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

extern crate alloc;

mod body;
mod buffer;
mod client;
mod error;
mod head;
mod limits;
mod message;
mod method;
mod redact;
mod server;
pub mod status;
mod syntax;

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod blocking;

pub use client::{ClientConn, ClientEvent};
pub use error::HttpError;
pub use head::{
    BodyFraming, HeaderValues, Headers, RequestHead, ResponseHead, TargetForm, Version,
};
pub use limits::Limits;
pub use message::{Request, Response};
pub use method::{Method, MethodSet};
pub use server::{ServerConn, ServerEvent};
pub use status::{StatusClass, reason_phrase, status_class};

/// The crate version, as published (`CARGO_PKG_VERSION`).
///
/// # Examples
///
/// ```
/// assert_eq!(http_net::VERSION.split('.').count(), 3);
/// ```
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// The README's and the API reference's examples run as doctests, so their
// claims stay true.
#[cfg(all(doctest, feature = "std"))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

#[cfg(all(doctest, feature = "std"))]
#[doc = include_str!("../docs/API.md")]
struct ApiDoctests;

#[cfg(all(doctest, feature = "std"))]
#[doc = include_str!("../docs/MIGRATION.md")]
struct MigrationDoctests;

#[cfg(test)]
mod tests {
    #[test]
    fn test_public_types_are_send_and_sync() {
        fn assert<T: Send + Sync>() {}
        assert::<crate::ServerConn>();
        assert::<crate::ServerEvent<'_>>();
        assert::<crate::ClientConn>();
        assert::<crate::ClientEvent<'_>>();
        assert::<crate::Response>();
        assert::<crate::Request>();
        assert::<crate::RequestHead<'_>>();
        assert::<crate::ResponseHead<'_>>();
        assert::<crate::Headers<'_>>();
        assert::<crate::HeaderValues<'_, '_>>();
        assert::<crate::HttpError>();
        assert::<crate::Limits>();
        assert::<crate::Method>();
        assert::<crate::MethodSet>();
        assert::<crate::Version>();
        assert::<crate::BodyFraming>();
        assert::<crate::TargetForm>();
        assert::<crate::StatusClass>();
        #[cfg(feature = "std")]
        {
            assert::<crate::blocking::Server>();
            assert::<crate::blocking::ServerConfig>();
            assert::<crate::blocking::ShutdownHandle>();
            assert::<crate::blocking::Connection>();
            assert::<crate::blocking::Incoming<'_>>();
            assert::<crate::blocking::Upgraded>();
            assert::<crate::blocking::Client>();
            assert::<crate::blocking::ClientResponse>();
            assert::<crate::blocking::Error>();
        }
    }

    #[test]
    fn test_version_matches_the_manifest() {
        assert_eq!(crate::VERSION, env!("CARGO_PKG_VERSION"));
    }
}
