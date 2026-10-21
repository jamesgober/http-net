//! A small blocking adapter over `std::net`: the Tier-1 path.
//!
//! [`Server`] serves a handler on a socket with one thread per connection
//! (bounded by [`ServerConfig::with_max_connections`]); [`Connection`] is the
//! per-connection loop for callers who run their own accept loop or need the
//! socket back after an upgrade; [`get`] fetches a URL. Everything here is a
//! thin shell around [`ServerConn`] and [`ClientConn`]: all parsing, framing,
//! and limit enforcement happens in the sans-IO core.
//!
//! Only plain `http://` is spoken; there is no TLS in this crate.

use std::{
    fmt, io,
    io::{Read, Write},
    net::{
        IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
    },
    string::{String, ToString},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    vec::Vec,
};

use crate::{
    ClientConn, ClientEvent, HttpError, Limits, Method, Request, RequestHead, Response, ServerConn,
    ServerEvent, redact::FieldValue,
};

/// Bytes a closing connection reads and discards so the peer's unread data
/// does not turn the close into a reset that destroys the last response.
const DRAIN_LIMIT: usize = 256 * 1024;
/// How long one read of the lingering close may wait.
const DRAIN_READ_TIMEOUT: Duration = Duration::from_millis(250);
/// How long the whole lingering close may take, however the peer behaves:
/// a peer that keeps sending must not keep the connection (and its slot).
const DRAIN_TOTAL: Duration = Duration::from_secs(1);
/// Responses larger than this do not keep their output buffer afterwards.
const OUT_RETAIN: usize = 64 * 1024;

/// What can go wrong in the blocking adapter.
///
/// # Examples
///
/// ```
/// let err = http_net::blocking::get("https://example.com/").unwrap_err();
/// assert!(matches!(err, http_net::blocking::Error::InvalidUrl(_)));
/// ```
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// The socket failed (connect, read, write, or timeout).
    Io(io::Error),
    /// The peer sent a message this crate refuses, or a call was out of
    /// order.
    Http(HttpError),
    /// The URL is not `http://host[:port][/path][?query]`; the text says
    /// which part is wrong.
    InvalidUrl(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Http(e) => write!(f, "HTTP error: {e}"),
            Self::InvalidUrl(why) => write!(f, "invalid URL: {why}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Http(e) => Some(e),
            Self::InvalidUrl(_) => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<HttpError> for Error {
    fn from(e: HttpError) -> Self {
        Self::Http(e)
    }
}

/// Settings for [`Server`].
///
/// | Setting | Default |
/// |---|---|
/// | limits | [`Limits::new`] |
/// | concurrent connections | 64 (the 65th is answered `503` and closed) |
/// | read timeout (also the idle keep-alive timeout) | 10 s |
/// | request timeout (first byte of a request to the end of its body) | 30 s |
/// | write timeout | 10 s |
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use http_net::{blocking::ServerConfig, Limits};
///
/// let config = ServerConfig::new()
///     .with_limits(Limits::new().with_max_body(16 * 1024))
///     .with_max_connections(8)
///     .with_read_timeout(Some(Duration::from_secs(5)));
/// assert_eq!(config.max_connections(), 8);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    limits: Limits,
    max_connections: usize,
    read_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerConfig {
    /// The defaults (see the table on [`ServerConfig`]).
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::blocking::ServerConfig::new().max_connections(), 64);
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limits: Limits::new(),
            max_connections: 64,
            read_timeout: Some(Duration::from_secs(10)),
            request_timeout: Some(Duration::from_secs(30)),
            write_timeout: Some(Duration::from_secs(10)),
        }
    }

    /// Sets the message limits for every connection.
    ///
    /// # Examples
    ///
    /// ```
    /// let c = http_net::blocking::ServerConfig::new()
    ///     .with_limits(http_net::Limits::new().with_max_headers(10));
    /// assert_eq!(c.limits().max_headers(), 10);
    /// ```
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets how many connections are served at once (at least 1).
    ///
    /// # Examples
    ///
    /// ```
    /// let c = http_net::blocking::ServerConfig::new().with_max_connections(0);
    /// assert_eq!(c.max_connections(), 1);
    /// ```
    #[must_use]
    pub const fn with_max_connections(mut self, n: usize) -> Self {
        self.max_connections = if n == 0 { 1 } else { n };
        self
    }

    /// Sets the socket read timeout: how long a request may take to arrive,
    /// and how long an idle keep-alive connection is held. `None` waits
    /// forever.
    ///
    /// # Examples
    ///
    /// ```
    /// let c = http_net::blocking::ServerConfig::new().with_read_timeout(None);
    /// assert_eq!(c.read_timeout(), None);
    /// ```
    #[must_use]
    pub const fn with_read_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Sets the request timeout: the most time one request may take to
    /// arrive, from its first byte to the end of its body. The read timeout
    /// alone cannot stop a client that sends one byte just inside it
    /// ("slowloris"); this deadline can. A request still incomplete when it
    /// passes is answered `408 Request Timeout` and the connection closed.
    /// Time spent idle between keep-alive requests does not count (the read
    /// timeout governs that). `None` disables the deadline.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// let c = http_net::blocking::ServerConfig::new().with_request_timeout(Some(Duration::from_secs(10)));
    /// assert_eq!(c.request_timeout(), Some(Duration::from_secs(10)));
    /// ```
    #[must_use]
    pub const fn with_request_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Sets the socket write timeout. `None` waits forever.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// let c = http_net::blocking::ServerConfig::new().with_write_timeout(Some(Duration::from_secs(1)));
    /// assert_eq!(c.write_timeout(), Some(Duration::from_secs(1)));
    /// ```
    #[must_use]
    pub const fn with_write_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.write_timeout = timeout;
        self
    }

    /// The message limits.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::blocking::ServerConfig::new().limits(), http_net::Limits::new());
    /// ```
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// The concurrent connection cap.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::blocking::ServerConfig::new().max_connections(), 64);
    /// ```
    #[must_use]
    pub const fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// The read timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// assert_eq!(http_net::blocking::ServerConfig::new().read_timeout(), Some(Duration::from_secs(10)));
    /// ```
    #[must_use]
    pub const fn read_timeout(&self) -> Option<Duration> {
        self.read_timeout
    }

    /// The request timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// assert_eq!(http_net::blocking::ServerConfig::new().request_timeout(), Some(Duration::from_secs(30)));
    /// ```
    #[must_use]
    pub const fn request_timeout(&self) -> Option<Duration> {
        self.request_timeout
    }

    /// The write timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// assert_eq!(http_net::blocking::ServerConfig::new().write_timeout(), Some(Duration::from_secs(10)));
    /// ```
    #[must_use]
    pub const fn write_timeout(&self) -> Option<Duration> {
        self.write_timeout
    }
}

/// A connection handed over by a `101 Switching Protocols` (or a 2xx to
/// `CONNECT`): the socket, the bytes of the new protocol that already
/// arrived, and the target of the request that asked for the switch.
///
/// # Examples
///
/// ```no_run
/// use http_net::{blocking::Server, Response};
///
/// let server = Server::bind("127.0.0.1:0")?.on_upgrade(|up| {
///     // Hand `up.stream` and `up.leftover` to a protocol engine.
///     let _ = (up.stream, up.leftover, up.target);
/// });
/// server.serve(|req, _body| {
///     if req.is_upgrade() {
///         Response::switching_protocols("x")
///     } else {
///         Response::new(404)
///     }
/// })?;
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug)]
pub struct Upgraded {
    /// The socket, now speaking the new protocol.
    pub stream: TcpStream,
    /// Bytes of the new protocol received together with the request.
    pub leftover: Vec<u8>,
    /// The target of the request that asked for the switch.
    pub target: String,
}

type UpgradeHook = Arc<dyn Fn(Upgraded) + Send + Sync>;

/// A blocking HTTP/1.1 server: one thread per connection, bounded.
///
/// # Examples
///
/// ```
/// use http_net::{blocking::{self, Server}, Response};
///
/// let server = Server::bind("127.0.0.1:0")?;
/// let addr = server.local_addr();
/// let stop = server.shutdown_handle();
/// let thread = std::thread::spawn(move || {
///     server.serve(|req, _body| Response::text(200, &format!("you asked for {}", req.path())))
/// });
///
/// let resp = blocking::get(&format!("http://{addr}/hello"))?;
/// assert_eq!(resp.status(), 200);
/// assert_eq!(resp.text(), Some("you asked for /hello"));
///
/// stop.shutdown();
/// thread.join().unwrap()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct Server {
    listener: TcpListener,
    local: SocketAddr,
    config: ServerConfig,
    stop: Arc<AtomicBool>,
    upgrade: Option<UpgradeHook>,
}

impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("local_addr", &self.local)
            .field("config", &self.config)
            .finish()
    }
}

/// Stops a running [`Server::serve`] from another thread.
///
/// # Examples
///
/// ```
/// let server = http_net::blocking::Server::bind("127.0.0.1:0")?;
/// let stop = server.shutdown_handle();
/// let t = std::thread::spawn(move || server.serve(|_, _| http_net::Response::new(204)));
/// stop.shutdown();
/// t.join().unwrap()?;
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct ShutdownHandle {
    stop: Arc<AtomicBool>,
    wake: SocketAddr,
}

impl ShutdownHandle {
    /// Asks the server to stop: it accepts no new connections, lets each
    /// open connection finish its current exchange, waits for them, and
    /// returns from `serve`.
    ///
    /// # Examples
    ///
    /// See [`ShutdownHandle`].
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
        // `accept` blocks; a throwaway connection wakes it so it sees the
        // flag. If the connect fails the listener is already gone, which is
        // the outcome being asked for, so the error carries no information.
        if let Ok(stream) = TcpStream::connect_timeout(&self.wake, Duration::from_secs(1)) {
            drop(stream);
        }
    }
}

/// Counts live connection threads so shutdown can wait for them.
#[derive(Default)]
struct Active {
    count: Mutex<usize>,
    idle: Condvar,
}

impl Active {
    fn try_enter(&self, max: usize) -> bool {
        let mut n = self
            .count
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *n >= max {
            return false;
        }
        *n += 1;
        true
    }

    fn leave(&self) {
        let mut n = self
            .count
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *n = n.saturating_sub(1);
        if *n == 0 {
            self.idle.notify_all();
        }
    }

    fn wait_idle(&self) {
        let mut n = self
            .count
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *n > 0 {
            n = self
                .idle
                .wait(n)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

/// Leaves the active set even if the handler panics.
struct ActiveGuard(Arc<Active>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.leave();
    }
}

impl Server {
    /// Binds a listening socket. Use `127.0.0.1:0` for an ephemeral
    /// localhost port and read it back with [`local_addr`](Self::local_addr).
    ///
    /// # Errors
    ///
    /// The bind error from the operating system.
    ///
    /// # Examples
    ///
    /// ```
    /// let server = http_net::blocking::Server::bind("127.0.0.1:0")?;
    /// assert!(server.local_addr().ip().is_loopback());
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn bind(addr: impl ToSocketAddrs) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        let local = listener.local_addr()?;
        Ok(Self {
            listener,
            local,
            config: ServerConfig::new(),
            stop: Arc::new(AtomicBool::new(false)),
            upgrade: None,
        })
    }

    /// Replaces the configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::blocking::{Server, ServerConfig};
    /// let s = Server::bind("127.0.0.1:0")?.with_config(ServerConfig::new().with_max_connections(4));
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn with_config(mut self, config: ServerConfig) -> Self {
        self.config = config;
        self
    }

    /// Sets what happens to a connection after the handler answers with
    /// `101 Switching Protocols`: `hook` receives the socket on the
    /// connection's thread. Without a hook such connections are closed.
    ///
    /// # Examples
    ///
    /// See [`Upgraded`].
    #[must_use]
    pub fn on_upgrade(mut self, hook: impl Fn(Upgraded) + Send + Sync + 'static) -> Self {
        self.upgrade = Some(Arc::new(hook));
        self
    }

    /// The bound address (with the real port when bound to port 0).
    ///
    /// # Examples
    ///
    /// ```
    /// let server = http_net::blocking::Server::bind("127.0.0.1:0")?;
    /// assert_ne!(server.local_addr().port(), 0);
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// A handle that stops [`serve`](Self::serve) from another thread.
    ///
    /// # Examples
    ///
    /// See [`ShutdownHandle`].
    #[must_use]
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        let mut wake = self.local;
        if wake.ip().is_unspecified() {
            wake.set_ip(match wake.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
            });
        }
        ShutdownHandle {
            stop: Arc::clone(&self.stop),
            wake,
        }
    }

    /// Serves `handler` until [`ShutdownHandle::shutdown`] is called.
    ///
    /// The handler gets each request's head and its complete body (bounded
    /// by [`Limits::max_body`]) and returns the response. Requests that fail
    /// to parse are answered with their [`HttpError::status`] and the
    /// connection is closed; the handler never sees them. Every response
    /// gets a `date` header unless the handler set one.
    ///
    /// # Errors
    ///
    /// Only if accepting connections fails persistently; transient accept
    /// errors are retried.
    ///
    /// # Examples
    ///
    /// See [`Server`].
    pub fn serve<H>(self, handler: H) -> io::Result<()>
    where
        H: Fn(&RequestHead<'_>, &[u8]) -> Response + Send + Sync + 'static,
    {
        let handler = Arc::new(handler);
        let active = Arc::new(Active::default());
        let mut consecutive_errors = 0u32;
        for incoming in self.listener.incoming() {
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            let stream = match incoming {
                Ok(stream) => {
                    consecutive_errors = 0;
                    stream
                }
                Err(e) => {
                    // Aborted handshakes and descriptor exhaustion are
                    // transient; back off briefly instead of spinning, and
                    // give up only if accept never recovers.
                    consecutive_errors += 1;
                    if consecutive_errors > 1000 {
                        return Err(e);
                    }
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
            };
            if !active.try_enter(self.config.max_connections) {
                refuse_busy(stream, &self.config);
                continue;
            }
            let guard = ActiveGuard(Arc::clone(&active));
            let handler = Arc::clone(&handler);
            let upgrade = self.upgrade.clone();
            let stop = Arc::clone(&self.stop);
            let config = self.config;
            let spawned = thread::Builder::new()
                .name("http-net-conn".into())
                .spawn(move || {
                    let _guard = guard;
                    serve_stream(stream, &config, &*handler, upgrade.as_deref(), &stop);
                });
            // A failed spawn drops the closure, its guard, and the stream:
            // the connection is closed and the slot released.
            drop(spawned);
        }
        active.wait_idle();
        Ok(())
    }
}

fn refuse_busy(mut stream: TcpStream, config: &ServerConfig) {
    const BUSY: &[u8] =
        b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
    // Best effort on a connection being turned away: a failure here only
    // means the client already left. This runs on the accept thread, so it
    // must never wait on the peer: the 503 fits in an empty send buffer,
    // and only what has already arrived is drained (without blocking) so
    // that it does not turn the close into a reset.
    if stream.set_write_timeout(config.write_timeout).is_err()
        || stream.write_all(BUSY).is_err()
        || stream.shutdown(Shutdown::Write).is_err()
        || stream.set_nonblocking(true).is_err()
    {
        return;
    }
    let mut scratch = [0u8; 4096];
    let mut drained = 0;
    while drained < DRAIN_LIMIT {
        match stream.read(&mut scratch) {
            Ok(n) if n > 0 => drained += n,
            _ => break,
        }
    }
}

fn serve_stream(
    stream: TcpStream,
    config: &ServerConfig,
    handler: &(dyn Fn(&RequestHead<'_>, &[u8]) -> Response + Send + Sync),
    upgrade: Option<&(dyn Fn(Upgraded) + Send + Sync)>,
    stop: &AtomicBool,
) {
    let configured = stream.set_read_timeout(config.read_timeout).is_ok()
        && stream.set_write_timeout(config.write_timeout).is_ok()
        && stream.set_nodelay(true).is_ok();
    if !configured {
        return;
    }
    let mut conn =
        Connection::new(stream, config.limits).with_request_timeout(config.request_timeout);
    while !stop.load(Ordering::SeqCst) {
        // The handler runs inside the first match; errors (which borrow
        // nothing) are handled in the second, where `conn` is free again.
        let outcome = match conn.next_request() {
            Ok(Some(incoming)) => {
                let head = incoming.head();
                Ok((
                    handler(&head, incoming.body()),
                    head.method() == Method::Head,
                ))
            }
            Ok(None) => break,
            Err(e) => Err(e),
        };
        let (response, is_head) = match outcome {
            Ok(answer) => answer,
            Err(Error::Http(e)) => {
                if conn.respond(&Response::from_error(&e)).is_err() {
                    return;
                }
                break;
            }
            Err(Error::Io(e)) if is_timeout(&e) && conn.request_in_progress() => {
                // A request that did not arrive in time: say so, then
                // close (the rest of it can no longer be framed).
                if conn.send_request_timeout().is_ok() {
                    conn.close();
                }
                return;
            }
            Err(_) => return,
        };
        // `Server` writes full bodies only: the handler has no way to send
        // a streamed one, so it would leave the client waiting. A `HEAD`
        // answer is the exception: it announces a length or chunked
        // framing but carries no body, so it is complete once written.
        let streamed = response.body_bytes().is_none();
        let response = if streamed && !is_head {
            Response::text(
                500,
                "handler error: Server cannot send a streamed response; \
                 use Connection for streaming",
            )
            .close()
        } else {
            response
        };
        match conn.respond(&response) {
            Ok(()) if streamed && is_head => {
                if conn.end_body().is_err() {
                    return;
                }
            }
            Ok(()) => {}
            // Refused before anything was written (a builder error, or a
            // 101 to a request that did not ask): answer 500 instead.
            Err(Error::Http(e)) => {
                let message = format!("handler error: invalid response: {e}");
                if conn
                    .respond(&Response::text(500, &message).close())
                    .is_err()
                {
                    return;
                }
            }
            Err(_) => return,
        }
        if conn.is_upgraded() {
            match (conn.into_upgraded(), upgrade) {
                (Some(up), Some(hook)) => hook(up),
                (Some(up), None) => drain_and_close(up.stream),
                (None, _) => {}
            }
            return;
        }
    }
    conn.close();
}

fn drain_and_close(mut stream: TcpStream) {
    // Lingering close (RFC 9112 section 9.6): stop sending, then read what
    // the peer is still sending so the close does not become a reset that
    // discards the response before the peer reads it.
    // The drain is bounded in bytes and in total time, not only per read:
    // a peer that keeps trickling data must not hold the thread.
    if stream.flush().is_err() || stream.shutdown(Shutdown::Write).is_err() {
        return;
    }
    let deadline = Instant::now() + DRAIN_TOTAL;
    let mut scratch = [0u8; 4096];
    let mut drained = 0;
    while drained < DRAIN_LIMIT {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero()
            || stream
                .set_read_timeout(Some(left.min(DRAIN_READ_TIMEOUT)))
                .is_err()
        {
            break;
        }
        match stream.read(&mut scratch) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained += n,
        }
    }
}

fn is_timeout(e: &io::Error) -> bool {
    // Unix reports an expired socket timeout as WouldBlock, Windows as
    // TimedOut.
    matches!(
        e.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

/// One request read by [`Connection::next_request`]: its head and its
/// complete body.
///
/// # Examples
///
/// See [`Connection`].
#[derive(Debug)]
pub struct Incoming<'a> {
    head: RequestHead<'a>,
    body: &'a [u8],
}

impl<'a> Incoming<'a> {
    /// The request head.
    ///
    /// # Examples
    ///
    /// See [`Connection`].
    #[must_use]
    pub fn head(&self) -> RequestHead<'a> {
        self.head
    }

    /// The complete request body (empty when there is none).
    ///
    /// # Examples
    ///
    /// See [`Connection`].
    #[must_use]
    pub fn body(&self) -> &'a [u8] {
        self.body
    }
}

/// A blocking server connection: [`ServerConn`] driven over a `TcpStream`.
///
/// Use it for your own accept loop, or to keep the socket after an
/// upgrade with [`into_upgraded`](Self::into_upgraded).
///
/// # Examples
///
/// ```
/// use std::net::{TcpListener, TcpStream};
/// use std::io::{Read, Write};
/// use http_net::{blocking::Connection, Limits, Response};
///
/// let listener = TcpListener::bind("127.0.0.1:0")?;
/// let addr = listener.local_addr()?;
/// let client = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
///     let mut s = TcpStream::connect(addr)?;
///     s.write_all(b"POST /sum HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nConnection: close\r\n\r\n1 2")?;
///     let mut reply = Vec::new();
///     s.read_to_end(&mut reply)?;
///     Ok(reply)
/// });
///
/// let (stream, _) = listener.accept()?;
/// let mut conn = Connection::new(stream, Limits::new());
/// while let Some(req) = conn.next_request()? {
///     let sum: u32 = std::str::from_utf8(req.body())?.split(' ').filter_map(|n| n.parse::<u32>().ok()).sum();
///     let response = Response::text(200, &sum.to_string());
///     conn.respond(&response)?;
/// }
/// conn.close();
/// let reply = client.join().unwrap()?;
/// assert!(reply.ends_with(b"\r\n\r\n3"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct Connection {
    stream: TcpStream,
    conn: ServerConn,
    body: Vec<u8>,
    out: Vec<u8>,
    /// The socket's own read timeout, restored once a request deadline no
    /// longer applies.
    read_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    /// When the request being read must be complete.
    deadline: Option<Instant>,
    /// Whether the socket's read timeout is currently shortened to the
    /// deadline.
    shortened: bool,
}

impl Connection {
    /// Wraps an accepted socket. Set its timeouts first if you want them:
    /// the read timeout set on `stream` is the idle timeout, and
    /// [`with_request_timeout`](Self::with_request_timeout) adds a deadline
    /// for each request as a whole.
    ///
    /// # Examples
    ///
    /// See [`Connection`].
    #[must_use]
    pub fn new(stream: TcpStream, limits: Limits) -> Self {
        let read_timeout = stream.read_timeout().ok().flatten();
        Self {
            stream,
            conn: ServerConn::with_limits(limits),
            body: Vec::new(),
            out: Vec::new(),
            read_timeout,
            request_timeout: None,
            deadline: None,
            shortened: false,
        }
    }

    /// Sets a deadline for each request: from the moment its first byte is
    /// seen to the end of its body (see
    /// [`ServerConfig::with_request_timeout`]). When it passes,
    /// [`next_request`](Self::next_request) fails with an [`Error::Io`] of
    /// kind `TimedOut`. `None` (the default for a bare `Connection`) leaves
    /// only the socket's own read timeout.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// # fn demo(stream: std::net::TcpStream) {
    /// let conn = http_net::blocking::Connection::new(stream, http_net::Limits::new())
    ///     .with_request_timeout(Some(Duration::from_secs(10)));
    /// # let _ = conn;
    /// # }
    /// ```
    #[must_use]
    pub fn with_request_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Whether part of a request has arrived and the rest is outstanding.
    fn request_in_progress(&self) -> bool {
        self.conn.request().is_some() || !self.conn.remaining_input().is_empty()
    }

    /// Answers a request that did not arrive in time with `408`, unless a
    /// response is already on its way.
    fn send_request_timeout(&mut self) -> Result<(), Error> {
        if self.conn.response_started() {
            return Err(Error::Http(HttpError::InvalidState(
                "a response was already started",
            )));
        }
        const BODY: &[u8] = b"request timed out";
        self.out.clear();
        self.out.extend_from_slice(
            b"HTTP/1.1 408 Request Timeout\r\ncontent-type: text/plain; charset=utf-8\r\n\
              content-length: ",
        );
        self.out
            .extend_from_slice(BODY.len().to_string().as_bytes());
        self.out
            .extend_from_slice(b"\r\nconnection: close\r\ndate: ");
        self.out.extend_from_slice(&http_date(SystemTime::now()));
        self.out.extend_from_slice(b"\r\n\r\n");
        self.out.extend_from_slice(BODY);
        self.flush_out()
    }

    /// Reads into the parser's buffer, under the request deadline if one
    /// is running.
    fn fill(&mut self) -> Result<(), Error> {
        if let Some(limit) = self.request_timeout {
            if self.deadline.is_none() && self.request_in_progress() {
                self.deadline = Some(Instant::now() + limit);
            }
        }
        match self.deadline {
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the request did not arrive within the request timeout",
                    )));
                }
                let wait = self.read_timeout.map_or(left, |t| t.min(left));
                self.stream.set_read_timeout(Some(wait))?;
                self.shortened = true;
            }
            None if self.shortened => {
                self.stream.set_read_timeout(self.read_timeout)?;
                self.shortened = false;
            }
            None => {}
        }
        let spare = self.conn.read_buf();
        if spare.is_empty() {
            return Err(Error::Http(HttpError::InvalidState(
                "input buffer full while the parser needs input",
            )));
        }
        let n = loop {
            match self.stream.read(spare) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                other => break other?,
            }
        };
        if n == 0 {
            self.conn.feed_eof();
        } else {
            self.conn.commit(n);
        }
        Ok(())
    }

    /// Reads the next complete request. `Ok(None)` means the connection is
    /// finished (the client closed between requests, the previous exchange
    /// ended with `connection: close`, or the connection was upgraded).
    ///
    /// A request that carries `Expect: 100-continue` is answered with
    /// `100 Continue` before its body is read.
    ///
    /// # Errors
    ///
    /// [`Error::Http`] for a request this crate refuses (answer it with its
    /// [`HttpError::status`] and close), [`Error::Io`] for socket failures
    /// and timeouts (including the request deadline, as `TimedOut`), and
    /// [`Error::Http`] with [`HttpError::InvalidState`] if the previous
    /// request has not been answered.
    ///
    /// # Examples
    ///
    /// See [`Connection`].
    pub fn next_request(&mut self) -> Result<Option<Incoming<'_>>, Error> {
        self.body.clear();
        self.deadline = None;
        loop {
            match self.conn.poll()? {
                ServerEvent::Request(head) => {
                    // The whole body is read before the caller sees the
                    // request, so the expectation is answered here (RFC 9110
                    // section 10.1.1). A body over the limit was already
                    // refused from its Content-Length.
                    if head.expects_continue() {
                        self.out.clear();
                        self.conn.send_continue(&mut self.out)?;
                        self.flush_out()?;
                    }
                }
                ServerEvent::Body(chunk) => self.body.extend_from_slice(chunk),
                ServerEvent::RequestEnd => break,
                ServerEvent::NeedInput => self.fill()?,
                ServerEvent::AwaitingResponse => {
                    return Err(Error::Http(HttpError::InvalidState(
                        "respond to the previous request first",
                    )));
                }
                _ => return Ok(None),
            }
        }
        match self.conn.request() {
            Some(head) => Ok(Some(Incoming {
                head,
                body: &self.body,
            })),
            None => Ok(None),
        }
    }

    /// Writes `response` to the socket. A streamed response continues with
    /// [`send_body`](Self::send_body) and [`end_body`](Self::end_body).
    ///
    /// # Errors
    ///
    /// [`Error::Http`] when the response is invalid or out of order (see
    /// [`ServerConn::respond`]); [`Error::Io`] when the write fails.
    ///
    /// # Examples
    ///
    /// See [`Connection`].
    pub fn respond(&mut self, response: &Response) -> Result<(), Error> {
        self.out.clear();
        let date = http_date(SystemTime::now());
        self.conn
            .respond_dated(response, Some(&date), &mut self.out)?;
        self.flush_out()
    }

    /// Writes body bytes of a streamed response.
    ///
    /// # Errors
    ///
    /// As [`ServerConn::send_body`], plus [`Error::Io`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn demo(conn: &mut http_net::blocking::Connection) -> Result<(), http_net::blocking::Error> {
    /// conn.respond(&http_net::Response::new(200).chunked())?;
    /// conn.send_body(b"first")?;
    /// conn.end_body()?;
    /// # Ok(()) }
    /// ```
    pub fn send_body(&mut self, data: &[u8]) -> Result<(), Error> {
        self.out.clear();
        self.conn.send_body(data, &mut self.out)?;
        self.flush_out()
    }

    /// Ends a streamed response.
    ///
    /// # Errors
    ///
    /// As [`ServerConn::end_body`], plus [`Error::Io`].
    ///
    /// # Examples
    ///
    /// See [`send_body`](Self::send_body).
    pub fn end_body(&mut self) -> Result<(), Error> {
        self.out.clear();
        self.conn.end_body(&mut self.out)?;
        self.flush_out()
    }

    fn flush_out(&mut self) -> Result<(), Error> {
        self.stream.write_all(&self.out)?;
        if self.out.capacity() > OUT_RETAIN {
            self.out = Vec::new();
        }
        Ok(())
    }

    /// Whether a `101` (or a 2xx to `CONNECT`) was sent.
    ///
    /// # Examples
    ///
    /// See [`into_upgraded`](Self::into_upgraded).
    #[must_use]
    pub fn is_upgraded(&self) -> bool {
        self.conn.is_upgraded()
    }

    /// The socket and the bytes of the new protocol, after an upgrade;
    /// `None` if the connection was not upgraded. The socket's read timeout
    /// is the one it had when the `Connection` was created (a request
    /// deadline may have shortened it while the request was read).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn demo(mut conn: http_net::blocking::Connection) {
    /// if conn.is_upgraded() {
    ///     let up = conn.into_upgraded().unwrap();
    ///     // speak the new protocol on up.stream, starting with up.leftover
    /// #   let _ = up;
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn into_upgraded(self) -> Option<Upgraded> {
        if !self.is_upgraded() {
            return None;
        }
        let target = self
            .conn
            .request()
            .map(|r| r.target().to_string())
            .unwrap_or_default();
        if self.shortened {
            // Best effort: the new protocol must not inherit what was left
            // of the request deadline. Setting a timeout this socket has
            // already accepted does not fail in practice, and the hand-off
            // is more useful than refusing it over one.
            let _ = self.stream.set_read_timeout(self.read_timeout);
        }
        Some(Upgraded {
            leftover: self.conn.remaining_input().to_vec(),
            target,
            stream: self.stream,
        })
    }

    /// Closes the connection gracefully: stops sending, briefly drains what
    /// the client is still sending, and drops the socket.
    ///
    /// # Examples
    ///
    /// See [`Connection`].
    pub fn close(self) {
        drain_and_close(self.stream);
    }
}

/// A response fetched by [`get`] or [`Client::get`], fully read.
///
/// # Examples
///
/// See [`Server`].
#[derive(Clone, PartialEq, Eq)]
pub struct ClientResponse {
    status: u16,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

/// Shows status, fields, and body size; the values of credential fields
/// (`set-cookie` above all) are replaced by `<redacted N bytes>`.
impl fmt::Debug for ClientResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Fields<'a>(&'a [(String, Vec<u8>)]);
        impl fmt::Debug for Fields<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list()
                    .entries(self.0.iter().map(|(name, value)| {
                        (
                            name.as_str(),
                            FieldValue {
                                name: name.as_bytes(),
                                value,
                            },
                        )
                    }))
                    .finish()
            }
        }
        f.debug_struct("ClientResponse")
            .field("status", &self.status)
            .field("headers", &Fields(&self.headers))
            .field("body", &format_args!("{} bytes", self.body.len()))
            .finish()
    }
}

impl ClientResponse {
    /// The status code.
    ///
    /// # Examples
    ///
    /// See [`Server`].
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The fields in arrival order.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let resp = http_net::blocking::get("http://127.0.0.1:8080/")?;
    /// for (name, value) in resp.headers() {
    ///     let _ = (name, value);
    /// }
    /// # Ok::<(), http_net::blocking::Error>(())
    /// ```
    pub fn headers(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.headers.iter().map(|(n, v)| (n.as_str(), v.as_slice()))
    }

    /// The first field named `name` (ASCII case-insensitive).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let resp = http_net::blocking::get("http://127.0.0.1:8080/")?;
    /// let _ = resp.header("content-type");
    /// # Ok::<(), http_net::blocking::Error>(())
    /// ```
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }

    /// The body.
    ///
    /// # Examples
    ///
    /// See [`Server`].
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The body, if it is UTF-8.
    ///
    /// # Examples
    ///
    /// See [`Server`].
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        core::str::from_utf8(&self.body).ok()
    }

    /// Takes the body.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let bytes = http_net::blocking::get("http://127.0.0.1:8080/")?.into_body();
    /// # let _ = bytes;
    /// # Ok::<(), http_net::blocking::Error>(())
    /// ```
    #[must_use]
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }
}

/// Fetches `url` with `GET` using the default [`Client`].
///
/// # Errors
///
/// [`Error::InvalidUrl`] for anything but `http://host[:port][/path]`,
/// [`Error::Io`] for connection failures and timeouts, [`Error::Http`] for
/// a response this crate refuses (including one over the body limit).
///
/// # Examples
///
/// See [`Server`].
pub fn get(url: &str) -> Result<ClientResponse, Error> {
    Client::new().get(url)
}

/// A blocking HTTP/1.1 client: one connection per request.
///
/// | Setting | Default |
/// |---|---|
/// | limits | [`Limits::new`] with a 16 MiB body |
/// | connect, read, and write timeout | 30 s each |
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
/// use http_net::{blocking::Client, Limits};
///
/// let client = Client::new()
///     .with_limits(Limits::new().with_max_body(64 << 20))
///     .with_timeout(Duration::from_secs(5));
/// let resp = client.get("http://127.0.0.1:8080/big")?;
/// # let _ = resp;
/// # Ok::<(), http_net::blocking::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Client {
    limits: Limits,
    timeout: Duration,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// The defaults (see the table on [`Client`]).
    ///
    /// # Examples
    ///
    /// ```
    /// let _ = http_net::blocking::Client::new();
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limits: Limits::new().with_max_body(16 * 1024 * 1024),
            timeout: Duration::from_secs(30),
        }
    }

    /// Sets the response limits.
    ///
    /// # Examples
    ///
    /// ```
    /// let _ = http_net::blocking::Client::new().with_limits(http_net::Limits::new());
    /// ```
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets the connect, read, and write timeout (zero is raised to 1 ms).
    ///
    /// # Examples
    ///
    /// ```
    /// let _ = http_net::blocking::Client::new().with_timeout(std::time::Duration::from_secs(2));
    /// ```
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = if timeout.is_zero() {
            Duration::from_millis(1)
        } else {
            timeout
        };
        self
    }

    /// Fetches `url` with `GET`.
    ///
    /// # Errors
    ///
    /// As [`get`].
    ///
    /// # Examples
    ///
    /// See [`Client`].
    pub fn get(&self, url: &str) -> Result<ClientResponse, Error> {
        let url = Url::parse(url)?;
        let request = Request::get(url.target)
            .header("host", url.authority)
            .close();
        let mut stream = self.connect(&url)?;
        let mut conn = ClientConn::with_limits(self.limits);
        let mut out = Vec::new();
        conn.send_request(&request, &mut out)?;
        stream.write_all(&out)?;
        read_response(&mut stream, &mut conn)
    }

    fn connect(&self, url: &Url<'_>) -> Result<TcpStream, Error> {
        let mut last = None;
        for addr in (url.host, url.port).to_socket_addrs()? {
            match TcpStream::connect_timeout(&addr, self.timeout) {
                Ok(stream) => {
                    stream.set_read_timeout(Some(self.timeout))?;
                    stream.set_write_timeout(Some(self.timeout))?;
                    stream.set_nodelay(true)?;
                    return Ok(stream);
                }
                Err(e) => last = Some(e),
            }
        }
        Err(Error::Io(last.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "the host resolved to no address")
        })))
    }
}

fn read_response(stream: &mut TcpStream, conn: &mut ClientConn) -> Result<ClientResponse, Error> {
    let mut response = ClientResponse {
        status: 0,
        headers: Vec::new(),
        body: Vec::new(),
    };
    loop {
        match conn.poll()? {
            ClientEvent::Response(head) => {
                response.status = head.status();
                response.headers = head
                    .headers()
                    .map(|(n, v)| (n.to_string(), v.to_vec()))
                    .collect();
            }
            ClientEvent::Body(chunk) => response.body.extend_from_slice(chunk),
            ClientEvent::ResponseEnd => return Ok(response),
            ClientEvent::NeedInput => {
                let spare = conn.read_buf();
                if spare.is_empty() {
                    return Err(Error::Http(HttpError::InvalidState(
                        "input buffer full while the parser needs input",
                    )));
                }
                let n = loop {
                    match stream.read(spare) {
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        other => break other?,
                    }
                };
                if n == 0 {
                    conn.feed_eof();
                } else {
                    conn.commit(n);
                }
            }
            _ => {
                return Err(Error::Http(HttpError::InvalidState(
                    "the connection ended without a complete response",
                )));
            }
        }
    }
}

/// The parts of an `http://` URL needed to send a request.
#[derive(Debug, PartialEq, Eq)]
struct Url<'a> {
    /// `host[:port]` as written, for the Host header.
    authority: &'a str,
    /// The host for name resolution (brackets removed from IPv6 literals).
    host: &'a str,
    port: u16,
    /// Path and query; `/` when the URL has no path.
    target: &'a str,
}

impl<'a> Url<'a> {
    fn parse(url: &'a str) -> Result<Self, Error> {
        let scheme_end = url.find("://").ok_or(Error::InvalidUrl("missing scheme"))?;
        if !url[..scheme_end].eq_ignore_ascii_case("http") {
            return Err(Error::InvalidUrl(
                "only http:// is supported (no TLS in this crate)",
            ));
        }
        let rest = &url[scheme_end + 3..];
        // The fragment is never sent.
        let rest = rest.split_once('#').map_or(rest, |(r, _)| r);
        let auth_end = rest.find(['/', '?']).unwrap_or(rest.len());
        let authority = &rest[..auth_end];
        let target = match &rest[auth_end..] {
            "" => "/",
            t if t.starts_with('?') => {
                return Err(Error::InvalidUrl("a query needs a path, for example /?q"));
            }
            t => t,
        };
        if authority.is_empty() {
            return Err(Error::InvalidUrl("missing host"));
        }
        if authority.contains('@') {
            return Err(Error::InvalidUrl(
                "credentials in the URL are not supported",
            ));
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (inside, after) = v6.split_once(']').ok_or(Error::InvalidUrl("unclosed ["))?;
            let port = match after {
                "" => None,
                p => Some(
                    p.strip_prefix(':')
                        .ok_or(Error::InvalidUrl("junk after ]"))?,
                ),
            };
            (inside, port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            }
        };
        let port = match port {
            None => 80,
            Some(p) => p.parse().map_err(|_| Error::InvalidUrl("bad port"))?,
        };
        if host.is_empty() {
            return Err(Error::InvalidUrl("missing host"));
        }
        Ok(Self {
            authority,
            host,
            port,
            target,
        })
    }
}

/// Formats `time` as an IMF-fixdate (RFC 9110 section 5.6.7), for example
/// `Sun, 06 Nov 1994 08:49:37 GMT`.
fn http_date(time: SystemTime) -> [u8; 29] {
    let secs = time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    const WEEKDAYS: [&[u8; 3]; 7] = [b"Thu", b"Fri", b"Sat", b"Sun", b"Mon", b"Tue", b"Wed"];
    const MONTHS: [&[u8; 3]; 12] = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
        b"Dec",
    ];
    let mut out = *b"Thu, 01 Jan 1970 00:00:00 GMT";
    out[..3].copy_from_slice(WEEKDAYS[(days % 7) as usize]);
    two_digits(&mut out[5..7], day);
    out[8..11].copy_from_slice(MONTHS[(month - 1) as usize]);
    let y = year.min(9999);
    two_digits(&mut out[12..14], y / 100);
    two_digits(&mut out[14..16], y % 100);
    two_digits(&mut out[17..19], rem / 3600);
    two_digits(&mut out[20..22], rem % 3600 / 60);
    two_digits(&mut out[23..25], rem % 60);
    out
}

fn two_digits(dst: &mut [u8], v: u64) {
    if let [tens, ones] = dst {
        *tens = b'0' + (v / 10 % 10) as u8;
        *ones = b'0' + (v % 10) as u8;
    }
}

/// Days since 1970-01-01 to (year, month 1..=12, day 1..=31), after Howard
/// Hinnant's `civil_from_days`, restricted to dates on or after the epoch.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_date_known_values() {
        let at = |s: u64| UNIX_EPOCH + Duration::from_secs(s);
        assert_eq!(&http_date(at(0)), b"Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(
            &http_date(at(784_111_777)),
            b"Sun, 06 Nov 1994 08:49:37 GMT"
        );
        assert_eq!(
            &http_date(at(951_782_400)),
            b"Tue, 29 Feb 2000 00:00:00 GMT"
        );
        assert_eq!(
            &http_date(at(1_791_072_000)),
            b"Sun, 04 Oct 2026 00:00:00 GMT"
        );
    }

    #[test]
    fn test_url_parsing() {
        let u = Url::parse("http://127.0.0.1:8080/a/b?c=d#frag").unwrap();
        assert_eq!(
            u,
            Url {
                authority: "127.0.0.1:8080",
                host: "127.0.0.1",
                port: 8080,
                target: "/a/b?c=d"
            }
        );
        let u = Url::parse("HTTP://[::1]/").unwrap();
        assert_eq!((u.host, u.port, u.authority), ("::1", 80, "[::1]"));
        assert_eq!(Url::parse("http://example.com").unwrap().target, "/");
        for bad in [
            "example.com",
            "https://x/",
            "http:///x",
            "http://u:p@x/",
            "http://x:99999/",
            "http://[::1/",
            "http://[::1]x/",
            "http://x?q",
            "http://:80/",
        ] {
            assert!(
                matches!(Url::parse(bad), Err(Error::InvalidUrl(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn test_error_display_and_source() {
        use std::error::Error as _;
        let e = Error::from(HttpError::BareCr);
        assert!(e.to_string().starts_with("HTTP error"));
        assert!(e.source().is_some());
        let e = Error::from(io::Error::other("x"));
        assert!(e.source().is_some());
        assert!(Error::InvalidUrl("y").source().is_none());
    }
}
