//! The client side of an HTTP/1.1 connection, without I/O.

use alloc::vec::Vec;

use crate::{
    body::{Decoder, Encoder, Step, push_framing},
    buffer::Buffer,
    error::HttpError,
    head::{
        Asked, HeadKind, HeadScanner, Headers, ResponseHead, ResponseInfo, Scan,
        interpret_response, switches_to_offered,
    },
    limits::{Limits, MAX_PIPELINE_DEPTH},
    message::{OutBody, Request, check_trailers, push_last_chunk_with_trailers},
    method::Method,
    scan::find_byte,
    server::Progress,
};

/// The error for sending a body the server declined (a final status in
/// answer to `Expect: 100-continue`).
const REFUSED: HttpError = HttpError::InvalidState(
    "the server answered with a final status instead of 100 Continue; \
     the body must not be sent",
);

/// What a [`ClientConn`] has for the caller after [`poll`](ClientConn::poll).
///
/// # Examples
///
/// ```
/// use http_net::{ClientConn, ClientEvent, Request};
///
/// let mut conn = ClientConn::new();
/// let mut out = Vec::new();
/// conn.send_request(&Request::get("/").header("host", "example.com"), &mut out).unwrap();
/// let _ = conn.feed(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n");
/// let mut body = Vec::new();
/// loop {
///     match conn.poll().unwrap() {
///         ClientEvent::Response(resp) => assert_eq!(resp.status(), 200),
///         ClientEvent::Body(chunk) => body.extend_from_slice(chunk),
///         ClientEvent::ResponseEnd => break,
///         other => panic!("{other:?}"),
///     }
/// }
/// assert_eq!(body, b"abc");
/// ```
#[non_exhaustive]
pub enum ClientEvent<'a> {
    /// The final response head arrived. Its body follows as
    /// [`Body`](ClientEvent::Body) events, then
    /// [`ResponseEnd`](ClientEvent::ResponseEnd). Interim (1xx) responses
    /// before it are skipped unless
    /// [`set_report_informational`](ClientConn::set_report_informational)
    /// asked for them; either way they count against
    /// [`Limits::max_interim`](crate::Limits::max_interim) and, together,
    /// [`Limits::max_header_bytes`](crate::Limits::max_header_bytes).
    Response(ResponseHead<'a>),
    /// An interim response other than `101` (for example `103 Early Hints`,
    /// or `102 Processing`), only with
    /// [`set_report_informational(true)`](ClientConn::set_report_informational).
    /// The final response follows.
    Informational(ResponseHead<'a>),
    /// The server answered `100 Continue` to a request built with
    /// [`Request::expect_continue`](crate::Request::expect_continue): send
    /// the body now.
    Continue,
    /// A run of body bytes, after chunked decoding.
    Body(&'a [u8]),
    /// The response's trailer fields, just before
    /// [`ResponseEnd`](ClientEvent::ResponseEnd): only with
    /// [`set_report_trailers(true)`](ClientConn::set_report_trailers) and a
    /// non-empty trailer section.
    Trailers(Headers<'a>),
    /// The response is complete.
    ResponseEnd,
    /// More input is needed (or, for a body that runs until close,
    /// [`feed_eof`](ClientConn::feed_eof) once the server closes).
    NeedInput,
    /// No request is outstanding; send the next one.
    Idle,
    /// The server switched protocols (101 to an upgrade request, or 2xx to
    /// `CONNECT`); the response head was reported just before. Bytes of the
    /// new protocol that already arrived are in
    /// [`remaining_input`](ClientConn::remaining_input).
    Upgraded,
    /// The connection cannot carry another request: close the socket.
    Closed,
}

/// Body bytes print as their length: a body can carry credentials that no
/// field redaction sees (a token in a JSON answer).
impl core::fmt::Debug for ClientEvent<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Response(head) => f.debug_tuple("Response").field(head).finish(),
            Self::Informational(head) => f.debug_tuple("Informational").field(head).finish(),
            Self::Continue => f.write_str("Continue"),
            Self::Body(bytes) => f
                .debug_tuple("Body")
                .field(&format_args!("{} bytes", bytes.len()))
                .finish(),
            Self::Trailers(fields) => f.debug_tuple("Trailers").field(fields).finish(),
            Self::ResponseEnd => f.write_str("ResponseEnd"),
            Self::NeedInput => f.write_str("NeedInput"),
            Self::Idle => f.write_str("Idle"),
            Self::Upgraded => f.write_str("Upgraded"),
            Self::Closed => f.write_str("Closed"),
        }
    }
}

/// Opt-in tolerances for responses a strict client would refuse. All are
/// off by default; requests are never parsed leniently.
///
/// - `obs_fold_in_responses`: replace each obsolete line fold in a response
///   head (a field line continued on the next line, which begins with a
///   space or tab) by overwriting the fold's CR and LF with spaces, as RFC
///   9112 section 5.2 tells a user agent to do. The rewrite happens in
///   place in the connection's buffer, so offsets do not move, views stay
///   borrowed, and nothing is allocated. Whitespace before the first field
///   is still refused.
///
/// Bare LF, bare CR, `Content-Length` with `Transfer-Encoding`, and
/// whitespace before a colon are never tolerated: they are how messages
/// get framed differently by different hops.
///
/// # Examples
///
/// ```
/// use http_net::{ClientConn, ClientEvent, ClientLeniency, Request};
///
/// let mut conn = ClientConn::new();
/// conn.set_leniency(ClientLeniency::new().with_obs_fold_in_responses(true));
/// conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())?;
/// let _ = conn.feed(b"HTTP/1.1 200 OK\r\nX-Long: part one,\r\n part two\r\nContent-Length: 0\r\n\r\n");
/// let ClientEvent::Response(resp) = conn.poll()? else { panic!() };
/// assert_eq!(resp.header("x-long"), Some(&b"part one,   part two"[..]));
/// # Ok::<(), http_net::HttpError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ClientLeniency {
    /// Replace obs-folds in response fields with spaces instead of refusing
    /// them with [`HttpError::ObsFold`].
    pub obs_fold_in_responses: bool,
}

impl ClientLeniency {
    /// Every tolerance off (the strict default).
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(!http_net::ClientLeniency::new().obs_fold_in_responses);
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            obs_fold_in_responses: false,
        }
    }

    /// Sets [`obs_fold_in_responses`](Self::obs_fold_in_responses).
    ///
    /// # Examples
    ///
    /// ```
    /// let l = http_net::ClientLeniency::new().with_obs_fold_in_responses(true);
    /// assert!(l.obs_fold_in_responses);
    /// ```
    #[must_use]
    pub const fn with_obs_fold_in_responses(mut self, on: bool) -> Self {
        self.obs_fold_in_responses = on;
        self
    }
}

/// The in-place obs-fold rewrite of one response head. It walks the head's
/// line ends once, overall linear however the input is split, and tells the
/// head scanner how much it may see: a line end whose next byte has not
/// arrived is held back, because only that byte says whether the line is
/// folded. The scanner therefore never completes a field line that is about
/// to be continued.
#[derive(Clone, Copy, Debug)]
struct Unfold {
    /// Where the search for the next LF resumes.
    scan: usize,
    /// Start of the line being examined.
    line_start: usize,
    /// The status line has ended (it is never folded).
    past_status: bool,
    /// The blank line that ends the head was seen.
    done: bool,
}

impl Unfold {
    const fn new() -> Self {
        Self {
            scan: 0,
            line_start: 0,
            past_status: false,
            done: false,
        }
    }

    /// Rewrites the folds found in `msg` (the head so far) and returns how
    /// many of its bytes the head scanner may examine.
    fn run(&mut self, msg: &mut [u8], eof: bool) -> usize {
        if self.done {
            return msg.len();
        }
        loop {
            let Some(off) = msg.get(self.scan..).and_then(|rest| find_byte(b'\n', rest)) else {
                self.scan = msg.len();
                return msg.len();
            };
            let lf = self.scan + off;
            if !self.past_status {
                self.past_status = true;
                self.line_start = lf + 1;
                self.scan = lf + 1;
                continue;
            }
            // line_start <= lf: it only ever moves to just past an LF.
            let line = msg.get(self.line_start..lf).unwrap_or(&[]);
            if line.is_empty() || line == b"\r" {
                self.done = true;
                return msg.len();
            }
            let crlf = lf > 0 && msg.get(lf - 1) == Some(&b'\r');
            match msg.get(lf + 1) {
                None if eof => {
                    self.scan = msg.len();
                    return msg.len();
                }
                None => {
                    // Revisit this LF once its next byte arrives.
                    self.scan = lf;
                    return lf;
                }
                Some(&b) if crlf && (b == b' ' || b == b'\t') => {
                    // RFC 9112 section 5.2: replace the fold with SP. The
                    // line goes on, so its start stays where it was.
                    msg[lf - 1] = b' ';
                    msg[lf] = b' ';
                    self.scan = lf + 1;
                }
                Some(_) => {
                    self.line_start = lf + 1;
                    self.scan = lf + 1;
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Idle,
    Head,
    /// An interim head was reported and is still pinned; the next poll
    /// drops it and waits for the next head.
    Interim,
    Body,
    Complete,
    Upgraded,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReqWrite {
    Streaming(Encoder),
    Sent,
}

/// The client side of one HTTP/1.1 connection: a sans-IO state machine.
///
/// By default one request is outstanding at a time; with
/// [`Limits::with_pipeline_depth`], idempotent requests may be pipelined
/// behind it (see [`can_send`](Self::can_send)).
/// [`send_request`](Self::send_request)
/// serializes a [`Request`]; [`feed`](Self::feed) and [`poll`](Self::poll)
/// parse the response. When the response allows it, the connection returns
/// to [`ClientEvent::Idle`] and can send the next request (keep-alive).
///
/// The response is framed with the request in mind: a `HEAD` request's
/// response has no body whatever its headers say, a `CONNECT` 2xx becomes a
/// tunnel, and a response with neither `Content-Length` nor
/// `Transfer-Encoding` runs until the server closes.
///
/// # Examples
///
/// ```
/// use http_net::{ClientConn, ClientEvent, Request};
///
/// let mut conn = ClientConn::new();
/// let mut out = Vec::new();
/// conn.send_request(&Request::get("/a").header("host", "h"), &mut out).unwrap();
/// assert_eq!(out, b"GET /a HTTP/1.1\r\nhost: h\r\n\r\n");
/// let _ = conn.feed(b"HTTP/1.1 204 No Content\r\n\r\n");
/// assert!(matches!(conn.poll().unwrap(), ClientEvent::Response(_)));
/// assert!(matches!(conn.poll().unwrap(), ClientEvent::ResponseEnd));
/// assert!(matches!(conn.poll().unwrap(), ClientEvent::Idle));
/// ```
pub struct ClientConn {
    buf: Buffer,
    limits: Limits,
    scanner: HeadScanner,
    trailers: HeadScanner,
    decoder: Decoder,
    info: ResponseInfo,
    asked: Asked,
    upgrade_asked: bool,
    /// The protocols the outstanding upgrade request offered, comma
    /// separated; a `101` may switch only to these.
    upgrade_offer: Vec<u8>,
    state: State,
    req: ReqWrite,
    keep_alive: bool,
    /// Bytes of interim (1xx) heads seen for the current request. They
    /// count against the header budget so that a server cannot keep the
    /// client parsing forever without answering.
    interim_bytes: usize,
    /// Interim heads seen for the current request, against `max_interim`.
    interim_count: u16,
    report_interim: bool,
    report_trailers: bool,
    /// The request was sent with `Expect: 100-continue` and neither a `100`,
    /// a final response, nor body bytes have happened since.
    waiting_continue: bool,
    /// A final response arrived while waiting for `100`: the promised body
    /// must not be sent, and the connection closes after the response.
    body_refused: bool,
    /// The request body was declared chunked (trailers allowed).
    req_chunked: bool,
    /// The request being answered is idempotent (it may share the
    /// connection with pipelined requests).
    idempotent: bool,
    /// Requests sent after the one being answered, in order: a fixed ring,
    /// so pipelining allocates nothing after construction.
    queue: [Queued; MAX_PIPELINE_DEPTH as usize],
    queue_start: usize,
    queued: usize,
    leniency: ClientLeniency,
    /// Where the obs-fold rewrite stopped in the current response head.
    unfold: Unfold,
}

/// A pipelined request waiting for its response: what framing its response
/// needs and whether it asked to close.
#[derive(Clone, Copy, Debug)]
struct Queued {
    asked: Asked,
    close: bool,
}

/// Writes the request line, fields, framing, and (for a full body) the body;
/// returns how the rest of the body, if any, is to be written.
fn write_request(request: &Request, out: &mut Vec<u8>) -> Result<ReqWrite, HttpError> {
    let method = request.method_kind;
    let expects_body = matches!(method, Method::Post | Method::Put | Method::Patch);
    let (mut encoder, declared) = match &request.body {
        OutBody::Full(b) if b.is_empty() && !expects_body => (Encoder::Discard, None),
        OutBody::Full(b) => (
            Encoder::Length {
                remaining: b.len() as u64,
            },
            Some(b.len() as u64),
        ),
        OutBody::Length(n) => (Encoder::Length { remaining: *n }, Some(*n)),
        OutBody::Chunked => (Encoder::Chunked, None),
    };
    out.extend_from_slice(request.method().as_bytes());
    out.push(b' ');
    out.extend_from_slice(request.target().as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    out.extend_from_slice(request.fields());
    push_framing(out, encoder, declared);
    if request.close {
        out.extend_from_slice(b"connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    match &request.body {
        OutBody::Full(b) => {
            encoder.write(b, out)?;
            Ok(ReqWrite::Sent)
        }
        _ => Ok(ReqWrite::Streaming(encoder)),
    }
}

const NO_QUEUED: Queued = Queued {
    asked: Asked {
        head: false,
        connect: false,
    },
    close: false,
};

impl Default for ClientConn {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for ClientConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientConn")
            .field("state", &self.state)
            .field("request", &self.req)
            .field("buffered", &self.buf.unread().len())
            .field("limits", &self.limits)
            .finish()
    }
}

impl ClientConn {
    /// A connection with the default [`Limits`].
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = http_net::ClientConn::new();
    /// assert!(matches!(conn.poll(), Ok(http_net::ClientEvent::Idle)));
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(Limits::new())
    }

    /// A connection enforcing `limits` on responses.
    ///
    /// # Examples
    ///
    /// ```
    /// let conn = http_net::ClientConn::with_limits(http_net::Limits::new().with_max_body(1 << 24));
    /// assert_eq!(conn.limits().max_body(), 1 << 24);
    /// ```
    #[must_use]
    pub fn with_limits(limits: Limits) -> Self {
        Self::from_buffer(Buffer::new(limits.buffer_capacity()), limits)
    }

    /// A connection enforcing `limits` that reads into `storage` (its
    /// capacity is used up to [`Limits::buffer_capacity`], its contents are
    /// ignored), for drivers that pool buffers. Give it back with
    /// [`into_buffer`](Self::into_buffer).
    ///
    /// # Examples
    ///
    /// ```
    /// let conn = http_net::ClientConn::with_buffer(Vec::with_capacity(4096), http_net::Limits::new());
    /// assert!(conn.into_buffer().capacity() >= 4096);
    /// ```
    #[must_use]
    pub fn with_buffer(storage: Vec<u8>, limits: Limits) -> Self {
        Self::from_buffer(
            Buffer::with_storage(storage, limits.buffer_capacity()),
            limits,
        )
    }

    fn from_buffer(buf: Buffer, limits: Limits) -> Self {
        Self {
            buf,
            limits,
            scanner: HeadScanner::new(),
            trailers: HeadScanner::new(),
            decoder: Decoder::new(),
            info: ResponseInfo::EMPTY,
            asked: Asked {
                head: false,
                connect: false,
            },
            upgrade_asked: false,
            upgrade_offer: Vec::new(),
            state: State::Idle,
            req: ReqWrite::Sent,
            keep_alive: true,
            interim_bytes: 0,
            interim_count: 0,
            report_interim: false,
            report_trailers: false,
            waiting_continue: false,
            body_refused: false,
            req_chunked: false,
            idempotent: true,
            queue: [NO_QUEUED; MAX_PIPELINE_DEPTH as usize],
            queue_start: 0,
            queued: 0,
            leniency: ClientLeniency::new(),
            unfold: Unfold::new(),
        }
    }

    /// The limits this connection enforces.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::ClientConn::new().limits().max_headers(), 100);
    /// ```
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Copies as much of `bytes` into the input buffer as fits; returns how
    /// many were taken (see [`ServerConn::feed`](crate::ServerConn::feed)).
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = http_net::ClientConn::new();
    /// assert_eq!(conn.feed(b"HTTP/1.1"), 8);
    /// ```
    #[must_use = "bytes beyond the returned count were not taken"]
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        self.buf.feed(bytes)
    }

    /// Spare space at the end of the input buffer; follow with
    /// [`commit`](Self::commit).
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = http_net::ClientConn::new();
    /// assert!(!conn.read_buf().is_empty());
    /// ```
    pub fn read_buf(&mut self) -> &mut [u8] {
        self.buf.spare()
    }

    /// Records that `n` bytes were written into [`read_buf`](Self::read_buf).
    /// An `n` larger than the slice `read_buf` returned is clamped to its
    /// length: committing bytes that were not written would hand stale
    /// buffer contents to the parser.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = http_net::ClientConn::new();
    /// conn.read_buf()[..4].copy_from_slice(b"HTTP");
    /// conn.commit(4);
    /// ```
    pub fn commit(&mut self, n: usize) {
        self.buf.commit(n);
    }

    /// Records that the server closed its sending side: ends a body that
    /// runs until close, or reports [`HttpError::UnexpectedEof`] mid-message.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ClientConn, ClientEvent, Request};
    ///
    /// let mut conn = ClientConn::new();
    /// conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new()).unwrap();
    /// let _ = conn.feed(b"HTTP/1.0 200 OK\r\n\r\nall of it");
    /// assert!(matches!(conn.poll().unwrap(), ClientEvent::Response(_)));
    /// assert!(matches!(conn.poll().unwrap(), ClientEvent::Body(b"all of it")));
    /// assert!(matches!(conn.poll().unwrap(), ClientEvent::NeedInput));
    /// conn.feed_eof();
    /// assert!(matches!(conn.poll().unwrap(), ClientEvent::ResponseEnd));
    /// assert!(matches!(conn.poll().unwrap(), ClientEvent::Closed));
    /// ```
    pub fn feed_eof(&mut self) {
        self.buf.set_eof();
    }

    /// Writes `request` into `out` and starts waiting for its response.
    ///
    /// A full body is sent with `content-length` (omitted for an empty body
    /// on methods that do not expect one); a streamed body continues with
    /// [`send_body`](Self::send_body) and [`end_body`](Self::end_body).
    ///
    /// A request built with [`Request::expect_continue`] is sent head first:
    /// [`is_waiting_for_continue`](Self::is_waiting_for_continue) is true
    /// until the server answers `100 Continue` (reported as
    /// [`ClientEvent::Continue`]: then send the body), a final status (then
    /// the body must not be sent and the connection closes after the
    /// response), or the caller sends the body anyway (RFC 9110 section
    /// 10.1.1 allows it after a wait of its choosing).
    ///
    /// # Errors
    ///
    /// - the first error recorded by the [`Request`] builder;
    /// - [`HttpError::MissingHost`] when the request has no `host` header;
    /// - [`HttpError::InvalidState`] when a request is outstanding and this
    ///   one cannot be pipelined (depth 1, depth full, or not idempotent with
    ///   a full body; see [`can_send`](Self::can_send)), when the connection
    ///   is closed or upgraded, or when an `expect_continue` request has a
    ///   full body (it needs `content_length` or `chunked`);
    /// - [`HttpError::UnexpectedData`] when response bytes nobody asked for
    ///   are buffered.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ClientConn, HttpError, Request};
    ///
    /// let mut conn = ClientConn::new();
    /// let mut out = Vec::new();
    /// assert_eq!(conn.send_request(&Request::get("/"), &mut out), Err(HttpError::MissingHost));
    /// conn.send_request(&Request::post("/f").header("host", "a").body(&b"xyz"[..]), &mut out).unwrap();
    /// assert_eq!(out, b"POST /f HTTP/1.1\r\nhost: a\r\ncontent-length: 3\r\n\r\nxyz");
    /// ```
    pub fn send_request(&mut self, request: &Request, out: &mut Vec<u8>) -> Result<(), HttpError> {
        if let Some(e) = request.error() {
            return Err(e);
        }
        match self.state {
            State::Idle => {}
            State::Closed | State::Upgraded => {
                return Err(HttpError::InvalidState(
                    "the connection is closed or upgraded",
                ));
            }
            _ => return self.send_pipelined(request, out),
        }
        if !self.buf.unread().is_empty() {
            return Err(HttpError::UnexpectedData);
        }
        if !request.has_host {
            return Err(HttpError::MissingHost);
        }
        if request.expect_continue && matches!(request.body, OutBody::Full(_)) {
            // The point of the expectation is to hold the body back until
            // the server agrees; a full body would be written at once.
            return Err(HttpError::InvalidState(
                "expect_continue needs a streamed body (content_length or chunked), \
                 sent after ClientEvent::Continue",
            ));
        }
        let method = request.method_kind;
        self.req = write_request(request, out)?;
        self.asked = Asked {
            head: method == Method::Head,
            connect: method == Method::Connect,
        };
        self.upgrade_asked = request.upgrade;
        if request.upgrade {
            self.upgrade_offer.clear();
            for offer in request.upgrade_offers() {
                if !self.upgrade_offer.is_empty() {
                    self.upgrade_offer.push(b',');
                }
                self.upgrade_offer.extend_from_slice(offer);
            }
        }
        self.keep_alive = !request.close;
        self.idempotent = method.is_idempotent();
        self.req_chunked = matches!(request.body, OutBody::Chunked);
        self.waiting_continue = request.expect_continue;
        self.body_refused = false;
        self.buf.unpin();
        self.buf.pin_at_pos();
        self.scanner.reset();
        self.unfold = Unfold::new();
        self.interim_bytes = 0;
        self.interim_count = 0;
        self.state = State::Head;
        Ok(())
    }

    /// Sends `request` behind the ones already outstanding (pipelining).
    fn send_pipelined(&mut self, request: &Request, out: &mut Vec<u8>) -> Result<(), HttpError> {
        if !self.can_send() {
            return Err(HttpError::InvalidState(
                if self.limits.pipeline_depth() <= 1 {
                    "a request is already outstanding (raise Limits::with_pipeline_depth to pipeline)"
                } else {
                    "pipelining needs room in the pipeline depth, idempotent requests, \
                 every earlier body sent, and no close, upgrade, CONNECT, or expectation"
                },
            ));
        }
        if !request.has_host {
            return Err(HttpError::MissingHost);
        }
        let method = request.method_kind;
        if !method.is_idempotent()
            || request.upgrade
            || request.expect_continue
            || !matches!(request.body, OutBody::Full(_))
        {
            return Err(HttpError::InvalidState(
                "only idempotent requests with a full body and no upgrade or expectation \
                 can be pipelined",
            ));
        }
        let req = write_request(request, out)?;
        debug_assert_eq!(req, ReqWrite::Sent);
        let slot = (self.queue_start + self.queued) % self.queue.len();
        self.queue[slot] = Queued {
            asked: Asked {
                head: method == Method::Head,
                connect: false,
            },
            close: request.close,
        };
        self.queued += 1;
        Ok(())
    }

    /// Starts on the response to the oldest queued request.
    fn next_queued(&mut self) {
        let next = self.queue[self.queue_start];
        self.queue_start = (self.queue_start + 1) % self.queue.len();
        self.queued -= 1;
        self.asked = next.asked;
        self.keep_alive = !next.close;
        self.upgrade_asked = false;
        self.idempotent = true;
        self.req_chunked = false;
        self.waiting_continue = false;
        self.body_refused = false;
        self.buf.unpin();
        self.buf.pin_at_pos();
        self.scanner.reset();
        self.interim_bytes = 0;
        self.interim_count = 0;
        self.state = State::Head;
    }

    /// Whether any outstanding request asked to close the connection.
    fn closing(&self) -> bool {
        !self.keep_alive
            || (0..self.queued).any(|i| self.queue[(self.queue_start + i) % self.queue.len()].close)
    }

    /// The number of requests sent whose response has not completed:
    /// 0 when idle, up to [`Limits::pipeline_depth`] when pipelining. After
    /// the connection closed it is the number of requests that never got
    /// a response (send them again on a new connection if they are safe to
    /// repeat).
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ClientConn, Limits, Request};
    ///
    /// let mut conn = ClientConn::with_limits(Limits::new().with_pipeline_depth(4));
    /// let get = |p: &str| Request::get(p).header("host", "a");
    /// let mut out = Vec::new();
    /// conn.send_request(&get("/1"), &mut out)?;
    /// conn.send_request(&get("/2"), &mut out)?;
    /// assert_eq!(conn.outstanding(), 2);
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    #[must_use]
    pub fn outstanding(&self) -> usize {
        match self.state {
            State::Idle => 0,
            State::Head | State::Interim | State::Body => 1 + self.queued,
            State::Complete | State::Closed | State::Upgraded => self.queued,
        }
    }

    /// Whether [`send_request`](Self::send_request) would accept another
    /// request now. With no request outstanding: the connection is open
    /// and nothing unsolicited is buffered. With requests outstanding
    /// (pipelining): fewer than [`Limits::pipeline_depth`] are outstanding,
    /// all of them are idempotent with their bodies fully sent, none asked
    /// to close, upgrade, `CONNECT`, or expect `100 Continue`, and the
    /// response being read, once its head has arrived, keeps the connection
    /// open (RFC 9112 section 9.6: after `close`, or a response that ends
    /// with the connection, the client sends nothing more). The new request
    /// must also be idempotent with a full body (RFC 9112 section 9.3.2: a
    /// client should not pipeline non-idempotent requests).
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ClientConn, Limits, Request};
    ///
    /// let mut conn = ClientConn::new(); // depth 1: no pipelining
    /// assert!(conn.can_send());
    /// conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())?;
    /// assert!(!conn.can_send());
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    #[must_use]
    pub fn can_send(&self) -> bool {
        match self.state {
            State::Idle => self.buf.unread().is_empty() && !self.buf.is_eof(),
            State::Closed | State::Upgraded => false,
            State::Head | State::Interim | State::Body | State::Complete => {
                self.outstanding() < usize::from(self.limits.pipeline_depth())
                    && self.idempotent
                    && self.req == ReqWrite::Sent
                    && !self.closing()
                    && !self.upgrade_asked
                    && !self.asked.connect
                    && !self.waiting_continue
                    && !self.body_refused
                    && !self.buf.is_eof()
                    && (matches!(self.state, State::Head | State::Interim) || self.info.keep_alive)
            }
        }
    }

    /// Returns the connection to its initial state for a new socket,
    /// keeping the buffer and field-index allocations and the limits and
    /// reporting settings. Requests still outstanding are forgotten.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ClientConn, Progress, Request};
    ///
    /// let mut conn = ClientConn::new();
    /// conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())?;
    /// conn.reset();
    /// assert_eq!(conn.progress(), Progress::Idle);
    /// assert!(conn.can_send());
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    pub fn reset(&mut self) {
        self.buf.reset();
        self.scanner.reset();
        self.trailers.reset();
        self.decoder = Decoder::new();
        self.info = ResponseInfo::EMPTY;
        self.asked = NO_QUEUED.asked;
        self.upgrade_asked = false;
        self.state = State::Idle;
        self.req = ReqWrite::Sent;
        self.keep_alive = true;
        self.interim_bytes = 0;
        self.interim_count = 0;
        self.waiting_continue = false;
        self.body_refused = false;
        self.req_chunked = false;
        self.idempotent = true;
        self.queue_start = 0;
        self.queued = 0;
    }

    /// Gives the input buffer's storage back, for a pool.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::ClientConn::new().into_buffer().capacity(), 0);
    /// ```
    #[must_use]
    pub fn into_buffer(mut self) -> Vec<u8> {
        self.buf.take_storage()
    }

    /// Frees the input buffer and the field indexes while no request is
    /// outstanding and nothing is buffered. Returns whether memory was
    /// released.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ClientConn, ClientEvent, Request};
    ///
    /// let mut conn = ClientConn::new();
    /// conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())?;
    /// let _ = conn.feed(b"HTTP/1.1 204 No Content\r\n\r\n");
    /// while !matches!(conn.poll()?, ClientEvent::Idle) {}
    /// assert!(conn.shrink_idle());
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    pub fn shrink_idle(&mut self) -> bool {
        if self.state != State::Idle {
            return false;
        }
        self.buf.unpin();
        let freed = self.buf.shrink();
        if freed {
            self.scanner.fields = Vec::new();
            self.trailers.fields = Vec::new();
        }
        freed
    }

    /// Writes body bytes of a streamed request.
    ///
    /// Sending body bytes while waiting for `100 Continue` ends the wait.
    ///
    /// # Errors
    ///
    /// [`HttpError::BodyLengthMismatch`] past the declared length;
    /// [`HttpError::InvalidState`] when no streamed request is in progress,
    /// or when the server answered an `expect_continue` request with a final
    /// status (the body must not be sent then).
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ClientConn, Request};
    ///
    /// let mut conn = ClientConn::new();
    /// let mut out = Vec::new();
    /// conn.send_request(&Request::post("/up").header("host", "a").chunked(), &mut out).unwrap();
    /// conn.send_body(b"part", &mut out).unwrap();
    /// conn.end_body(&mut out).unwrap();
    /// assert!(out.ends_with(b"4\r\npart\r\n0\r\n\r\n"));
    /// ```
    pub fn send_body(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), HttpError> {
        if self.body_refused {
            return Err(REFUSED);
        }
        match &mut self.req {
            ReqWrite::Streaming(encoder) => {
                encoder.write(data, out)?;
                self.waiting_continue = false;
                Ok(())
            }
            ReqWrite::Sent => Err(HttpError::InvalidState("no streamed request in progress")),
        }
    }

    /// Ends a streamed request body.
    ///
    /// # Errors
    ///
    /// [`HttpError::BodyLengthMismatch`] when fewer bytes than declared were
    /// sent; [`HttpError::InvalidState`] when no streamed request is in
    /// progress, or when the server answered an `expect_continue` request
    /// with a final status (the body must not be sent then).
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ClientConn, Request};
    ///
    /// let mut conn = ClientConn::new();
    /// let mut out = Vec::new();
    /// conn.send_request(&Request::post("/").header("host", "a").content_length(2), &mut out).unwrap();
    /// conn.send_body(b"ok", &mut out).unwrap();
    /// conn.end_body(&mut out).unwrap();
    /// assert!(out.ends_with(b"\r\n\r\nok"));
    /// ```
    pub fn end_body(&mut self, out: &mut Vec<u8>) -> Result<(), HttpError> {
        self.end_body_with_trailers(&[], out)
    }

    /// Ends a streamed chunked request body with a trailer section (see
    /// [`ServerConn::end_body_with_trailers`](crate::ServerConn::end_body_with_trailers)
    /// for the fields that are refused).
    ///
    /// # Errors
    ///
    /// [`HttpError::TrailerNotAllowed`] for a forbidden field or a body
    /// that is not chunked; the field errors of
    /// [`Request::header`]; otherwise as [`end_body`](Self::end_body).
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ClientConn, Request};
    ///
    /// let mut conn = ClientConn::new();
    /// let mut out = Vec::new();
    /// conn.send_request(&Request::put("/f").header("host", "a").chunked(), &mut out)?;
    /// conn.send_body(b"data", &mut out)?;
    /// conn.end_body_with_trailers(&[("content-digest", b"sha-256=:x:")], &mut out)?;
    /// assert!(out.ends_with(b"0\r\ncontent-digest: sha-256=:x:\r\n\r\n"));
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    pub fn end_body_with_trailers(
        &mut self,
        trailers: &[(&str, &[u8])],
        out: &mut Vec<u8>,
    ) -> Result<(), HttpError> {
        if self.body_refused {
            return Err(REFUSED);
        }
        let ReqWrite::Streaming(encoder) = &mut self.req else {
            return Err(HttpError::InvalidState("no streamed request in progress"));
        };
        if !trailers.is_empty() && !self.req_chunked {
            return Err(HttpError::TrailerNotAllowed);
        }
        if *encoder == Encoder::Chunked {
            push_last_chunk_with_trailers(out, trailers)?;
        } else {
            check_trailers(trailers)?;
            encoder.finish(out)?;
        }
        self.req = ReqWrite::Sent;
        self.waiting_continue = false;
        Ok(())
    }

    /// Advances the response parser and reports what happened.
    ///
    /// # Errors
    ///
    /// Any [`HttpError`] parse error; the connection is then closed and must
    /// not be reused.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ClientConn, HttpError, Request};
    ///
    /// let mut conn = ClientConn::new();
    /// conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new()).unwrap();
    /// let _ = conn.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx");
    /// assert_eq!(conn.poll().unwrap_err(), HttpError::DuplicateContentLength);
    /// ```
    pub fn poll(&mut self) -> Result<ClientEvent<'_>, HttpError> {
        loop {
            match self.state {
                State::Idle => {
                    if !self.buf.unread().is_empty() {
                        return Err(self.fail(HttpError::UnexpectedData));
                    }
                    if self.buf.is_eof() {
                        self.state = State::Closed;
                        return Ok(ClientEvent::Closed);
                    }
                    return Ok(ClientEvent::Idle);
                }
                State::Head => return self.poll_head(),
                State::Interim => {
                    self.next_head();
                    self.state = State::Head;
                }
                State::Body => return self.poll_body(),
                State::Complete => {
                    if self.reusable() && self.queued > 0 {
                        // Pipelined: the next response is for the oldest
                        // queued request, and may already be buffered.
                        self.next_queued();
                    } else if self.reusable() {
                        self.state = State::Idle;
                    } else {
                        // Queued requests, if any, will get no response;
                        // `outstanding()` says how many.
                        self.state = State::Closed;
                        return Ok(ClientEvent::Closed);
                    }
                }
                State::Upgraded => return Ok(ClientEvent::Upgraded),
                State::Closed => return Ok(ClientEvent::Closed),
            }
        }
    }

    fn poll_head(&mut self) -> Result<ClientEvent<'_>, HttpError> {
        loop {
            let start = self.buf.pin();
            let visible = if self.leniency.obs_fold_in_responses {
                let eof = self.buf.is_eof();
                self.unfold.run(self.buf.tail_mut(start), eof)
            } else {
                self.buf.from(start).len()
            };
            let msg = self.buf.from(start);
            let progress = self
                .scanner
                .advance(
                    msg.get(..visible).unwrap_or(msg),
                    &self.limits,
                    HeadKind::Response,
                    true,
                )
                .map_err(|e| self.fail(e))?;
            let len = match progress {
                Scan::Partial if self.buf.is_eof() => {
                    return Err(self.fail(HttpError::UnexpectedEof));
                }
                Scan::Partial => return Ok(ClientEvent::NeedInput),
                Scan::Done(len) => len,
            };
            let info = interpret_response(
                self.buf.from(start),
                self.scanner.start_line(),
                &self.scanner.fields,
                &self.limits,
                self.asked,
            )
            .map_err(|e| self.fail(e))?;
            self.buf.consume(len);
            self.buf.extend_pin_to_pos();
            self.info = info;
            let status = info.status;
            let switched = if status == 101 {
                // RFC 9110 section 7.8: a 101 names the protocols it switches
                // to, and only to ones the request offered.
                let offered = self.upgrade_asked
                    && info.upgrade_field
                    && switches_to_offered(
                        self.buf.from(start),
                        &self.scanner.fields,
                        &self.upgrade_offer,
                    );
                if !offered {
                    return Err(self.fail(HttpError::UnexpectedUpgrade));
                }
                true
            } else {
                self.asked.connect && (200..300).contains(&status)
            };
            if switched {
                self.waiting_continue = false;
                self.state = State::Upgraded;
            } else if (100..200).contains(&status) {
                // Interim response (100 Continue, 103 Early Hints): budgeted
                // by count and by bytes, so a server cannot keep the client
                // parsing forever without a final answer.
                self.interim_count = self.interim_count.saturating_add(1);
                if self.interim_count > self.limits.max_interim() {
                    return Err(self.fail(HttpError::TooManyInterim));
                }
                self.interim_bytes = self.interim_bytes.saturating_add(len);
                if self.interim_bytes > self.limits.max_header_bytes() {
                    return Err(self.fail(HttpError::HeadersTooLarge));
                }
                if status == 100 && self.waiting_continue {
                    self.waiting_continue = false;
                    self.next_head();
                    return Ok(ClientEvent::Continue);
                }
                if self.report_interim {
                    self.state = State::Interim;
                    return Ok(ClientEvent::Informational(self.view()));
                }
                self.next_head();
                continue;
            } else {
                if self.waiting_continue {
                    // RFC 9110 section 10.1.1: a final status instead of 100
                    // means the server does not want the body. A promised
                    // body that is never sent leaves the request unfinished,
                    // so the connection closes after this response.
                    self.waiting_continue = false;
                    self.body_refused = self.req != ReqWrite::Sent;
                }
                self.decoder.start(info.framing);
                self.state = State::Body;
            }
            return Ok(ClientEvent::Response(self.view()));
        }
    }

    /// Drops the current (interim) head and waits for the next one.
    fn next_head(&mut self) {
        self.buf.unpin();
        self.buf.pin_at_pos();
        self.scanner.reset();
        self.unfold = Unfold::new();
    }

    fn reusable(&self) -> bool {
        self.keep_alive && self.info.keep_alive && self.req == ReqWrite::Sent && !self.body_refused
    }

    fn poll_body(&mut self) -> Result<ClientEvent<'_>, HttpError> {
        let mut framing_bytes = 0;
        let step = self.decoder.step(
            self.buf.unread(),
            self.buf.is_eof(),
            &self.limits,
            &mut self.trailers,
            self.report_trailers,
            &mut framing_bytes,
        );
        self.buf.consume(framing_bytes);
        match step.map_err(|e| self.fail(e))? {
            Step::Data(n) => {
                let start = self.buf.pos();
                self.buf.consume(n);
                Ok(ClientEvent::Body(self.buf.range(start, start + n)))
            }
            Step::Trailers => Ok(ClientEvent::Trailers(Headers::new(
                self.buf.unread(),
                &self.trailers.fields,
            ))),
            Step::Done => {
                self.state = State::Complete;
                Ok(ClientEvent::ResponseEnd)
            }
            Step::NeedMore => Ok(ClientEvent::NeedInput),
        }
    }

    fn fail(&mut self, e: HttpError) -> HttpError {
        self.state = State::Closed;
        e
    }

    fn view(&self) -> ResponseHead<'_> {
        ResponseHead::new(
            self.buf.from(self.buf.pin()),
            &self.scanner.fields,
            &self.info,
        )
    }

    /// The current response's head, from its arrival until the next request
    /// is sent (still available after an upgrade).
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ClientConn, ClientEvent, Request};
    ///
    /// let mut conn = ClientConn::new();
    /// conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new()).unwrap();
    /// let _ = conn.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    /// while !matches!(conn.poll().unwrap(), ClientEvent::ResponseEnd) {}
    /// assert_eq!(conn.response().unwrap().status(), 200);
    /// ```
    #[must_use]
    pub fn response(&self) -> Option<ResponseHead<'_>> {
        match self.state {
            State::Body | State::Complete | State::Upgraded => Some(self.view()),
            _ => None,
        }
    }

    /// Whether the server switched protocols and the connection now belongs
    /// to another protocol.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(!http_net::ClientConn::new().is_upgraded());
    /// ```
    #[must_use]
    pub fn is_upgraded(&self) -> bool {
        self.state == State::Upgraded
    }

    /// Input that arrived after the last message parsed: after
    /// [`ClientEvent::Upgraded`], the first bytes of the new protocol.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ClientConn, ClientEvent, Request};
    ///
    /// let mut conn = ClientConn::new();
    /// conn.send_request(&Request::get("/").header("host", "a").upgrade("x"), &mut Vec::new()).unwrap();
    /// let _ = conn.feed(b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: x\r\n\r\nhi");
    /// assert!(matches!(conn.poll().unwrap(), ClientEvent::Response(_)));
    /// assert!(matches!(conn.poll().unwrap(), ClientEvent::Upgraded));
    /// assert_eq!(conn.remaining_input(), b"hi");
    /// ```
    #[must_use]
    pub fn remaining_input(&self) -> &[u8] {
        self.buf.unread()
    }

    /// When `true`, each interim response other than `101` (for example
    /// `103 Early Hints`) is reported as [`ClientEvent::Informational`]
    /// before the final response; when `false` (the default) they are
    /// skipped. Interim responses count against
    /// [`Limits::max_interim`](crate::Limits::max_interim) either way.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ClientConn, ClientEvent, Request};
    ///
    /// let mut conn = ClientConn::new();
    /// conn.set_report_informational(true);
    /// conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())?;
    /// let _ = conn.feed(b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n");
    /// let ClientEvent::Informational(hints) = conn.poll()? else { panic!() };
    /// assert_eq!(hints.status(), 103);
    /// assert_eq!(hints.header("link"), Some(&b"</a.css>; rel=preload"[..]));
    /// assert!(matches!(conn.poll()?, ClientEvent::Response(r) if r.status() == 204));
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    pub fn set_report_informational(&mut self, report: bool) {
        self.report_interim = report;
    }

    /// When `true`, a response's trailer fields are kept (bounded by the
    /// trailer budgets of [`Limits`]) and reported as
    /// [`ClientEvent::Trailers`] just before [`ClientEvent::ResponseEnd`];
    /// when `false` (the default) they are validated and discarded.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ClientConn, ClientEvent, Request};
    ///
    /// let mut conn = ClientConn::new();
    /// conn.set_report_trailers(true);
    /// conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())?;
    /// let _ = conn.feed(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nServer-Timing: db;dur=5\r\n\r\n");
    /// let mut saw = false;
    /// loop {
    ///     match conn.poll()? {
    ///         ClientEvent::Trailers(t) => saw = t.len() == 1,
    ///         ClientEvent::ResponseEnd => break,
    ///         _ => {}
    ///     }
    /// }
    /// assert!(saw);
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    pub fn set_report_trailers(&mut self, report: bool) {
        self.report_trailers = report;
    }

    /// Sets the opt-in tolerances for responses (see [`ClientLeniency`]);
    /// the default is strict. Takes effect from the next response head.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ClientConn, ClientLeniency, HttpError, Request};
    ///
    /// let folded = b"HTTP/1.1 200 OK\r\nX: a\r\n b\r\nContent-Length: 0\r\n\r\n";
    /// let mut strict = ClientConn::new();
    /// strict.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())?;
    /// let _ = strict.feed(folded);
    /// assert_eq!(strict.poll().unwrap_err(), HttpError::ObsFold);
    ///
    /// let mut lenient = ClientConn::new();
    /// lenient.set_leniency(ClientLeniency::new().with_obs_fold_in_responses(true));
    /// lenient.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())?;
    /// let _ = lenient.feed(folded);
    /// assert!(lenient.poll().is_ok());
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    pub fn set_leniency(&mut self, leniency: ClientLeniency) {
        self.leniency = leniency;
    }

    /// Whether a request built with
    /// [`Request::expect_continue`](crate::Request::expect_continue) is
    /// still waiting: no `100 Continue`, no final response, and no body
    /// bytes sent yet. A client may stop waiting on its own timer and send
    /// the body anyway (RFC 9110 section 10.1.1).
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ClientConn, ClientEvent, Request};
    ///
    /// let mut conn = ClientConn::new();
    /// let mut out = Vec::new();
    /// let upload = Request::put("/big").header("host", "a").content_length(4).expect_continue();
    /// conn.send_request(&upload, &mut out)?;
    /// assert!(conn.is_waiting_for_continue());
    /// let _ = conn.feed(b"HTTP/1.1 100 Continue\r\n\r\n");
    /// assert!(matches!(conn.poll()?, ClientEvent::Continue));
    /// assert!(!conn.is_waiting_for_continue());
    /// conn.send_body(b"data", &mut out)?;
    /// conn.end_body(&mut out)?;
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    #[must_use]
    pub fn is_waiting_for_continue(&self) -> bool {
        self.waiting_continue
    }

    /// Whether the connection can carry another request now: no request
    /// is outstanding (or the last response completed) and both sides allow
    /// keep-alive. With pipelining, [`can_send`](Self::can_send) says
    /// whether another request can be sent while some are outstanding.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ClientConn, ClientEvent, Request};
    ///
    /// let mut conn = ClientConn::new();
    /// assert!(conn.is_reusable());
    /// conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())?;
    /// assert!(!conn.is_reusable());
    /// let _ = conn.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    /// while !matches!(conn.poll()?, ClientEvent::ResponseEnd) {}
    /// assert!(conn.is_reusable());
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    #[must_use]
    pub fn is_reusable(&self) -> bool {
        match self.state {
            State::Idle => self.buf.unread().is_empty() && !self.buf.is_eof(),
            State::Complete => self.reusable() && self.buf.unread().is_empty(),
            _ => false,
        }
    }

    /// The connection's phase, for response deadlines: [`Progress::Idle`]
    /// with no request outstanding, [`Progress::WritingBody`] while a
    /// request body is streamed, [`Progress::AwaitingResponse`] until the
    /// first byte of the response, then [`Progress::Head`] and
    /// [`Progress::Body`].
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ClientConn, Progress, Request};
    ///
    /// let mut conn = ClientConn::new();
    /// assert_eq!(conn.progress(), Progress::Idle);
    /// conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())?;
    /// assert_eq!(conn.progress(), Progress::AwaitingResponse);
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    #[must_use]
    pub fn progress(&self) -> Progress {
        if matches!(self.req, ReqWrite::Streaming(_))
            && !self.body_refused
            && !matches!(self.state, State::Closed | State::Upgraded)
        {
            return Progress::WritingBody;
        }
        match self.state {
            State::Idle => Progress::Idle,
            State::Head if self.buf.from(self.buf.pin()).is_empty() => Progress::AwaitingResponse,
            State::Head | State::Interim => Progress::Head,
            State::Body => Progress::Body,
            State::Complete if self.reusable() => Progress::Idle,
            State::Complete | State::Closed => Progress::Closed,
            State::Upgraded => Progress::Upgraded,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::head::BodyFraming;

    fn get() -> Request {
        Request::get("/").header("host", "a")
    }

    #[test]
    fn test_interim_responses_are_skipped() {
        let mut conn = ClientConn::new();
        conn.send_request(&get(), &mut Vec::new()).unwrap();
        let _ = conn.feed(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let ClientEvent::Response(r) = conn.poll().unwrap() else {
            panic!("expected response");
        };
        assert_eq!(r.status(), 200);
        assert!(matches!(conn.poll().unwrap(), ClientEvent::Body(b"ok")));
        assert!(matches!(conn.poll().unwrap(), ClientEvent::ResponseEnd));
        assert!(matches!(conn.poll().unwrap(), ClientEvent::Idle));
    }

    #[test]
    fn test_unrequested_upgrade_and_unsolicited_data_are_errors() {
        let mut conn = ClientConn::new();
        conn.send_request(&get(), &mut Vec::new()).unwrap();
        let _ = conn
            .feed(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\nConnection: upgrade\r\n\r\n");
        assert_eq!(conn.poll().unwrap_err(), HttpError::UnexpectedUpgrade);

        let mut conn = ClientConn::new();
        let _ = conn.feed(b"HTTP/1.1 200 OK\r\n\r\n");
        assert_eq!(conn.poll().unwrap_err(), HttpError::UnexpectedData);
    }

    /// T-21: a `101` switches only to a protocol the request offered (RFC
    /// 9110 section 7.8); a back end answering an upgrade to something else
    /// must not take over the connection.
    #[test]
    fn test_switching_protocols_must_name_an_offered_protocol() {
        let answer = |offers: &[&str], upgrade: &str| {
            let mut request = Request::get("/").header("host", "a");
            for offer in offers {
                request = request.upgrade(offer);
            }
            let mut conn = ClientConn::new();
            conn.send_request(&request, &mut Vec::new()).unwrap();
            let response = alloc::format!(
                "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\n{upgrade}\r\n"
            );
            let _ = conn.feed(response.as_bytes());
            match conn.poll() {
                Ok(ClientEvent::Response(r)) => {
                    assert_eq!(r.status(), 101);
                    matches!(conn.poll(), Ok(ClientEvent::Upgraded))
                }
                Err(e) => {
                    assert_eq!(e, HttpError::UnexpectedUpgrade);
                    false
                }
                other => panic!("unexpected {other:?}"),
            }
        };
        // The protocol offered, in any case, with or without a version.
        assert!(answer(&["websocket"], "Upgrade: websocket\r\n"));
        assert!(answer(&["websocket"], "Upgrade: WebSocket\r\n"));
        assert!(answer(&["websocket/13"], "Upgrade: websocket\r\n"));
        assert!(answer(&["websocket"], "Upgrade: websocket/13\r\n"));
        // One of several offers.
        assert!(answer(&["foo", "websocket"], "Upgrade: websocket\r\n"));
        // Anything not offered, h2c above all, or no protocol at all.
        assert!(!answer(&["websocket"], "Upgrade: h2c\r\n"));
        assert!(!answer(&["websocket"], "Upgrade: foo\r\n"));
        assert!(!answer(&["websocket"], "Upgrade: websocket, foo\r\n"));
        assert!(!answer(
            &["websocket"],
            "Upgrade: websocket\r\nUpgrade: foo\r\n"
        ));
        assert!(!answer(&["websocket/13"], "Upgrade: websocket/14\r\n"));
        assert!(!answer(&["websocket"], "Upgrade:\r\n"));
        assert!(!answer(&["websocket"], ""));
    }

    #[test]
    fn test_head_response_has_no_body_and_connection_is_reused() {
        let mut conn = ClientConn::new();
        conn.send_request(
            &Request::new("HEAD", "/").header("host", "a"),
            &mut Vec::new(),
        )
        .unwrap();
        let _ = conn.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n");
        let ClientEvent::Response(r) = conn.poll().unwrap() else {
            panic!("expected response");
        };
        assert_eq!(r.framing(), BodyFraming::None);
        assert!(matches!(conn.poll().unwrap(), ClientEvent::ResponseEnd));
        assert!(matches!(conn.poll().unwrap(), ClientEvent::Idle));
        conn.send_request(&get(), &mut Vec::new()).unwrap();
        assert!(matches!(
            conn.send_request(&get(), &mut Vec::new()),
            Err(HttpError::InvalidState(_))
        ));
    }

    #[test]
    fn test_close_and_streaming_request_prevent_reuse() {
        let mut conn = ClientConn::new();
        conn.send_request(&get().close(), &mut Vec::new()).unwrap();
        let _ = conn.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        while !matches!(conn.poll().unwrap(), ClientEvent::ResponseEnd) {}
        assert!(matches!(conn.poll().unwrap(), ClientEvent::Closed));
        assert!(conn.send_request(&get(), &mut Vec::new()).is_err());

        let mut conn = ClientConn::new();
        let mut out = Vec::new();
        conn.send_request(&Request::post("/").header("host", "a").chunked(), &mut out)
            .unwrap();
        let _ = conn.feed(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n");
        while !matches!(conn.poll().unwrap(), ClientEvent::ResponseEnd) {}
        assert!(matches!(conn.poll().unwrap(), ClientEvent::Closed));
        assert!(matches!(conn.send_body(b"x", &mut out), Ok(())));
        assert!(matches!(conn.end_body(&mut out), Ok(())));
        assert!(matches!(
            conn.end_body(&mut out),
            Err(HttpError::InvalidState(_))
        ));
    }

    #[test]
    fn test_eof_before_response_is_an_error() {
        let mut conn = ClientConn::new();
        conn.send_request(&get(), &mut Vec::new()).unwrap();
        conn.feed_eof();
        assert_eq!(conn.poll().unwrap_err(), HttpError::UnexpectedEof);
    }
}
