//! The server side of an HTTP/1.1 connection, without I/O.

use alloc::vec::Vec;

use crate::{
    body::{Decoder, Encoder, Step, push_framing},
    buffer::Buffer,
    date::HttpDate,
    error::HttpError,
    head::{
        HeadKind, HeadScanner, Headers, RequestHead, RequestInfo, Scan, Version, interpret_request,
    },
    limits::Limits,
    message::{
        OutBody, Response, check_response_field, check_trailers, check_upgrade_protocol,
        push_last_chunk_with_trailers, write_field,
    },
    method::Method,
    preface::is_h2_preface,
    status::write_status_line,
    write::{BodyPlan, OutgoingBody, Output, ResponseHeadRef},
};

/// What a [`ServerConn`] has for the caller after [`poll`](ServerConn::poll).
///
/// # Examples
///
/// ```
/// use http_net::{Response, ServerConn, ServerEvent};
///
/// let mut conn = ServerConn::new();
/// let mut out = Vec::new();
/// let _ = conn.feed(b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhi");
/// let mut body = Vec::new();
/// loop {
///     match conn.poll().unwrap() {
///         ServerEvent::Request(req) => assert_eq!(req.path(), "/echo"),
///         ServerEvent::Body(chunk) => body.extend_from_slice(chunk),
///         ServerEvent::RequestEnd => {
///             conn.respond(&Response::new(200).body(body.clone()), &mut out).unwrap();
///         }
///         ServerEvent::NeedInput => break,
///         other => panic!("{other:?}"),
///     }
/// }
/// assert!(out.ends_with(b"\r\n\r\nhi"));
/// ```
#[non_exhaustive]
#[derive(Debug)]
pub enum ServerEvent<'a> {
    /// A request head arrived. Its body (if any) follows as
    /// [`Body`](ServerEvent::Body) events, then
    /// [`RequestEnd`](ServerEvent::RequestEnd). A response may be sent from
    /// this point on; sending it while body bytes are still unread closes
    /// the connection afterwards (a request without a body stays
    /// keep-alive). If the head
    /// [`expects_continue`](RequestHead::expects_continue), answer with
    /// [`send_continue`](ServerConn::send_continue) or a final response
    /// before waiting for the body.
    Request(RequestHead<'a>),
    /// A run of body bytes, after chunked decoding.
    Body(&'a [u8]),
    /// The request's trailer fields, just before
    /// [`RequestEnd`](ServerEvent::RequestEnd): only with
    /// [`set_report_trailers(true)`](ServerConn::set_report_trailers) and a
    /// non-empty trailer section. They never change how the request was
    /// framed. The values of credential fields are redacted in `Debug`.
    Trailers(Headers<'a>),
    /// The request is complete. Send the response if it has not been sent.
    RequestEnd,
    /// More input is needed: read from the socket, then
    /// [`feed`](ServerConn::feed) (or [`read_buf`](ServerConn::read_buf) and
    /// [`commit`](ServerConn::commit)), or [`feed_eof`](ServerConn::feed_eof)
    /// if the peer closed.
    NeedInput,
    /// The request is complete and its response has not been finished yet.
    /// Pipelined requests wait in the buffer until it is.
    AwaitingResponse,
    /// A `101 Switching Protocols` (or a 2xx to `CONNECT`) was sent: the
    /// connection now belongs to the new protocol. Bytes that already arrived
    /// for it are in [`remaining_input`](ServerConn::remaining_input).
    Upgraded,
    /// The connection is finished: flush any output, then close the socket.
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReqState {
    Head,
    Body,
    Complete,
    Upgraded,
    Failed,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RespState {
    Idle,
    Streaming(Encoder),
    Sent,
}

/// The phase of a connection, for drivers that run header-read, request,
/// and response deadlines: what [`ServerConn::progress`] and
/// [`ClientConn::progress`](crate::ClientConn::progress) report.
///
/// # Examples
///
/// ```
/// use http_net::{Progress, ServerConn, ServerEvent};
///
/// let mut conn = ServerConn::new();
/// assert_eq!(conn.progress(), Progress::Idle);
/// let _ = conn.feed(b"GET / HTTP/1.1\r\n");
/// assert!(matches!(conn.poll(), Ok(ServerEvent::NeedInput)));
/// assert_eq!(conn.progress(), Progress::Head);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Progress {
    /// Between messages: no byte of the next one has been seen. Idle
    /// keep-alive time belongs to this phase, so a request deadline should
    /// not start here.
    Idle,
    /// Some bytes of a head have arrived; the head is not complete.
    Head,
    /// The head is complete and body bytes are still to come.
    Body,
    /// Server: the request is complete (or has no body left to read) and its
    /// response is not finished. Client: the request was sent and nothing of
    /// the response has arrived.
    AwaitingResponse,
    /// A streamed body is being written: the response on a server, the
    /// request on a client.
    WritingBody,
    /// The connection belongs to another protocol.
    Upgraded,
    /// The connection is finished (or will be once the last response is
    /// written).
    Closed,
}

/// The server side of one HTTP/1.1 connection: a sans-IO state machine.
///
/// The connection owns a bounded input buffer. The caller moves bytes
/// between it and the socket: input in through [`feed`](Self::feed) (or
/// [`read_buf`](Self::read_buf) + [`commit`](Self::commit) to read straight
/// into the buffer), events out through [`poll`](Self::poll), responses out
/// through [`respond`](Self::respond) into a caller-owned `Vec<u8>`.
///
/// Requests are handled one at a time, in order. Keep-alive is automatic:
/// after a response is finished the next request (possibly already buffered,
/// when the client pipelines) is parsed on the next `poll`. A connection
/// that must close (the client asked, HTTP/1.0 without keep-alive, the
/// response was sent before the request body was read, or a parse error)
/// reports [`ServerEvent::Closed`] once its last response is written.
///
/// Steady state allocates nothing: the input buffer and the field index are
/// reused across requests.
///
/// # Examples
///
/// ```
/// use http_net::{Response, ServerConn, ServerEvent};
///
/// let mut conn = ServerConn::new();
/// let mut out = Vec::new();
/// // Two pipelined requests in one read.
/// let _ = conn.feed(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n");
/// let mut paths = Vec::new();
/// loop {
///     match conn.poll().unwrap() {
///         ServerEvent::Request(req) => paths.push(req.path().to_string()),
///         ServerEvent::RequestEnd => conn.respond(&Response::text(200, "ok"), &mut out).unwrap(),
///         ServerEvent::NeedInput => break,
///         other => panic!("{other:?}"),
///     }
/// }
/// assert_eq!(paths, ["/a", "/b"]);
/// ```
pub struct ServerConn {
    buf: Buffer,
    limits: Limits,
    scanner: HeadScanner,
    trailers: HeadScanner,
    decoder: Decoder,
    info: RequestInfo,
    state: ReqState,
    resp: RespState,
    keep_alive: bool,
    /// Cleared by `set_keep_alive(false)`: every later response closes.
    allow_keep_alive: bool,
    continue_sent: bool,
    /// A body byte of the current request was delivered.
    body_seen: bool,
    /// The response being streamed was declared chunked (trailers allowed,
    /// even if an HTTP/1.0 client forced a close-delimited body).
    resp_chunked: bool,
    report_trailers: bool,
    requests_served: u64,
    /// The connection has not yet shown whether it starts with the HTTP/2
    /// preface (checked once, before the first request only).
    preface_undecided: bool,
}

impl Default for ServerConn {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for ServerConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerConn")
            .field("state", &self.state)
            .field("response", &self.resp)
            .field("buffered", &self.buf.unread().len())
            .field("limits", &self.limits)
            .finish()
    }
}

impl ServerConn {
    /// A connection with the default [`Limits`].
    ///
    /// # Examples
    ///
    /// ```
    /// let conn = http_net::ServerConn::new();
    /// assert!(conn.request().is_none());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(Limits::new())
    }

    /// A connection enforcing `limits`.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{HttpError, Limits, ServerConn};
    ///
    /// let mut conn = ServerConn::with_limits(Limits::new().with_max_body(4));
    /// let _ = conn.feed(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n");
    /// assert_eq!(conn.poll().unwrap_err(), HttpError::BodyTooLarge);
    /// ```
    #[must_use]
    pub fn with_limits(limits: Limits) -> Self {
        Self::from_buffer(Buffer::new(limits.buffer_capacity()), limits)
    }

    /// A connection enforcing `limits` that reads into `storage`, for
    /// drivers that pool buffers: its capacity is used up to
    /// [`Limits::buffer_capacity`], its contents are ignored. Give it back
    /// with [`into_buffer`](Self::into_buffer).
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{Limits, ServerConn, ServerEvent};
    ///
    /// let pooled: Vec<u8> = Vec::with_capacity(8192);
    /// let mut conn = ServerConn::with_buffer(pooled, Limits::new());
    /// let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    /// assert!(matches!(conn.poll().unwrap(), ServerEvent::Request(_)));
    /// let back = conn.into_buffer();
    /// assert!(back.capacity() >= 8192);
    /// ```
    #[must_use]
    pub fn with_buffer(storage: Vec<u8>, limits: Limits) -> Self {
        Self::from_buffer(
            Buffer::with_storage(storage, limits.buffer_capacity()),
            limits,
        )
    }

    fn from_buffer(mut buf: Buffer, limits: Limits) -> Self {
        buf.pin_at_pos();
        Self {
            buf,
            limits,
            scanner: HeadScanner::new(),
            trailers: HeadScanner::new(),
            decoder: Decoder::new(),
            info: RequestInfo::EMPTY,
            state: ReqState::Head,
            resp: RespState::Idle,
            keep_alive: false,
            allow_keep_alive: true,
            continue_sent: false,
            body_seen: false,
            resp_chunked: false,
            report_trailers: false,
            requests_served: 0,
            preface_undecided: true,
        }
    }

    /// The limits this connection enforces.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::ServerConn::new().limits(), &http_net::Limits::new());
    /// ```
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Copies as much of `bytes` into the input buffer as fits and returns
    /// how many bytes were taken. Fewer than `bytes.len()` means the buffer
    /// is full: [`poll`](Self::poll) until it asks for input, then feed the
    /// rest.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = http_net::ServerConn::new();
    /// assert_eq!(conn.feed(b"GET / HTTP/1.1\r\n"), 16);
    /// ```
    #[must_use = "bytes beyond the returned count were not taken"]
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        self.buf.feed(bytes)
    }

    /// Spare space at the end of the input buffer, for reading from a
    /// socket without an intermediate copy. Follow with
    /// [`commit`](Self::commit). It is empty only when the buffer is full of
    /// input the parser has not been asked to process yet; poll first.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = http_net::ServerConn::new();
    /// let spare = conn.read_buf();
    /// let msg = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    /// spare[..msg.len()].copy_from_slice(msg);
    /// conn.commit(msg.len());
    /// assert!(matches!(conn.poll(), Ok(http_net::ServerEvent::Request(_))));
    /// ```
    pub fn read_buf(&mut self) -> &mut [u8] {
        self.buf.spare()
    }

    /// Records that `n` bytes were written into [`read_buf`](Self::read_buf).
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = http_net::ServerConn::new();
    /// conn.read_buf()[0] = b'G';
    /// conn.commit(1);
    /// assert!(matches!(conn.poll(), Ok(http_net::ServerEvent::NeedInput)));
    /// ```
    pub fn commit(&mut self, n: usize) {
        self.buf.commit(n);
    }

    /// Records that the peer closed its sending side. A connection idle
    /// between requests then reports [`ServerEvent::Closed`]; one in the
    /// middle of a request reports [`HttpError::UnexpectedEof`].
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = http_net::ServerConn::new();
    /// conn.feed_eof();
    /// assert!(matches!(conn.poll(), Ok(http_net::ServerEvent::Closed)));
    /// ```
    pub fn feed_eof(&mut self) {
        self.buf.set_eof();
    }

    /// Advances the parser and reports what happened. Call it until it
    /// returns [`ServerEvent::NeedInput`], [`ServerEvent::AwaitingResponse`],
    /// [`ServerEvent::Upgraded`], or [`ServerEvent::Closed`].
    ///
    /// # Errors
    ///
    /// Any [`HttpError`] parse error. The connection is then finished: send
    /// one error response (see [`HttpError::status`]) with
    /// [`respond`](Self::respond), flush, and close.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{HttpError, ServerConn};
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n");
    /// assert_eq!(conn.poll().unwrap_err(), HttpError::ObsFold);
    /// ```
    pub fn poll(&mut self) -> Result<ServerEvent<'_>, HttpError> {
        loop {
            match self.state {
                ReqState::Head => return self.poll_head(),
                ReqState::Body => {
                    if self.resp == RespState::Sent && !self.decoder.is_read() {
                        // Answered before the body was read: the rest of the
                        // body cannot be trusted to frame the next request.
                        self.state = ReqState::Closed;
                        return Ok(ServerEvent::Closed);
                    }
                    return self.poll_body();
                }
                ReqState::Complete => {
                    if self.resp != RespState::Sent {
                        return Ok(ServerEvent::AwaitingResponse);
                    }
                    if !self.keep_alive {
                        self.state = ReqState::Closed;
                        return Ok(ServerEvent::Closed);
                    }
                    self.next_exchange();
                }
                ReqState::Upgraded => return Ok(ServerEvent::Upgraded),
                ReqState::Failed | ReqState::Closed => return Ok(ServerEvent::Closed),
            }
        }
    }

    fn poll_head(&mut self) -> Result<ServerEvent<'_>, HttpError> {
        let start = self.buf.pin();
        if self.preface_undecided {
            // RFC 9113 section 3.4: prior-knowledge HTTP/2 starts the
            // connection with a fixed preface. Decide before the head is
            // scanned (its first 18 bytes are a complete HTTP/1.1-shaped
            // head), and wait while the input could still be the preface, so
            // the answer does not depend on how the bytes arrived.
            match is_h2_preface(self.buf.from(start)) {
                Some(true) => return Err(self.fail(HttpError::Http2Preface)),
                Some(false) => self.preface_undecided = false,
                None if self.buf.is_eof() => self.preface_undecided = false,
                None => return Ok(ServerEvent::NeedInput),
            }
        }
        let msg = self.buf.from(start);
        let progress = self
            .scanner
            .advance(msg, &self.limits, HeadKind::Request, true)
            .map_err(|e| self.fail(e))?;
        let len = match progress {
            Scan::Partial if self.buf.is_eof() => {
                if self.buf.from(start).is_empty() {
                    self.state = ReqState::Closed;
                    return Ok(ServerEvent::Closed);
                }
                return Err(self.fail(HttpError::UnexpectedEof));
            }
            Scan::Partial => return Ok(ServerEvent::NeedInput),
            Scan::Done(len) => len,
        };
        let info = interpret_request(
            self.buf.from(start),
            self.scanner.start_line(),
            &self.scanner.fields,
            &self.limits,
        )
        .map_err(|e| self.fail(e))?;
        self.buf.consume(len);
        self.buf.extend_pin_to_pos();
        self.info = info;
        self.keep_alive = info.keep_alive;
        self.decoder.start(info.framing);
        self.state = ReqState::Body;
        Ok(ServerEvent::Request(self.view()))
    }

    fn poll_body(&mut self) -> Result<ServerEvent<'_>, HttpError> {
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
                self.body_seen = true;
                Ok(ServerEvent::Body(self.buf.range(start, start + n)))
            }
            Step::Trailers => Ok(ServerEvent::Trailers(Headers::new(
                self.buf.unread(),
                &self.trailers.fields,
            ))),
            Step::Done => {
                self.state = ReqState::Complete;
                Ok(ServerEvent::RequestEnd)
            }
            Step::NeedMore => Ok(ServerEvent::NeedInput),
        }
    }

    fn fail(&mut self, e: HttpError) -> HttpError {
        self.state = ReqState::Failed;
        self.keep_alive = false;
        e
    }

    fn next_exchange(&mut self) {
        self.buf.wipe_consumed();
        self.buf.unpin();
        self.buf.pin_at_pos();
        self.scanner.reset();
        self.resp = RespState::Idle;
        self.info = RequestInfo::EMPTY;
        self.continue_sent = false;
        self.body_seen = false;
        self.state = ReqState::Head;
    }

    /// Whether a response to the current request has been started.
    #[cfg(feature = "std")]
    pub(crate) fn response_started(&self) -> bool {
        self.resp != RespState::Idle
    }

    /// Whether the current request's body has been read to its end: the
    /// exchange is complete, or the request has no body at all (a response
    /// given at [`ServerEvent::Request`] then leaves nothing unread).
    fn body_read(&self) -> bool {
        self.state == ReqState::Complete || (self.state == ReqState::Body && self.decoder.is_read())
    }

    fn view(&self) -> RequestHead<'_> {
        RequestHead::new(
            self.buf.from(self.buf.pin()),
            &self.scanner.fields,
            &self.info,
        )
    }

    /// The current request's head, from its arrival until the next request
    /// begins (still available after an upgrade).
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"PUT /f HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\nz");
    /// while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
    /// assert_eq!(conn.request().unwrap().path(), "/f");
    /// ```
    #[must_use]
    pub fn request(&self) -> Option<RequestHead<'_>> {
        match self.state {
            ReqState::Body | ReqState::Complete | ReqState::Upgraded => Some(self.view()),
            _ => None,
        }
    }

    /// Whether a `101 Switching Protocols` (or a 2xx to `CONNECT`) was sent
    /// and the connection now belongs to another protocol.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(!http_net::ServerConn::new().is_upgraded());
    /// ```
    #[must_use]
    pub fn is_upgraded(&self) -> bool {
        self.state == ReqState::Upgraded
    }

    /// Input that arrived after the last message this connection parsed:
    /// after [`ServerEvent::Upgraded`], the first bytes of the new protocol.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{Response, ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: x\r\n\r\n\x81\x00");
    /// assert!(matches!(conn.poll().unwrap(), ServerEvent::Request(_)));
    /// assert!(matches!(conn.poll().unwrap(), ServerEvent::RequestEnd));
    /// conn.respond(&Response::switching_protocols("x"), &mut Vec::new()).unwrap();
    /// assert!(matches!(conn.poll().unwrap(), ServerEvent::Upgraded));
    /// assert_eq!(conn.remaining_input(), b"\x81\x00");
    /// ```
    #[must_use]
    pub fn remaining_input(&self) -> &[u8] {
        self.buf.unread()
    }

    /// Writes `response` for the current request into `out`.
    ///
    /// With a full body the response is complete. With a streamed body
    /// ([`Response::chunked`], [`Response::content_length`]) follow with
    /// [`send_body`](Self::send_body) and [`end_body`](Self::end_body).
    /// After a parse error, one response may still be sent; it is marked
    /// `connection: close`.
    ///
    /// # Errors
    ///
    /// - the first error recorded by the [`Response`] builder;
    /// - [`HttpError::InvalidStatus`] for a status outside `100..=599`, or a
    ///   1xx other than 101;
    /// - [`HttpError::BodyNotAllowed`] for a body on 1xx, 204, 304, 101, or a
    ///   2xx to `CONNECT`;
    /// - [`HttpError::UpgradeNotOffered`] for a 101 whose protocol the
    ///   request's `Upgrade` field did not offer;
    /// - [`HttpError::InvalidState`] when there is no request to answer, a
    ///   response was already started, or a 101 does not answer a complete
    ///   upgrade request.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{Response, ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n");
    /// while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
    /// let mut out = Vec::new();
    /// conn.respond(&Response::text(200, "hello"), &mut out).unwrap();
    /// // HEAD: the length is announced, the body is not sent.
    /// assert!(out.windows(17).any(|w| w == b"content-length: 5"));
    /// assert!(out.ends_with(b"\r\n\r\n"));
    /// ```
    pub fn respond(&mut self, response: &Response, out: &mut Vec<u8>) -> Result<(), HttpError> {
        self.respond_dated(response, None, out)
    }

    /// As [`respond`](Self::respond), adding `date: <date>` unless the
    /// response set its own `date` field. Keep a
    /// [`DateCache`](crate::DateCache) per driver thread and pass
    /// `cache.update(now)`: the value is reformatted once per second, not
    /// once per response.
    ///
    /// # Errors
    ///
    /// As [`respond`](Self::respond).
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{DateCache, Response, ServerConn, ServerEvent};
    ///
    /// let mut dates = DateCache::new();
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    /// while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
    /// let mut out = Vec::new();
    /// conn.respond_with_date(&Response::new(204), dates.update(784_111_777), &mut out)?;
    /// assert!(out.windows(35).any(|w| w == b"date: Sun, 06 Nov 1994 08:49:37 GMT"));
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    pub fn respond_with_date(
        &mut self,
        response: &Response,
        date: &HttpDate,
        out: &mut Vec<u8>,
    ) -> Result<(), HttpError> {
        self.respond_dated(response, Some(date.as_bytes()), out)
    }

    /// As [`respond`](Self::respond), but writes only the head: for a
    /// full-body response the caller then sends
    /// [`Response::body_bytes`] itself, so head and body can leave in one
    /// vectored write (`write_vectored`) without the body being copied into
    /// `out`. The returned [`BodyPlan`] says what follows:
    ///
    /// - [`BodyPlan::Raw`]: send the body bytes, exactly as they are, right
    ///   after the head; the response already counts as sent.
    /// - [`BodyPlan::None`]: nothing (an empty body, `HEAD`, 204, 304, a
    ///   tunnel).
    /// - [`BodyPlan::Stream`]: a streamed response; continue with
    ///   [`send_body`](Self::send_body) and [`end_body`](Self::end_body).
    ///
    /// # Errors
    ///
    /// As [`respond`](Self::respond); nothing is written on error.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{BodyPlan, Response, ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"GET /big HTTP/1.1\r\nHost: a\r\n\r\n");
    /// while !matches!(conn.poll()?, ServerEvent::RequestEnd) {}
    /// let response = Response::new(200).body(vec![b'x'; 64 * 1024]);
    /// let mut head = Vec::new();
    /// let plan = conn.respond_head_only(&response, &mut head)?;
    /// assert_eq!(plan, BodyPlan::Raw);
    /// assert!(head.ends_with(b"content-length: 65536\r\n\r\n"));
    /// // Send `head` and `response.body_bytes()` together, e.g. with
    /// // `std::io::Write::write_vectored`.
    /// assert_eq!(response.body_bytes().map(<[u8]>::len), Some(64 * 1024));
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    pub fn respond_head_only(
        &mut self,
        response: &Response,
        out: &mut Vec<u8>,
    ) -> Result<BodyPlan, HttpError> {
        self.start_response(response, None, out)
    }

    /// [`respond_head_only`](Self::respond_head_only) with a `date` (the
    /// blocking server's vectored path).
    #[cfg(feature = "std")]
    pub(crate) fn respond_head_dated(
        &mut self,
        response: &Response,
        date: Option<&[u8]>,
        out: &mut Vec<u8>,
    ) -> Result<BodyPlan, HttpError> {
        self.start_response(response, date, out)
    }

    /// Writes an interim (1xx) response other than `100` and `101`, for
    /// example `103 Early Hints` with `link` fields, before the final
    /// response. It may be sent more than once, for any request method,
    /// at any point before the final response starts (RFC 9110 section
    /// 15.2), but never to an HTTP/1.0 client. Only the status and the
    /// fields are written; an interim response has no body and does not
    /// change the connection.
    ///
    /// # Errors
    ///
    /// The first error recorded by the builder; [`HttpError::InvalidStatus`]
    /// unless the status is in `102..=199`; [`HttpError::BodyNotAllowed`]
    /// for a body; [`HttpError::InterimNotAllowed`] for an HTTP/1.0 request
    /// or once the final response has started; [`HttpError::InvalidState`]
    /// when there is no request (or after a parse error, an upgrade, or the
    /// end of the connection).
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{Response, ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    /// while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
    /// let mut out = Vec::new();
    /// let hints = Response::new(103).header("link", "</style.css>; rel=preload; as=style");
    /// conn.send_informational(&hints, &mut out)?;
    /// conn.respond(&Response::text(200, "page"), &mut out)?;
    /// assert!(out.starts_with(b"HTTP/1.1 103 Early Hints\r\nlink: </style.css>"));
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    pub fn send_informational(
        &mut self,
        interim: &Response,
        out: &mut Vec<u8>,
    ) -> Result<(), HttpError> {
        if let Some(e) = interim.error() {
            return Err(e);
        }
        let status = interim.status();
        if !(102..=199).contains(&status) {
            return Err(HttpError::InvalidStatus);
        }
        if !matches!(&interim.body, OutBody::Full(b) if b.is_empty()) {
            return Err(HttpError::BodyNotAllowed);
        }
        if !matches!(self.state, ReqState::Body | ReqState::Complete) {
            return Err(HttpError::InvalidState(
                "an interim response needs a request to answer",
            ));
        }
        if self.info.version != Version::Http11 || self.resp != RespState::Idle {
            return Err(HttpError::InterimNotAllowed);
        }
        write_status_line(out, status);
        out.extend_from_slice(interim.fields());
        out.extend_from_slice(b"\r\n");
        Ok(())
    }

    /// Stops (`false`) or allows (`true`) keep-alive. With `false` the
    /// current response, or the next one if it has not started, carries
    /// `connection: close`, and the connection ends after it: the gentlest
    /// way to shed load or to cap requests per connection. If the current
    /// response has already been written, the connection ends after it.
    /// `true` cannot keep open a connection the protocol requires to close
    /// (the client asked, or body bytes were left unread).
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{Response, ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    /// while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
    /// conn.set_keep_alive(false);
    /// let mut out = Vec::new();
    /// conn.respond(&Response::new(204), &mut out).unwrap();
    /// assert!(out.windows(17).any(|w| w == b"connection: close"));
    /// assert!(matches!(conn.poll().unwrap(), ServerEvent::Closed));
    /// ```
    pub fn set_keep_alive(&mut self, keep: bool) {
        self.allow_keep_alive = keep;
        if !keep && self.resp != RespState::Idle {
            self.keep_alive = false;
        }
    }

    /// Whether the connection can stay open after the current exchange, as
    /// far as is known now: keep-alive is allowed (see
    /// [`set_keep_alive`](Self::set_keep_alive)) and neither the request,
    /// the response, nor an error requires a close.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// assert!(conn.keep_alive());
    /// let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
    /// assert!(matches!(conn.poll().unwrap(), ServerEvent::Request(_)));
    /// assert!(!conn.keep_alive());
    /// ```
    #[must_use]
    pub fn keep_alive(&self) -> bool {
        self.allow_keep_alive
            && match self.state {
                ReqState::Head => true,
                ReqState::Body | ReqState::Complete => self.keep_alive,
                ReqState::Upgraded | ReqState::Failed | ReqState::Closed => false,
            }
    }

    /// The number of responses completed on this connection (full-body
    /// responses when written, streamed ones at `end_body`), so a driver can
    /// cap requests per connection.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{Response, ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    /// while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
    /// assert_eq!(conn.requests_served(), 0);
    /// conn.respond(&Response::new(204), &mut Vec::new()).unwrap();
    /// assert_eq!(conn.requests_served(), 1);
    /// ```
    #[must_use]
    pub fn requests_served(&self) -> u64 {
        self.requests_served
    }

    /// The connection's phase, for header-read, request, and response
    /// deadlines. [`Progress::Head`] starts at the first byte of a request,
    /// so idle keep-alive time (`Idle`) is never counted against a request.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{Progress, Response, ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\nab");
    /// assert!(matches!(conn.poll().unwrap(), ServerEvent::Request(_)));
    /// assert!(matches!(conn.poll().unwrap(), ServerEvent::Body(_)));
    /// assert!(matches!(conn.poll().unwrap(), ServerEvent::NeedInput));
    /// assert_eq!(conn.progress(), Progress::Body);
    /// let _ = conn.feed(b"cd");
    /// while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
    /// assert_eq!(conn.progress(), Progress::AwaitingResponse);
    /// conn.respond(&Response::new(200).chunked(), &mut Vec::new()).unwrap();
    /// assert_eq!(conn.progress(), Progress::WritingBody);
    /// conn.end_body(&mut Vec::new()).unwrap();
    /// assert_eq!(conn.progress(), Progress::Idle);
    /// ```
    #[must_use]
    pub fn progress(&self) -> Progress {
        if matches!(self.resp, RespState::Streaming(_)) {
            return Progress::WritingBody;
        }
        match self.state {
            ReqState::Head if self.buf.from(self.buf.pin()).is_empty() => Progress::Idle,
            ReqState::Head => Progress::Head,
            // Answered before `RequestEnd` was polled. An unread body closes
            // the connection (`poll`); a read one (or none) is the same as
            // `Complete`.
            ReqState::Body if self.resp == RespState::Sent => {
                if self.decoder.is_read() && self.keep_alive {
                    Progress::Idle
                } else {
                    Progress::Closed
                }
            }
            ReqState::Body if !self.decoder.is_read() => Progress::Body,
            ReqState::Body => Progress::AwaitingResponse,
            ReqState::Complete if self.resp != RespState::Sent => Progress::AwaitingResponse,
            ReqState::Complete if self.keep_alive => Progress::Idle,
            ReqState::Complete => Progress::Closed,
            // One error response is still expected.
            ReqState::Failed if self.resp == RespState::Idle => Progress::AwaitingResponse,
            ReqState::Upgraded => Progress::Upgraded,
            ReqState::Failed | ReqState::Closed => Progress::Closed,
        }
    }

    /// When `true`, a request's trailer fields are kept (bounded by
    /// [`Limits::max_trailer_fields`] and [`Limits::max_trailer_bytes`]) and
    /// reported as [`ServerEvent::Trailers`] just before
    /// [`ServerEvent::RequestEnd`]. When `false` (the default) they are
    /// validated and discarded. Trailers never change how a message is
    /// framed either way.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// conn.set_report_trailers(true);
    /// let _ = conn.feed(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nDigest: sha-256=x\r\n\r\n");
    /// let mut digest = None;
    /// loop {
    ///     match conn.poll().unwrap() {
    ///         ServerEvent::Trailers(t) => digest = t.clone().find(|(n, _)| n.eq_ignore_ascii_case("digest")).map(|(_, v)| v.to_vec()),
    ///         ServerEvent::RequestEnd => break,
    ///         _ => {}
    ///     }
    /// }
    /// assert_eq!(digest.as_deref(), Some(&b"sha-256=x"[..]));
    /// ```
    pub fn set_report_trailers(&mut self, report: bool) {
        self.report_trailers = report;
    }

    /// Returns the connection to its initial state for a new socket,
    /// keeping the buffer and field-index allocations (and the limits,
    /// [`set_report_trailers`](Self::set_report_trailers), and
    /// [`set_wipe`](Self::set_wipe) settings). Everything per connection
    /// starts over: buffered input, the request in progress, keep-alive
    /// (allowed again), and the request count. With wiping on, the whole
    /// buffer is zeroed first.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{Progress, ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\nGET /next");
    /// assert!(matches!(conn.poll().unwrap(), ServerEvent::Request(_)));
    /// conn.reset(); // the socket closed; reuse the object for the next one
    /// assert_eq!(conn.progress(), Progress::Idle);
    /// assert!(conn.remaining_input().is_empty());
    /// ```
    pub fn reset(&mut self) {
        self.buf.reset();
        self.buf.pin_at_pos();
        self.scanner.reset();
        self.trailers.reset();
        self.decoder = Decoder::new();
        self.info = RequestInfo::EMPTY;
        self.state = ReqState::Head;
        self.resp = RespState::Idle;
        self.keep_alive = false;
        self.allow_keep_alive = true;
        self.continue_sent = false;
        self.body_seen = false;
        self.resp_chunked = false;
        self.requests_served = 0;
        self.preface_undecided = true;
    }

    /// Gives the input buffer's storage back (for a pool), wiped first when
    /// [`set_wipe`](Self::set_wipe) is on.
    ///
    /// # Examples
    ///
    /// ```
    /// let conn = http_net::ServerConn::new();
    /// assert_eq!(conn.into_buffer().capacity(), 0); // nothing was ever buffered
    /// ```
    #[must_use]
    pub fn into_buffer(mut self) -> Vec<u8> {
        self.buf.take_storage()
    }

    /// Frees the input buffer and the field indexes while the connection is
    /// idle between requests with nothing buffered, so thousands of idle
    /// keep-alive connections cost only their struct size. Returns whether
    /// memory was released; the next input allocates again.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{Response, ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    /// assert!(matches!(conn.poll().unwrap(), ServerEvent::Request(_)));
    /// assert!(!conn.shrink_idle()); // a request is in progress
    /// assert!(matches!(conn.poll().unwrap(), ServerEvent::RequestEnd));
    /// conn.respond(&Response::new(204), &mut Vec::new()).unwrap();
    /// assert!(matches!(conn.poll().unwrap(), ServerEvent::NeedInput));
    /// assert!(conn.shrink_idle());
    /// ```
    pub fn shrink_idle(&mut self) -> bool {
        if self.progress() != Progress::Idle || self.state != ReqState::Head {
            return false;
        }
        self.buf.unpin();
        let freed = self.buf.shrink();
        self.buf.pin_at_pos();
        if freed {
            self.scanner.fields = Vec::new();
            self.trailers.fields = Vec::new();
        }
        freed
    }

    /// When `true`, the bytes of every finished request (head, body, and
    /// framing) are zeroed before the buffer is reused, stale copies left by
    /// compaction are zeroed, and the whole buffer is zeroed on
    /// [`reset`](Self::reset), [`into_buffer`](Self::into_buffer), and drop,
    /// so credentials do not linger in memory between requests. Costs a
    /// `memset` of each request's bytes (about 30 to 60 ns for 2 KiB, an
    /// estimate). Off by default.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = http_net::ServerConn::new();
    /// conn.set_wipe(true);
    /// ```
    pub fn set_wipe(&mut self, wipe: bool) {
        self.buf.set_wipe(wipe);
    }

    #[inline]
    pub(crate) fn respond_dated<O: Output + ?Sized>(
        &mut self,
        response: &Response,
        date: Option<&[u8]>,
        out: &mut O,
    ) -> Result<(), HttpError> {
        let plan = self.start_response(response, date, out)?;
        if plan == BodyPlan::Raw {
            if let OutBody::Full(body) = &response.body {
                out.put(body);
            }
        }
        Ok(())
    }

    /// Validates and writes a response head, and moves the connection to
    /// the state it implies: the one code path behind `respond`,
    /// `respond_into`, and `write_head`. Nothing is written on error.
    // Forced inline: called from several entry points, it otherwise stays
    // out of line and `respond` measured about 7% slower than in 0.4.
    #[inline(always)]
    pub(crate) fn start_response<S: HeadSource + ?Sized, O: Output + ?Sized>(
        &mut self,
        spec: &S,
        date: Option<&[u8]>,
        out: &mut O,
    ) -> Result<BodyPlan, HttpError> {
        // Builder errors (a Response) or field errors (a borrowed head)
        // come first, as when a Response is written.
        let has_date = spec.check()?;
        let failed = self.state == ReqState::Failed;
        match self.state {
            ReqState::Body | ReqState::Complete | ReqState::Failed => {}
            ReqState::Head => return Err(HttpError::InvalidState("no request to respond to")),
            ReqState::Upgraded | ReqState::Closed => {
                return Err(HttpError::InvalidState(
                    "the connection is closed or upgraded",
                ));
            }
        }
        if self.resp != RespState::Idle {
            return Err(HttpError::InvalidState("a response was already started"));
        }
        let (status, body, upgrade) = (spec.status(), spec.body(), spec.upgrade());
        if !(100..=599).contains(&status) || ((100..200).contains(&status) && status != 101) {
            return Err(HttpError::InvalidStatus);
        }
        if upgrade.is_some() && status != 101 {
            return Err(HttpError::InvalidState(
                "an upgrade protocol needs status 101",
            ));
        }
        let (method, version) = if failed {
            (Method::Get, Version::Http11)
        } else {
            (self.info.method, self.info.version)
        };
        let bodiless = (100..200).contains(&status) || status == 204 || status == 304;
        let tunnel = status == 101 || (method == Method::Connect && (200..300).contains(&status));
        if (bodiless || tunnel) && !matches!(body, OutgoingBody::Empty | OutgoingBody::Full(0)) {
            return Err(HttpError::BodyNotAllowed);
        }
        if tunnel {
            let complete_upgrade =
                self.body_read() && (self.info.upgrade || method == Method::Connect);
            if !complete_upgrade || (status == 101 && upgrade.is_none()) || failed {
                return Err(HttpError::InvalidState(
                    "101 (or 2xx to CONNECT) must answer a complete upgrade request; \
                     build it with Response::switching_protocols",
                ));
            }
            // RFC 9110 section 7.8: never switch to a protocol the client
            // did not offer.
            if status == 101 && !upgrade.is_some_and(|p| self.view().offers(p)) {
                return Err(HttpError::UpgradeNotOffered);
            }
        }

        let mut close = failed
            || spec.close()
            || !self.keep_alive
            || !self.allow_keep_alive
            || !self.body_read();
        let head_only = method == Method::Head || bodiless || tunnel;
        self.resp_chunked = body == OutgoingBody::Chunked;
        let (mut encoder, declared) = match body {
            OutgoingBody::Empty => (Encoder::Length { remaining: 0 }, Some(0)),
            OutgoingBody::Full(n) | OutgoingBody::Length(n) => {
                (Encoder::Length { remaining: n }, Some(n))
            }
            OutgoingBody::Chunked if version == Version::Http10 => {
                close = true;
                (Encoder::CloseDelimited, None)
            }
            OutgoingBody::Chunked => (Encoder::Chunked, None),
        };

        write_status_line(out, status);
        if !(bodiless || tunnel) {
            push_framing(out, encoder, declared);
        }
        if tunnel {
            close = false;
        } else if close {
            out.put(b"connection: close\r\n");
        } else if version == Version::Http10 {
            out.put(b"connection: keep-alive\r\n");
        }
        if let Some(date) = date.filter(|_| !has_date) {
            out.put(b"date: ");
            out.put(date);
            out.put(b"\r\n");
        }
        spec.write_fields(out);
        out.put(b"\r\n");

        if head_only {
            encoder = Encoder::Discard;
        }
        self.keep_alive = !close;
        let plan = match body {
            OutgoingBody::Empty | OutgoingBody::Full(_) => {
                self.resp = RespState::Sent;
                self.requests_served += 1;
                match body {
                    OutgoingBody::Full(n) if n > 0 && !head_only => BodyPlan::Raw,
                    _ => BodyPlan::None,
                }
            }
            OutgoingBody::Length(_) | OutgoingBody::Chunked => {
                self.resp = RespState::Streaming(encoder);
                BodyPlan::Stream
            }
        };
        if tunnel {
            self.state = ReqState::Upgraded;
        } else if failed {
            self.state = ReqState::Closed;
        }
        Ok(plan)
    }

    /// Body bytes of a streamed response, into any output.
    pub(crate) fn stream_body<O: Output + ?Sized>(
        &mut self,
        data: &[u8],
        out: &mut O,
    ) -> Result<(), HttpError> {
        match &mut self.resp {
            RespState::Streaming(encoder) => encoder.write(data, out),
            _ => Err(HttpError::InvalidState("no streamed response in progress")),
        }
    }

    /// The end of a streamed response, with optional trailers, into any
    /// output.
    pub(crate) fn finish_body<O: Output + ?Sized>(
        &mut self,
        trailers: &[(&str, &[u8])],
        out: &mut O,
    ) -> Result<(), HttpError> {
        let RespState::Streaming(encoder) = &mut self.resp else {
            return Err(HttpError::InvalidState("no streamed response in progress"));
        };
        if !trailers.is_empty() && !self.resp_chunked {
            return Err(HttpError::TrailerNotAllowed);
        }
        match encoder {
            Encoder::Chunked => push_last_chunk_with_trailers(out, trailers)?,
            _ => {
                check_trailers(trailers)?;
                encoder.finish(out)?;
            }
        }
        if *encoder == Encoder::CloseDelimited {
            self.keep_alive = false;
        }
        self.resp = RespState::Sent;
        self.requests_served += 1;
        Ok(())
    }

    /// Writes `HTTP/1.1 100 Continue` into `out`: the answer to
    /// [`RequestHead::expects_continue`](crate::RequestHead::expects_continue)
    /// that tells the client to send the body.
    ///
    /// RFC 9110 section 10.1.1 requires a server that receives
    /// `Expect: 100-continue` to send either this or a final response before
    /// waiting for the body; clients otherwise stall (curl for one second,
    /// some indefinitely). Call it after [`ServerEvent::Request`], once the
    /// head has been judged acceptable.
    ///
    /// # Errors
    ///
    /// [`HttpError::InterimNotAllowed`] for an HTTP/1.0 request (RFC 9110
    /// section 15.2 forbids any 1xx to an HTTP/1.0 client), once a body byte
    /// has been read or the whole body has arrived, once a response has
    /// started, or when `100 Continue` was already sent for this request;
    /// [`HttpError::InvalidState`] when no request is waiting for its body
    /// (none has arrived, or the connection failed, closed, or upgraded).
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"PUT /f HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n");
    /// let ServerEvent::Request(req) = conn.poll()? else { unreachable!() };
    /// assert!(req.expects_continue());
    /// let mut out = Vec::new();
    /// conn.send_continue(&mut out)?;
    /// assert_eq!(out, b"HTTP/1.1 100 Continue\r\n\r\n");
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    pub fn send_continue(&mut self, out: &mut Vec<u8>) -> Result<(), HttpError> {
        if !matches!(self.state, ReqState::Body | ReqState::Complete) {
            return Err(HttpError::InvalidState(
                "100 Continue needs a request whose body is still to come",
            ));
        }
        if self.state == ReqState::Complete
            || self.decoder.is_read()
            || self.body_seen
            || self.resp != RespState::Idle
            || self.info.version != Version::Http11
            || self.continue_sent
        {
            return Err(HttpError::InterimNotAllowed);
        }
        self.continue_sent = true;
        out.extend_from_slice(b"HTTP/1.1 100 Continue\r\n\r\n");
        Ok(())
    }

    /// Writes body bytes of a streamed response into `out`. For a `HEAD`
    /// request the bytes are dropped.
    ///
    /// # Errors
    ///
    /// [`HttpError::BodyLengthMismatch`] past the declared
    /// [`Response::content_length`]; [`HttpError::InvalidState`] when no
    /// streamed response is in progress.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{Response, ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"GET /log HTTP/1.1\r\nHost: a\r\n\r\n");
    /// while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
    /// let mut out = Vec::new();
    /// conn.respond(&Response::new(200).chunked(), &mut out).unwrap();
    /// conn.send_body(b"line 1\n", &mut out).unwrap();
    /// conn.end_body(&mut out).unwrap();
    /// assert!(out.ends_with(b"7\r\nline 1\n\r\n0\r\n\r\n"));
    /// ```
    pub fn send_body(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), HttpError> {
        self.stream_body(data, out)
    }

    /// Ends a streamed response body (the last chunk for chunked encoding).
    ///
    /// # Errors
    ///
    /// [`HttpError::BodyLengthMismatch`] when fewer bytes than the declared
    /// length were sent; [`HttpError::InvalidState`] when no streamed
    /// response is in progress.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{HttpError, Response, ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    /// while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
    /// let mut out = Vec::new();
    /// conn.respond(&Response::new(200).content_length(3), &mut out).unwrap();
    /// conn.send_body(b"ab", &mut out).unwrap();
    /// assert_eq!(conn.end_body(&mut out), Err(HttpError::BodyLengthMismatch));
    /// ```
    pub fn end_body(&mut self, out: &mut Vec<u8>) -> Result<(), HttpError> {
        self.end_body_with_trailers(&[], out)
    }

    /// Ends a streamed chunked body with a trailer section: the last chunk,
    /// then `trailers` as fields. Every field is validated before anything
    /// is written.
    ///
    /// Trailers are optional metadata a recipient may discard (RFC 9110
    /// section 6.5), so when the body could not be chunked (an HTTP/1.0
    /// client forced a close-delimited body) or is not sent at all (`HEAD`),
    /// they are dropped with it and the call still succeeds: the handler
    /// does not need to know which framing the client forced.
    ///
    /// # Errors
    ///
    /// [`HttpError::TrailerNotAllowed`] for a field RFC 9110 section 6.5.1
    /// keeps out of trailers (framing, routing, authentication, request
    /// modifiers, response control, content handling: `content-length`,
    /// `host`, `authorization`, `set-cookie`, `content-type`, `date`, and
    /// the rest of the list in `docs/API.md`) or for a body declared with
    /// [`Response::content_length`]; the field errors of
    /// [`Response::header`]; [`HttpError::BodyLengthMismatch`] and
    /// [`HttpError::InvalidState`] as for [`end_body`](Self::end_body).
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{HttpError, Response, ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"GET /data HTTP/1.1\r\nHost: a\r\nTE: trailers\r\n\r\n");
    /// while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
    /// let mut out = Vec::new();
    /// conn.respond(&Response::new(200).chunked(), &mut out)?;
    /// conn.send_body(b"rows", &mut out)?;
    /// assert_eq!(
    ///     conn.end_body_with_trailers(&[("content-type", b"text/csv")], &mut out),
    ///     Err(HttpError::TrailerNotAllowed)
    /// );
    /// conn.end_body_with_trailers(&[("server-timing", b"db;dur=53")], &mut out)?;
    /// assert!(out.ends_with(b"4\r\nrows\r\n0\r\nserver-timing: db;dur=53\r\n\r\n"));
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    pub fn end_body_with_trailers(
        &mut self,
        trailers: &[(&str, &[u8])],
        out: &mut Vec<u8>,
    ) -> Result<(), HttpError> {
        self.finish_body(trailers, out)
    }
}

/// A response head to write: a [`Response`], whose fields its builder
/// already serialized and checked, or a
/// [`ResponseHeadRef`](crate::ResponseHeadRef), whose borrowed fields are
/// checked here. `start_response` is generic over it, so each source gets
/// its own compiled path with no runtime dispatch.
pub(crate) trait HeadSource {
    fn status(&self) -> u16;
    fn body(&self) -> OutgoingBody;
    fn close(&self) -> bool;
    /// The protocol of a 101.
    fn upgrade(&self) -> Option<&[u8]>;
    /// Validates what the builder did not: returns whether a `date` field
    /// is set.
    fn check(&self) -> Result<bool, HttpError>;
    fn write_fields<O: Output + ?Sized>(&self, out: &mut O);
}

impl HeadSource for Response {
    #[inline]
    fn status(&self) -> u16 {
        Response::status(self)
    }

    #[inline]
    fn body(&self) -> OutgoingBody {
        match &self.body {
            OutBody::Full(b) => OutgoingBody::Full(b.len() as u64),
            OutBody::Length(n) => OutgoingBody::Length(*n),
            OutBody::Chunked => OutgoingBody::Chunked,
        }
    }

    #[inline]
    fn close(&self) -> bool {
        self.close
    }

    #[inline]
    fn upgrade(&self) -> Option<&[u8]> {
        self.upgrade_protocol()
    }

    #[inline]
    fn check(&self) -> Result<bool, HttpError> {
        match self.error() {
            Some(e) => Err(e),
            None => Ok(self.has_date),
        }
    }

    #[inline]
    fn write_fields<O: Output + ?Sized>(&self, out: &mut O) {
        out.put(self.fields());
    }
}

impl HeadSource for ResponseHeadRef<'_> {
    #[inline]
    fn status(&self) -> u16 {
        self.status
    }

    #[inline]
    fn body(&self) -> OutgoingBody {
        self.body
    }

    #[inline]
    fn close(&self) -> bool {
        self.close
    }

    #[inline]
    fn upgrade(&self) -> Option<&[u8]> {
        self.upgrade.map(str::as_bytes)
    }

    fn check(&self) -> Result<bool, HttpError> {
        if let Some(protocol) = self.upgrade {
            check_upgrade_protocol(protocol.as_bytes())?;
        }
        let mut has_date = false;
        for &(name, value) in self.fields {
            has_date |= check_response_field(name, value)?;
        }
        Ok(has_date)
    }

    fn write_fields<O: Output + ?Sized>(&self, out: &mut O) {
        if let Some(protocol) = self.upgrade {
            // The same lines, in the same place, as
            // Response::switching_protocols writes.
            out.put(b"connection: upgrade\r\nupgrade: ");
            out.put(protocol.as_bytes());
            out.put(b"\r\n");
        }
        for &(name, value) in self.fields {
            write_field(out, name, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn events(conn: &mut ServerConn) -> Vec<alloc::string::String> {
        let mut log = Vec::new();
        loop {
            match conn.poll() {
                Ok(ServerEvent::Request(r)) => log.push(alloc::format!("req {}", r.target())),
                Ok(ServerEvent::Body(b)) => log.push(alloc::format!("body {}", b.len())),
                Ok(ServerEvent::RequestEnd) => {
                    log.push("end".into());
                    return log;
                }
                Ok(other) => {
                    log.push(alloc::format!("{other:?}"));
                    return log;
                }
                Err(e) => {
                    log.push(alloc::format!("err {e:?}"));
                    return log;
                }
            }
        }
    }

    #[test]
    fn test_early_response_closes_connection() {
        let mut conn = ServerConn::new();
        let _ = conn.feed(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nab");
        assert!(matches!(conn.poll(), Ok(ServerEvent::Request(_))));
        let mut out = Vec::new();
        conn.respond(&Response::new(413), &mut out).unwrap();
        assert!(out.windows(17).any(|w| w == b"connection: close"));
        assert!(matches!(conn.poll(), Ok(ServerEvent::Closed)));
    }

    #[test]
    fn test_respond_after_failure_is_once_and_closes() {
        let mut conn = ServerConn::new();
        let _ = conn.feed(b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(conn.poll().unwrap_err(), HttpError::MissingHost);
        let mut out = Vec::new();
        conn.respond(&Response::new(400), &mut out).unwrap();
        assert!(out.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
        assert!(conn.respond(&Response::new(400), &mut out).is_err());
        assert!(matches!(conn.poll(), Ok(ServerEvent::Closed)));
    }

    #[test]
    fn test_state_errors() {
        let mut conn = ServerConn::new();
        let mut out = Vec::new();
        assert!(matches!(
            conn.respond(&Response::new(200), &mut out),
            Err(HttpError::InvalidState(_))
        ));
        assert!(matches!(
            conn.send_body(b"x", &mut out),
            Err(HttpError::InvalidState(_))
        ));
        assert!(matches!(
            conn.end_body(&mut out),
            Err(HttpError::InvalidState(_))
        ));
        let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(events(&mut conn), vec!["req /", "end"]);
        assert_eq!(
            conn.respond(&Response::new(99), &mut out),
            Err(HttpError::InvalidStatus)
        );
        assert_eq!(
            conn.respond(&Response::new(100), &mut out),
            Err(HttpError::InvalidStatus)
        );
        assert_eq!(
            conn.respond(&Response::new(204).body(&b"x"[..]), &mut out),
            Err(HttpError::BodyNotAllowed)
        );
        assert!(matches!(
            conn.respond(&Response::switching_protocols("x"), &mut out),
            Err(HttpError::InvalidState(_))
        ));
        conn.respond(&Response::new(204), &mut out).unwrap();
        assert!(matches!(
            conn.respond(&Response::new(200), &mut out),
            Err(HttpError::InvalidState(_))
        ));
    }

    #[test]
    fn test_http10_keep_alive_and_chunked_fallback() {
        let mut conn = ServerConn::new();
        let _ = conn.feed(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
        assert_eq!(events(&mut conn), vec!["req /", "end"]);
        let mut out = Vec::new();
        conn.respond(&Response::text(200, "x"), &mut out).unwrap();
        assert!(out.windows(22).any(|w| w == b"connection: keep-alive"));
        assert!(matches!(conn.poll(), Ok(ServerEvent::NeedInput)));

        let _ = conn.feed(b"GET / HTTP/1.0\r\n\r\n");
        assert_eq!(events(&mut conn), vec!["req /", "end"]);
        let mut out = Vec::new();
        conn.respond(&Response::new(200).chunked(), &mut out)
            .unwrap();
        conn.send_body(b"abc", &mut out).unwrap();
        conn.end_body(&mut out).unwrap();
        assert!(out.ends_with(b"\r\n\r\nabc"));
        assert!(!out.windows(17).any(|w| w == b"transfer-encoding"));
        assert!(matches!(conn.poll(), Ok(ServerEvent::Closed)));
    }

    fn upgrade_request(conn: &mut ServerConn, offer: &str) {
        let msg = alloc::format!(
            "GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: {offer}\r\n\r\n"
        );
        let _ = conn.feed(msg.as_bytes());
        assert_eq!(events(conn), vec!["req /", "end"]);
    }

    #[test]
    fn test_switching_protocols_must_name_an_offered_protocol() {
        let mut conn = ServerConn::new();
        upgrade_request(&mut conn, "websocket/13, foo/2");
        let mut out = Vec::new();
        // `foo` alone would match `foo/2`: a name without a version
        // answers an offer of that name with any version.
        for refused in ["ftp", "foo/3", "websocket/12", "h2c"] {
            assert_eq!(
                conn.respond(&Response::switching_protocols(refused), &mut out),
                Err(HttpError::UpgradeNotOffered),
                "{refused}"
            );
            assert!(out.is_empty());
            assert!(!conn.is_upgraded());
        }
        conn.respond(&Response::switching_protocols("WebSocket"), &mut out)
            .unwrap();
        assert!(conn.is_upgraded());
        assert!(out.windows(18).any(|w| w == b"upgrade: WebSocket"));
    }

    #[test]
    fn test_refused_switch_leaves_a_normal_response_possible() {
        let mut conn = ServerConn::new();
        upgrade_request(&mut conn, "websocket");
        let mut out = Vec::new();
        assert_eq!(
            conn.respond(&Response::switching_protocols("irc"), &mut out),
            Err(HttpError::UpgradeNotOffered)
        );
        conn.respond(&Response::new(426), &mut out).unwrap();
        assert!(out.starts_with(b"HTTP/1.1 426 Upgrade Required\r\n"));
        assert!(matches!(conn.poll(), Ok(ServerEvent::NeedInput)));
    }

    #[test]
    fn test_h2c_only_offer_is_served_as_http11() {
        let mut conn = ServerConn::new();
        let _ = conn.feed(
            b"GET / HTTP/1.1\r\nHost: a\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAoAAA\r\n\r\n",
        );
        assert!(matches!(conn.poll(), Ok(ServerEvent::Request(r)) if !r.is_upgrade()));
        assert!(matches!(conn.poll(), Ok(ServerEvent::RequestEnd)));
        let mut out = Vec::new();
        assert!(matches!(
            conn.respond(&Response::switching_protocols("websocket"), &mut out),
            Err(HttpError::InvalidState(_))
        ));
        conn.respond(&Response::new(200), &mut out).unwrap();
        assert!(matches!(conn.poll(), Ok(ServerEvent::NeedInput)));
    }

    #[test]
    fn test_unregistered_status_keeps_the_space_before_an_empty_reason() {
        let mut conn = ServerConn::new();
        let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(events(&mut conn), vec!["req /", "end"]);
        let mut out = Vec::new();
        conn.respond(&Response::new(299), &mut out).unwrap();
        assert!(out.starts_with(b"HTTP/1.1 299 \r\n"));
    }

    #[test]
    fn test_connect_tunnel() {
        let mut conn = ServerConn::new();
        let _ = conn.feed(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nTLS");
        assert_eq!(events(&mut conn), vec!["req example.com:443", "end"]);
        let mut out = Vec::new();
        conn.respond(&Response::new(200), &mut out).unwrap();
        assert_eq!(out, b"HTTP/1.1 200 OK\r\n\r\n");
        assert!(matches!(conn.poll(), Ok(ServerEvent::Upgraded)));
        assert_eq!(conn.remaining_input(), b"TLS");
        assert!(conn.request().is_some());
    }
}
