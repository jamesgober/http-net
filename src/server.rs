//! The server side of an HTTP/1.1 connection, without I/O.

use alloc::vec::Vec;

use crate::{
    body::{Decoder, Encoder, Step, push_framing},
    buffer::Buffer,
    error::HttpError,
    head::{
        HeadKind, HeadScanner, Method, Progress, RequestHead, RequestInfo, Version,
        interpret_request,
    },
    limits::Limits,
    message::{OutBody, Response, reason_phrase},
    syntax::push_decimal,
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
    continue_sent: bool,
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
        let mut buf = Buffer::new(limits.buffer_cap());
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
            continue_sent: false,
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
                    if self.resp == RespState::Sent && !self.decoder.is_done() {
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
        let msg = self.buf.from(start);
        let progress = self
            .scanner
            .advance(msg, &self.limits, HeadKind::Request, true)
            .map_err(|e| self.fail(e))?;
        let len = match progress {
            Progress::Partial if self.buf.is_eof() => {
                if self.buf.from(start).is_empty() {
                    self.state = ReqState::Closed;
                    return Ok(ServerEvent::Closed);
                }
                return Err(self.fail(HttpError::UnexpectedEof));
            }
            Progress::Partial => return Ok(ServerEvent::NeedInput),
            Progress::Done(len) => len,
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
            &mut framing_bytes,
        );
        self.buf.consume(framing_bytes);
        match step.map_err(|e| self.fail(e))? {
            Step::Data(n) => {
                let start = self.buf.pos();
                self.buf.consume(n);
                Ok(ServerEvent::Body(self.buf.range(start, start + n)))
            }
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
        self.buf.unpin();
        self.buf.pin_at_pos();
        self.scanner.reset();
        self.resp = RespState::Idle;
        self.info = RequestInfo::EMPTY;
        self.continue_sent = false;
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
        self.state == ReqState::Complete || (self.state == ReqState::Body && self.decoder.is_done())
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
    /// - [`HttpError::BodyNotAllowed`] for a body on 1xx, 204, or 304;
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

    pub(crate) fn respond_dated(
        &mut self,
        response: &Response,
        date: Option<&[u8]>,
        out: &mut Vec<u8>,
    ) -> Result<(), HttpError> {
        if let Some(e) = response.error() {
            return Err(e);
        }
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
        let status = response.status();
        if !(100..=599).contains(&status) || ((100..200).contains(&status) && status != 101) {
            return Err(HttpError::InvalidStatus);
        }
        let (method, version) = if failed {
            (Method::Get, Version::Http11)
        } else {
            (self.info.method, self.info.version)
        };
        let bodiless = (100..200).contains(&status) || status == 204 || status == 304;
        let tunnel = status == 101 || (method == Method::Connect && (200..300).contains(&status));
        if bodiless || tunnel {
            let empty = matches!(&response.body, OutBody::Full(b) if b.is_empty());
            if !empty {
                return Err(HttpError::BodyNotAllowed);
            }
        }
        if tunnel {
            let complete_upgrade =
                self.body_read() && (self.info.upgrade || method == Method::Connect);
            if !complete_upgrade || (status == 101 && !response.upgrade) || failed {
                return Err(HttpError::InvalidState(
                    "101 (or 2xx to CONNECT) must answer a complete upgrade request; \
                     build it with Response::switching_protocols",
                ));
            }
        }

        let mut close = failed || response.close || !self.keep_alive || !self.body_read();
        let head_only = method == Method::Head || bodiless || tunnel;
        let (mut encoder, declared) = match &response.body {
            OutBody::Full(b) => (
                Encoder::Length {
                    remaining: b.len() as u64,
                },
                Some(b.len() as u64),
            ),
            OutBody::Length(n) => (Encoder::Length { remaining: *n }, Some(*n)),
            OutBody::Chunked if version == Version::Http10 => {
                close = true;
                (Encoder::CloseDelimited, None)
            }
            OutBody::Chunked => (Encoder::Chunked, None),
        };

        out.extend_from_slice(b"HTTP/1.1 ");
        push_decimal(out, u64::from(status));
        out.push(b' ');
        out.extend_from_slice(reason_phrase(status).as_bytes());
        out.extend_from_slice(b"\r\n");
        if !(bodiless || tunnel) {
            push_framing(out, encoder, declared);
        }
        if tunnel {
            close = false;
        } else if close {
            out.extend_from_slice(b"connection: close\r\n");
        } else if version == Version::Http10 {
            out.extend_from_slice(b"connection: keep-alive\r\n");
        }
        if let Some(date) = date.filter(|_| !response.has_date) {
            out.extend_from_slice(b"date: ");
            out.extend_from_slice(date);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(response.fields());
        out.extend_from_slice(b"\r\n");

        if head_only {
            encoder = Encoder::Discard;
        }
        self.keep_alive = !close;
        match &response.body {
            OutBody::Full(b) => {
                encoder.write(b, out)?;
                self.resp = RespState::Sent;
            }
            _ => self.resp = RespState::Streaming(encoder),
        }
        if tunnel {
            self.state = ReqState::Upgraded;
        } else if failed {
            self.state = ReqState::Closed;
        }
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
    /// [`HttpError::InvalidState`] unless the current request is HTTP/1.1,
    /// its body has not been read yet, no response has been started, and
    /// `100 Continue` has not already been sent for it. RFC 9110 section
    /// 15.2 forbids any 1xx to an HTTP/1.0 client.
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
        if self.state != ReqState::Body
            || self.decoder.is_done()
            || self.resp != RespState::Idle
            || self.info.version != Version::Http11
            || self.continue_sent
        {
            return Err(HttpError::InvalidState(
                "100 Continue answers an HTTP/1.1 request whose body has not been read, \
                 once, before the final response",
            ));
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
        match &mut self.resp {
            RespState::Streaming(encoder) => encoder.write(data, out),
            _ => Err(HttpError::InvalidState("no streamed response in progress")),
        }
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
        match &mut self.resp {
            RespState::Streaming(encoder) => {
                encoder.finish(out)?;
                if *encoder == Encoder::CloseDelimited {
                    self.keep_alive = false;
                }
                self.resp = RespState::Sent;
                Ok(())
            }
            _ => Err(HttpError::InvalidState("no streamed response in progress")),
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
