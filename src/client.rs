//! The client side of an HTTP/1.1 connection, without I/O.

use alloc::vec::Vec;

use crate::{
    body::{Decoder, Encoder, Step, push_framing},
    buffer::Buffer,
    error::HttpError,
    head::{
        Asked, HeadKind, HeadScanner, Method, Progress, ResponseHead, ResponseInfo,
        interpret_response,
    },
    limits::Limits,
    message::{OutBody, Request},
};

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
#[derive(Debug)]
pub enum ClientEvent<'a> {
    /// The response head arrived (interim 1xx responses other than 101 are
    /// skipped; together they count against
    /// [`Limits::max_header_bytes`](crate::Limits::max_header_bytes)). Its
    /// body follows as [`Body`](ClientEvent::Body) events, then
    /// [`ResponseEnd`](ClientEvent::ResponseEnd).
    Response(ResponseHead<'a>),
    /// A run of body bytes, after chunked decoding.
    Body(&'a [u8]),
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Idle,
    Head,
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
/// One request is outstanding at a time. [`send_request`](Self::send_request)
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
    state: State,
    req: ReqWrite,
    keep_alive: bool,
    /// Bytes of interim (1xx) heads skipped for the current request. They
    /// count against the header budget so that a server cannot keep the
    /// client parsing forever without answering.
    interim_bytes: usize,
}

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
        Self {
            buf: Buffer::new(limits.buffer_cap()),
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
            state: State::Idle,
            req: ReqWrite::Sent,
            keep_alive: true,
            interim_bytes: 0,
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
    /// # Errors
    ///
    /// - the first error recorded by the [`Request`] builder;
    /// - [`HttpError::MissingHost`] when the request has no `host` header;
    /// - [`HttpError::InvalidState`] when a request is already outstanding
    ///   or the connection is closed.
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
            _ => return Err(HttpError::InvalidState("a request is already outstanding")),
        }
        if !self.buf.unread().is_empty() {
            return Err(HttpError::UnexpectedData);
        }
        if !request.has_host {
            return Err(HttpError::MissingHost);
        }
        let method = request.method_kind;
        let expects_body = matches!(method, Method::Post | Method::Put | Method::Patch);
        let (encoder, declared) = match &request.body {
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
        let mut encoder = encoder;
        match &request.body {
            OutBody::Full(b) => {
                encoder.write(b, out)?;
                self.req = ReqWrite::Sent;
            }
            _ => self.req = ReqWrite::Streaming(encoder),
        }
        self.asked = Asked {
            head: method == Method::Head,
            connect: method == Method::Connect,
        };
        self.upgrade_asked = request.upgrade;
        self.keep_alive = !request.close;
        self.buf.unpin();
        self.buf.pin_at_pos();
        self.scanner.reset();
        self.interim_bytes = 0;
        self.state = State::Head;
        Ok(())
    }

    /// Writes body bytes of a streamed request.
    ///
    /// # Errors
    ///
    /// [`HttpError::BodyLengthMismatch`] past the declared length;
    /// [`HttpError::InvalidState`] when no streamed request is in progress.
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
        match &mut self.req {
            ReqWrite::Streaming(encoder) => encoder.write(data, out),
            ReqWrite::Sent => Err(HttpError::InvalidState("no streamed request in progress")),
        }
    }

    /// Ends a streamed request body.
    ///
    /// # Errors
    ///
    /// [`HttpError::BodyLengthMismatch`] when fewer bytes than declared were
    /// sent; [`HttpError::InvalidState`] when no streamed request is in
    /// progress.
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
        match &mut self.req {
            ReqWrite::Streaming(encoder) => {
                encoder.finish(out)?;
                self.req = ReqWrite::Sent;
                Ok(())
            }
            ReqWrite::Sent => Err(HttpError::InvalidState("no streamed request in progress")),
        }
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
                State::Body => return self.poll_body(),
                State::Complete => {
                    let reusable =
                        self.keep_alive && self.info.keep_alive && self.req == ReqWrite::Sent;
                    if reusable {
                        self.state = State::Idle;
                    } else {
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
            let progress = self
                .scanner
                .advance(self.buf.from(start), &self.limits, HeadKind::Response, true)
                .map_err(|e| self.fail(e))?;
            let len = match progress {
                Progress::Partial if self.buf.is_eof() => {
                    return Err(self.fail(HttpError::UnexpectedEof));
                }
                Progress::Partial => return Ok(ClientEvent::NeedInput),
                Progress::Done(len) => len,
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
                if !self.upgrade_asked || !info.upgrade_field {
                    return Err(self.fail(HttpError::UnexpectedUpgrade));
                }
                true
            } else {
                self.asked.connect && (200..300).contains(&status)
            };
            if switched {
                self.state = State::Upgraded;
            } else if (100..200).contains(&status) {
                // Interim response (100 Continue, 103 Early Hints): skip it
                // and keep waiting for the final one.
                self.interim_bytes = self.interim_bytes.saturating_add(len);
                if self.interim_bytes > self.limits.max_header_bytes() {
                    return Err(self.fail(HttpError::HeadersTooLarge));
                }
                self.buf.unpin();
                self.buf.pin_at_pos();
                self.scanner.reset();
                continue;
            } else {
                self.decoder.start(info.framing);
                self.state = State::Body;
            }
            return Ok(ClientEvent::Response(self.view()));
        }
    }

    fn poll_body(&mut self) -> Result<ClientEvent<'_>, HttpError> {
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
                Ok(ClientEvent::Body(self.buf.range(start, start + n)))
            }
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
