//! Outgoing messages: the `Response` a server sends and the `Request` a
//! client sends.
//!
//! Both builders validate as they go and remember the first problem instead
//! of failing each call, so a message can be built in one chained
//! expression; the problem surfaces as an error when the connection writes
//! the message. Framing headers (`content-length`, `transfer-encoding`,
//! `connection`, `upgrade`) are owned by the connection, which derives them
//! from the body and the exchange; setting them by hand is refused, which
//! makes conflicting framing on the way out impossible.

use alloc::{borrow::Cow, format, string::String, vec::Vec};
use core::fmt;

use crate::{
    error::HttpError,
    head::{Method, check_target},
    syntax::{check_field_value, is_token, trim_ows},
};

/// How an outgoing message's body is supplied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OutBody {
    /// The whole body, sent with `content-length`.
    Full(Cow<'static, [u8]>),
    /// Streamed afterwards with exactly this many bytes.
    Length(u64),
    /// Streamed afterwards with chunked encoding.
    Chunked,
}

/// Validates a field and appends `name: value\r\n`.
fn push_field(
    fields: &mut Vec<u8>,
    name: &str,
    value: &[u8],
    reserved: &[&str],
) -> Result<(), HttpError> {
    if !is_token(name.as_bytes()) {
        return Err(HttpError::InvalidHeaderName);
    }
    if reserved.iter().any(|r| r.eq_ignore_ascii_case(name)) {
        return Err(HttpError::ReservedHeader);
    }
    if trim_ows(value).len() != value.len() {
        // Surrounding whitespace would be stripped by the recipient; refusing
        // it keeps what is sent equal to what is received.
        return Err(HttpError::InvalidHeaderValue);
    }
    check_field_value(value)?;
    fields.extend_from_slice(name.as_bytes());
    fields.extend_from_slice(b": ");
    fields.extend_from_slice(value);
    fields.extend_from_slice(b"\r\n");
    Ok(())
}

const RESPONSE_RESERVED: &[&str] = &[
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
];
const REQUEST_RESERVED: &[&str] = &[
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
];

/// A response for a [`ServerConn`](crate::ServerConn) to send.
///
/// The status line, `content-length` / `transfer-encoding`, and
/// `connection` are written by the connection, which knows the request's
/// method and version: a `HEAD` request gets the headers without the body,
/// an HTTP/1.0 client never gets chunked encoding, and `connection: close`
/// is added whenever the connection will close.
///
/// # Examples
///
/// ```
/// use http_net::Response;
///
/// let ok = Response::text(200, "hello");
/// assert_eq!(ok.status(), 200);
///
/// let asset = Response::new(200)
///     .header("content-type", "text/css")
///     .header("cache-control", "max-age=31536000, immutable")
///     .body(&b"body { margin: 0 }"[..]);
/// assert_eq!(asset.header_value("content-type"), Some(&b"text/css"[..]));
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Response {
    status: u16,
    fields: Vec<u8>,
    pub(crate) body: OutBody,
    pub(crate) close: bool,
    pub(crate) upgrade: bool,
    pub(crate) has_date: bool,
    error: Option<HttpError>,
}

impl Response {
    /// A response with this status, no extra headers, and an empty body.
    ///
    /// The status is validated when the response is written (`100..=599`,
    /// and only `101` among the 1xx codes).
    ///
    /// # Examples
    ///
    /// ```
    /// let r = http_net::Response::new(204);
    /// assert_eq!(r.status(), 204);
    /// ```
    #[must_use]
    pub fn new(status: u16) -> Self {
        Self {
            status,
            fields: Vec::new(),
            body: OutBody::Full(Cow::Borrowed(&[])),
            close: false,
            upgrade: false,
            has_date: false,
            error: None,
        }
    }

    /// A `text/plain; charset=utf-8` response with `text` as its body.
    ///
    /// # Examples
    ///
    /// ```
    /// let r = http_net::Response::text(404, "no such page");
    /// assert_eq!(r.body_bytes(), Some(&b"no such page"[..]));
    /// ```
    #[must_use]
    pub fn text(status: u16, text: &str) -> Self {
        Self::new(status)
            .header("content-type", "text/plain; charset=utf-8")
            .body(text.as_bytes().to_vec())
    }

    /// A `101 Switching Protocols` response handing the connection to
    /// `protocol` (for example `websocket`). The connection writes
    /// `connection: upgrade` and `upgrade: <protocol>`; add any
    /// protocol-specific headers (such as `sec-websocket-accept`) with
    /// [`header`](Self::header).
    ///
    /// # Examples
    ///
    /// ```
    /// let r = http_net::Response::switching_protocols("websocket")
    ///     .header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    /// assert_eq!(r.status(), 101);
    /// assert_eq!(r.header_value("upgrade"), Some(&b"websocket"[..]));
    /// ```
    #[must_use]
    pub fn switching_protocols(protocol: &str) -> Self {
        let mut r = Self::new(101);
        r.upgrade = true;
        if !is_token(protocol.as_bytes()) {
            r.error = Some(HttpError::InvalidHeaderValue);
            return r;
        }
        r.fields
            .extend_from_slice(b"connection: upgrade\r\nupgrade: ");
        r.fields.extend_from_slice(protocol.as_bytes());
        r.fields.extend_from_slice(b"\r\n");
        r
    }

    /// Adds a header field. The name must be a token and the value may not
    /// contain control characters other than tab, nor leading or trailing
    /// whitespace. Framing headers are refused with
    /// [`HttpError::ReservedHeader`]; the first problem is reported when the
    /// response is written.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{HttpError, Response, ServerConn};
    ///
    /// let bad = Response::new(200).header("content-length", "5");
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    /// let _ = conn.poll();
    /// assert_eq!(conn.respond(&bad, &mut Vec::new()), Err(HttpError::ReservedHeader));
    /// ```
    #[must_use]
    pub fn header(mut self, name: &str, value: impl AsRef<[u8]>) -> Self {
        if self.error.is_none() {
            let value = value.as_ref();
            if let Err(e) = push_field(&mut self.fields, name, value, RESPONSE_RESERVED) {
                self.error = Some(e);
            } else if name.eq_ignore_ascii_case("date") {
                self.has_date = true;
            }
        }
        self
    }

    /// Sets the whole body; it is sent with `content-length`. Static data
    /// (an embedded asset) is borrowed rather than copied.
    ///
    /// # Examples
    ///
    /// ```
    /// static PAGE: &[u8] = b"<!doctype html><title>x</title>";
    /// let r = http_net::Response::new(200).body(PAGE);
    /// assert_eq!(r.body_bytes(), Some(PAGE));
    /// ```
    #[must_use]
    pub fn body(mut self, body: impl Into<Cow<'static, [u8]>>) -> Self {
        self.body = OutBody::Full(body.into());
        self
    }

    /// Streams the body with chunked encoding: after
    /// [`ServerConn::respond`](crate::ServerConn::respond), send data with
    /// [`ServerConn::send_body`](crate::ServerConn::send_body) and end it
    /// with [`ServerConn::end_body`](crate::ServerConn::end_body). For an
    /// HTTP/1.0 client the connection falls back to closing the connection
    /// to end the body.
    ///
    /// # Examples
    ///
    /// ```
    /// let r = http_net::Response::new(200).chunked();
    /// assert_eq!(r.body_bytes(), None);
    /// ```
    #[must_use]
    pub fn chunked(mut self) -> Self {
        self.body = OutBody::Chunked;
        self
    }

    /// Streams a body of exactly `len` bytes, sent with `content-length`;
    /// sending more or fewer is [`HttpError::BodyLengthMismatch`].
    ///
    /// # Examples
    ///
    /// ```
    /// let r = http_net::Response::new(200).content_length(1 << 20);
    /// assert_eq!(r.body_bytes(), None);
    /// ```
    #[must_use]
    pub fn content_length(mut self, len: u64) -> Self {
        self.body = OutBody::Length(len);
        self
    }

    /// Closes the connection after this response.
    ///
    /// # Examples
    ///
    /// ```
    /// let r = http_net::Response::new(503).close();
    /// assert!(r.closes());
    /// ```
    #[must_use]
    pub fn close(mut self) -> Self {
        self.close = true;
        self
    }

    /// The status code.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Response::new(418).status(), 418);
    /// ```
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Whether [`close`](Self::close) was requested.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(!http_net::Response::new(200).closes());
    /// ```
    #[must_use]
    pub fn closes(&self) -> bool {
        self.close
    }

    /// The full body, or `None` for a streamed one.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Response::new(200).body_bytes(), Some(&[][..]));
    /// ```
    #[must_use]
    pub fn body_bytes(&self) -> Option<&[u8]> {
        match &self.body {
            OutBody::Full(b) => Some(b),
            _ => None,
        }
    }

    /// The value of the first header named `name` added to this response
    /// (ASCII case-insensitive), including the `upgrade` of
    /// [`switching_protocols`](Self::switching_protocols).
    ///
    /// # Examples
    ///
    /// ```
    /// let r = http_net::Response::new(200).header("x-id", "7");
    /// assert_eq!(r.header_value("X-ID"), Some(&b"7"[..]));
    /// ```
    #[must_use]
    pub fn header_value(&self, name: &str) -> Option<&[u8]> {
        field_value(&self.fields, name)
    }

    pub(crate) fn error(&self) -> Option<HttpError> {
        self.error
    }

    pub(crate) fn fields(&self) -> &[u8] {
        &self.fields
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("fields", &String::from_utf8_lossy(&self.fields))
            .field("body", &body_debug(&self.body))
            .field("close", &self.close)
            .field("error", &self.error)
            .finish()
    }
}

/// A request for a [`ClientConn`](crate::ClientConn) to send.
///
/// HTTP/1.1 requires a `Host` field; the connection refuses to send a
/// request without one. The request line always says HTTP/1.1.
///
/// # Examples
///
/// ```
/// use http_net::Request;
///
/// let get = Request::get("/index.html").header("host", "example.com");
/// let post = Request::post("/api")
///     .header("host", "example.com")
///     .header("content-type", "application/json")
///     .body(br#"{"ok":true}"#.to_vec());
/// assert_eq!(get.method(), "GET");
/// assert_eq!(post.target(), "/api");
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    method: Cow<'static, str>,
    pub(crate) method_kind: Method,
    target: String,
    fields: Vec<u8>,
    pub(crate) body: OutBody,
    pub(crate) close: bool,
    pub(crate) upgrade: bool,
    pub(crate) has_host: bool,
    error: Option<HttpError>,
}

impl Request {
    /// A request with `method` and `target`, validated when it is sent:
    /// the method must be a token and the target must be in a form the
    /// method allows (`/path?query`, an absolute URI, `host:port` for
    /// `CONNECT`, or `*` for `OPTIONS`).
    ///
    /// # Examples
    ///
    /// ```
    /// let r = http_net::Request::new("PURGE", "/cache/a");
    /// assert_eq!(r.method(), "PURGE");
    /// ```
    #[must_use]
    pub fn new(method: &str, target: &str) -> Self {
        let method_kind = Method::from_bytes(method.as_bytes());
        let mut error = None;
        if !is_token(method.as_bytes()) {
            error = Some(HttpError::InvalidMethod);
        } else if let Err(e) = check_target(method_kind, target.as_bytes()) {
            error = Some(e);
        }
        Self {
            method: match method_kind.as_str() {
                Some(s) => Cow::Borrowed(s),
                None => Cow::Owned(method.into()),
            },
            method_kind,
            target: target.into(),
            fields: Vec::new(),
            body: OutBody::Full(Cow::Borrowed(&[])),
            close: false,
            upgrade: false,
            has_host: false,
            error,
        }
    }

    /// A `GET` request.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Request::get("/").method(), "GET");
    /// ```
    #[must_use]
    pub fn get(target: &str) -> Self {
        Self::new("GET", target)
    }

    /// A `POST` request.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Request::post("/").method(), "POST");
    /// ```
    #[must_use]
    pub fn post(target: &str) -> Self {
        Self::new("POST", target)
    }

    /// Adds a header field, validated as for [`Response::header`]. A second
    /// `host` is refused with [`HttpError::InvalidHost`].
    ///
    /// # Examples
    ///
    /// ```
    /// let r = http_net::Request::get("/").header("host", "a").header("accept", "*/*");
    /// assert_eq!(r.header_value("accept"), Some(&b"*/*"[..]));
    /// ```
    #[must_use]
    pub fn header(mut self, name: &str, value: impl AsRef<[u8]>) -> Self {
        if self.error.is_none() {
            let value = value.as_ref();
            let is_host = name.eq_ignore_ascii_case("host");
            if is_host && (self.has_host || !crate::syntax::is_host_value(value)) {
                self.error = Some(HttpError::InvalidHost);
            } else if let Err(e) = push_field(&mut self.fields, name, value, REQUEST_RESERVED) {
                self.error = Some(e);
            } else {
                self.has_host |= is_host;
            }
        }
        self
    }

    /// Sets the whole body, sent with `content-length`.
    ///
    /// # Examples
    ///
    /// ```
    /// let r = http_net::Request::post("/").body(&b"x=1"[..]);
    /// assert_eq!(r.body_bytes(), Some(&b"x=1"[..]));
    /// ```
    #[must_use]
    pub fn body(mut self, body: impl Into<Cow<'static, [u8]>>) -> Self {
        self.body = OutBody::Full(body.into());
        self
    }

    /// Streams the body with chunked encoding through
    /// [`ClientConn::send_body`](crate::ClientConn::send_body) and
    /// [`ClientConn::end_body`](crate::ClientConn::end_body).
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Request::post("/").chunked().body_bytes(), None);
    /// ```
    #[must_use]
    pub fn chunked(mut self) -> Self {
        self.body = OutBody::Chunked;
        self
    }

    /// Streams a body of exactly `len` bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Request::post("/").content_length(4).body_bytes(), None);
    /// ```
    #[must_use]
    pub fn content_length(mut self, len: u64) -> Self {
        self.body = OutBody::Length(len);
        self
    }

    /// Asks the server to close the connection after its response.
    ///
    /// # Examples
    ///
    /// ```
    /// let _ = http_net::Request::get("/").header("host", "a").close();
    /// ```
    #[must_use]
    pub fn close(mut self) -> Self {
        self.close = true;
        self
    }

    /// Asks to switch the connection to `protocol` (writes
    /// `connection: upgrade` and `upgrade: <protocol>`). A `101` answer
    /// hands the connection over; see
    /// [`ClientEvent::Upgraded`](crate::ClientEvent::Upgraded).
    ///
    /// # Examples
    ///
    /// ```
    /// let r = http_net::Request::get("/rpc").header("host", "a").upgrade("websocket");
    /// assert_eq!(r.header_value("upgrade"), Some(&b"websocket"[..]));
    /// ```
    #[must_use]
    pub fn upgrade(mut self, protocol: &str) -> Self {
        if self.error.is_none() {
            if is_token(protocol.as_bytes()) {
                self.upgrade = true;
                self.fields
                    .extend_from_slice(b"connection: upgrade\r\nupgrade: ");
                self.fields.extend_from_slice(protocol.as_bytes());
                self.fields.extend_from_slice(b"\r\n");
            } else {
                self.error = Some(HttpError::InvalidHeaderValue);
            }
        }
        self
    }

    /// The method text.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Request::new("OPTIONS", "*").method(), "OPTIONS");
    /// ```
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// The request target.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Request::get("/a?b").target(), "/a?b");
    /// ```
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The full body, or `None` for a streamed one.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Request::get("/").body_bytes(), Some(&[][..]));
    /// ```
    #[must_use]
    pub fn body_bytes(&self) -> Option<&[u8]> {
        match &self.body {
            OutBody::Full(b) => Some(b),
            _ => None,
        }
    }

    /// The value of the first header named `name` added to this request.
    ///
    /// # Examples
    ///
    /// ```
    /// let r = http_net::Request::get("/").header("host", "a");
    /// assert_eq!(r.header_value("HOST"), Some(&b"a"[..]));
    /// ```
    #[must_use]
    pub fn header_value(&self, name: &str) -> Option<&[u8]> {
        field_value(&self.fields, name)
    }

    pub(crate) fn error(&self) -> Option<HttpError> {
        self.error
    }

    pub(crate) fn fields(&self) -> &[u8] {
        &self.fields
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("target", &self.target)
            .field("fields", &String::from_utf8_lossy(&self.fields))
            .field("body", &body_debug(&self.body))
            .field("error", &self.error)
            .finish()
    }
}

fn body_debug(body: &OutBody) -> String {
    match body {
        OutBody::Full(b) => format!("{} bytes", b.len()),
        OutBody::Length(n) => format!("streamed, {n} bytes"),
        OutBody::Chunked => "streamed, chunked".into(),
    }
}

/// Looks a header up in serialized `name: value\r\n` lines.
fn field_value<'a>(fields: &'a [u8], name: &str) -> Option<&'a [u8]> {
    fields
        .split(|&b| b == b'\n')
        .filter_map(|line| {
            let line = line.strip_suffix(b"\r")?;
            let colon = line.iter().position(|&b| b == b':')?;
            Some((&line[..colon], line.get(colon + 2..).unwrap_or(&[])))
        })
        .find(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
        .map(|(_, v)| v)
}

/// The canonical reason phrase for a status code (RFC 9110 section 15).
///
/// # Examples
///
/// ```
/// assert_eq!(http_net::reason_phrase(404), "Not Found");
/// assert_eq!(http_net::reason_phrase(299), "");
/// ```
#[must_use]
pub const fn reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_refuses_reserved_and_invalid_headers() {
        assert_eq!(
            Response::new(200)
                .header("Transfer-Encoding", "chunked")
                .error(),
            Some(HttpError::ReservedHeader)
        );
        assert_eq!(
            Response::new(200).header("bad name", "x").error(),
            Some(HttpError::InvalidHeaderName)
        );
        assert_eq!(
            Response::new(200).header("x", "a\r\nInjected: 1").error(),
            Some(HttpError::BareCr)
        );
        assert_eq!(
            Response::new(200).header("x", " padded").error(),
            Some(HttpError::InvalidHeaderValue)
        );
        // The first error sticks.
        let r = Response::new(200)
            .header("a b", "1")
            .header("connection", "close");
        assert_eq!(r.error(), Some(HttpError::InvalidHeaderName));
    }

    #[test]
    fn test_request_validates_method_target_and_host() {
        assert_eq!(
            Request::new("G T", "/").error(),
            Some(HttpError::InvalidMethod)
        );
        assert_eq!(
            Request::get("no-slash").error(),
            Some(HttpError::InvalidTarget)
        );
        assert_eq!(
            Request::get("/")
                .header("host", "a")
                .header("Host", "b")
                .error(),
            Some(HttpError::InvalidHost)
        );
        assert_eq!(
            Request::get("/").header("host", "a b").error(),
            Some(HttpError::InvalidHost)
        );
        assert!(Request::get("/").header("host", "a").has_host);
        assert_eq!(
            Request::get("/").upgrade("a b").error(),
            Some(HttpError::InvalidHeaderValue)
        );
    }

    #[test]
    fn test_field_lookup_and_debug() {
        let r = Response::switching_protocols("websocket").header("x", "");
        assert_eq!(r.header_value("connection"), Some(&b"upgrade"[..]));
        assert_eq!(r.header_value("x"), Some(&b""[..]));
        assert!(alloc::format!("{r:?}").contains("Response"));
        assert_eq!(
            Response::switching_protocols("a b").error(),
            Some(HttpError::InvalidHeaderValue)
        );
    }
}
