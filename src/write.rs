//! The allocation-free response writer (Tier 3): where serialized bytes go
//! ([`Output`]), a borrowed description of a response head
//! ([`ResponseHeadRef`]), and the [`ServerConn`] methods that write into any
//! `Output`.
//!
//! [`ServerConn::respond`] and this writer share one code path, so a head
//! written here is byte for byte the head `respond` would write for the same
//! response, with the same validation and framing rules.

use alloc::vec::Vec;

use crate::{date::HttpDate, error::HttpError, message::Response, server::ServerConn};

/// Where serialized bytes go.
///
/// `Vec<u8>` is the default; a driver can write straight into its own buffer
/// instead (a zeroizing buffer that wipes on drop, a fixed slab in a passport,
/// a socket's send queue). [`put`](Self::put) cannot fail: an `Output` with a
/// fixed capacity must grow, or mark itself poisoned and have its owner close
/// the connection, because a half-written response cannot be recovered
/// anyway. [`reserve`](Self::reserve) is a hint and may be ignored.
///
/// # Examples
///
/// ```
/// use http_net::Output;
///
/// /// Counts bytes without keeping them.
/// struct Meter(usize);
///
/// impl Output for Meter {
///     fn put(&mut self, bytes: &[u8]) {
///         self.0 += bytes.len();
///     }
/// }
///
/// let mut m = Meter(0);
/// m.put(b"HTTP/1.1 ");
/// m.put(b"204 No Content\r\n");
/// assert_eq!(m.0, 25);
/// ```
pub trait Output {
    /// Appends `bytes`.
    fn put(&mut self, bytes: &[u8]);

    /// Says that about `additional` more bytes are coming; an
    /// implementation may grow once instead of several times. Optional.
    fn reserve(&mut self, additional: usize) {
        let _ = additional;
    }
}

impl Output for Vec<u8> {
    #[inline]
    fn put(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }

    #[inline]
    fn reserve(&mut self, additional: usize) {
        Vec::reserve(self, additional);
    }
}

impl<O: Output + ?Sized> Output for &mut O {
    #[inline]
    fn put(&mut self, bytes: &[u8]) {
        (**self).put(bytes);
    }

    #[inline]
    fn reserve(&mut self, additional: usize) {
        (**self).reserve(additional);
    }
}

/// How the body of a response written with
/// [`ServerConn::write_head`] is supplied.
///
/// # Examples
///
/// ```
/// use http_net::OutgoingBody;
///
/// let body = b"hello";
/// let full = OutgoingBody::Full(body.len() as u64);
/// assert_ne!(full, OutgoingBody::Chunked);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OutgoingBody {
    /// No body: `content-length: 0` (or nothing, for a status that never
    /// carries one).
    Empty,
    /// A body of exactly this many bytes that the caller writes itself,
    /// right after the head (for example with one vectored write of head and
    /// body); sent with `content-length`. The response is complete once the
    /// caller has written them.
    Full(u64),
    /// A streamed body of exactly this many bytes, sent with
    /// `content-length` through `send_body` and `end_body`.
    Length(u64),
    /// A streamed body with chunked encoding (close-delimited to an
    /// HTTP/1.0 client), through `send_body` and `end_body`.
    Chunked,
}

/// What the caller must do after [`ServerConn::write_head`].
///
/// # Examples
///
/// ```
/// use http_net::BodyPlan;
///
/// let plan = BodyPlan::Raw;
/// assert!(matches!(plan, BodyPlan::Raw));
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BodyPlan {
    /// The response is complete: there is no body to send (an empty body, a
    /// `HEAD` request, a status without a body, or an upgrade).
    None,
    /// Write the [`OutgoingBody::Full`] bytes as they are, right after the
    /// head; the connection already counts the response as complete.
    Raw,
    /// Stream the body with [`ServerConn::send_body`] (or
    /// [`send_body_into`](ServerConn::send_body_into)) and end it with
    /// [`ServerConn::end_body`] (or [`end_body_into`](ServerConn::end_body_into)).
    Stream,
}

/// A response head described with borrowed data, for
/// [`ServerConn::write_head`]: nothing is copied into an owned builder and
/// nothing is allocated.
///
/// The fields are validated when the head is written, with the same rules as
/// [`Response::header`]: token names, no framing or connection fields (the
/// connection writes those), no control bytes or surrounding whitespace in
/// values. A `date` field among them stops a date passed to `write_head`
/// from being added. `upgrade` names the protocol of a `101 Switching
/// Protocols`, as [`Response::switching_protocols`] does.
///
/// The struct is built with a literal, so its fields are public and it is
/// not `#[non_exhaustive]`; use [`ResponseHeadRef::new`] to start from the
/// defaults.
///
/// # Examples
///
/// ```
/// use http_net::{OutgoingBody, ResponseHeadRef};
///
/// let fields: &[(&str, &[u8])] = &[("content-type", b"text/plain")];
/// let head = ResponseHeadRef {
///     status: 200,
///     fields,
///     body: OutgoingBody::Full(5),
///     close: false,
///     upgrade: None,
/// };
/// assert_eq!(head, ResponseHeadRef::new(200, fields, OutgoingBody::Full(5)));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResponseHeadRef<'a> {
    /// The status code (`100..=599`; among the 1xx codes only `101`).
    pub status: u16,
    /// The fields, in order, as `(name, value)`.
    pub fields: &'a [(&'a str, &'a [u8])],
    /// How the body is supplied.
    pub body: OutgoingBody,
    /// Close the connection after this response.
    pub close: bool,
    /// The protocol a `101` switches to.
    pub upgrade: Option<&'a str>,
}

impl<'a> ResponseHeadRef<'a> {
    /// A head with `status`, `fields`, and `body`; no close, no upgrade.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{OutgoingBody, ResponseHeadRef};
    ///
    /// let head = ResponseHeadRef::new(204, &[], OutgoingBody::Empty);
    /// assert!(!head.close);
    /// ```
    #[must_use]
    pub const fn new(status: u16, fields: &'a [(&'a str, &'a [u8])], body: OutgoingBody) -> Self {
        Self {
            status,
            fields,
            body,
            close: false,
            upgrade: None,
        }
    }
}

impl ServerConn {
    /// Writes a response head described by borrowed data into any
    /// [`Output`] and says how to send the body. Nothing is allocated; the
    /// validation, framing fields, `connection` handling, and state changes
    /// are those of [`respond`](Self::respond), and the bytes are the same
    /// as `respond` would write for the equivalent [`Response`]. `date`, when
    /// given and the fields set no `date`, is written as `date: <date>`.
    ///
    /// After [`BodyPlan::Raw`] write the [`OutgoingBody::Full`] bytes
    /// yourself (for example with one vectored write of head and body); the
    /// response then counts as complete. After [`BodyPlan::Stream`] use
    /// [`send_body_into`](Self::send_body_into) and
    /// [`end_body_into`](Self::end_body_into) (or the `Vec` versions).
    ///
    /// # Errors
    ///
    /// As [`respond`](Self::respond), with the field errors of
    /// [`Response::header`] for `fields` and those of
    /// [`Response::switching_protocols`] for `upgrade`
    /// ([`HttpError::InvalidHeaderValue`] when it is not a protocol token,
    /// [`HttpError::UpgradeNotOffered`] for `h2c` or a protocol the request
    /// did not offer). An `upgrade` on a status other than `101`, or a
    /// `101` without one, is [`HttpError::InvalidState`]. Nothing is written
    /// on error.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{BodyPlan, OutgoingBody, ResponseHeadRef, ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"GET /app.js HTTP/1.1\r\nHost: a\r\n\r\n");
    /// while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
    ///
    /// let body: &[u8] = b"console.log(1)";
    /// let fields: &[(&str, &[u8])] = &[("content-type", b"text/javascript")];
    /// let head = ResponseHeadRef::new(200, fields, OutgoingBody::Full(body.len() as u64));
    /// let mut out = Vec::with_capacity(256);
    /// let plan = conn.write_head(&head, None, &mut out)?;
    /// assert_eq!(plan, BodyPlan::Raw);
    /// assert_eq!(out, b"HTTP/1.1 200 OK\r\ncontent-length: 14\r\ncontent-type: text/javascript\r\n\r\n");
    /// out.extend_from_slice(body); // or one vectored write of both
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    pub fn write_head<O: Output + ?Sized>(
        &mut self,
        head: &ResponseHeadRef<'_>,
        date: Option<&HttpDate>,
        out: &mut O,
    ) -> Result<BodyPlan, HttpError> {
        self.start_response(head, date.map(HttpDate::as_bytes).map(|d| &d[..]), out)
    }

    /// [`respond`](Self::respond) into any [`Output`], with an optional
    /// `date` as in [`respond_with_date`](Self::respond_with_date). A full
    /// body is written after the head; a streamed one continues with
    /// [`send_body_into`](Self::send_body_into) and
    /// [`end_body_into`](Self::end_body_into).
    ///
    /// # Errors
    ///
    /// As [`respond`](Self::respond).
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{Output, Response, ServerConn, ServerEvent};
    ///
    /// /// A bounded output that refuses to grow past its capacity.
    /// struct Slab { buf: [u8; 512], len: usize, overflow: bool }
    ///
    /// impl Output for Slab {
    ///     fn put(&mut self, bytes: &[u8]) {
    ///         match self.buf.get_mut(self.len..self.len + bytes.len()) {
    ///             Some(dst) => {
    ///                 dst.copy_from_slice(bytes);
    ///                 self.len += bytes.len();
    ///             }
    ///             None => self.overflow = true, // the owner closes the connection
    ///         }
    ///     }
    /// }
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    /// while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
    /// let mut slab = Slab { buf: [0; 512], len: 0, overflow: false };
    /// conn.respond_into(&Response::text(200, "hi"), None, &mut slab)?;
    /// assert!(!slab.overflow);
    /// assert!(slab.buf[..slab.len].ends_with(b"\r\n\r\nhi"));
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    pub fn respond_into<O: Output + ?Sized>(
        &mut self,
        response: &Response,
        date: Option<&HttpDate>,
        out: &mut O,
    ) -> Result<(), HttpError> {
        self.respond_dated(response, date.map(|d| &d.as_bytes()[..]), out)
    }

    /// [`send_body`](Self::send_body) into any [`Output`].
    ///
    /// # Errors
    ///
    /// As [`send_body`](Self::send_body).
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{BodyPlan, OutgoingBody, ResponseHeadRef, ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"GET /log HTTP/1.1\r\nHost: a\r\n\r\n");
    /// while !matches!(conn.poll().unwrap(), ServerEvent::RequestEnd) {}
    /// let mut out = Vec::new();
    /// let head = ResponseHeadRef::new(200, &[], OutgoingBody::Chunked);
    /// assert_eq!(conn.write_head(&head, None, &mut out)?, BodyPlan::Stream);
    /// conn.send_body_into(b"line\n", &mut out)?;
    /// conn.end_body_into(&[], &mut out)?;
    /// assert!(out.ends_with(b"5\r\nline\n\r\n0\r\n\r\n"));
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    pub fn send_body_into<O: Output + ?Sized>(
        &mut self,
        data: &[u8],
        out: &mut O,
    ) -> Result<(), HttpError> {
        self.stream_body(data, out)
    }

    /// Ends a streamed body into any [`Output`], with `trailers` (empty for
    /// none): [`end_body`](Self::end_body) and
    /// [`end_body_with_trailers`](Self::end_body_with_trailers) in one.
    ///
    /// # Errors
    ///
    /// As [`end_body_with_trailers`](Self::end_body_with_trailers).
    ///
    /// # Examples
    ///
    /// See [`send_body_into`](Self::send_body_into).
    pub fn end_body_into<O: Output + ?Sized>(
        &mut self,
        trailers: &[(&str, &[u8])],
        out: &mut O,
    ) -> Result<(), HttpError> {
        self.finish_body(trailers, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::{HttpError, ServerEvent};

    fn conn_after(request: &[u8]) -> ServerConn {
        let mut conn = ServerConn::new();
        let _ = conn.feed(request);
        loop {
            match conn.poll() {
                Ok(ServerEvent::RequestEnd) | Err(_) => return conn,
                Ok(_) => {}
            }
        }
    }

    const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";

    #[test]
    fn test_write_head_full_body_plans_raw_and_completes() {
        let mut conn = conn_after(GET);
        let mut out = Vec::new();
        let head = ResponseHeadRef::new(200, &[("x", b"1")], OutgoingBody::Full(3));
        assert_eq!(conn.write_head(&head, None, &mut out), Ok(BodyPlan::Raw));
        assert_eq!(out, b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\nx: 1\r\n\r\n");
        assert_eq!(conn.requests_served(), 1);
        assert!(matches!(conn.poll(), Ok(ServerEvent::NeedInput)));
    }

    #[test]
    fn test_write_head_head_request_and_bodiless_plan_none() {
        let mut conn = conn_after(b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n");
        let mut out = Vec::new();
        let head = ResponseHeadRef::new(200, &[], OutgoingBody::Full(9));
        assert_eq!(conn.write_head(&head, None, &mut out), Ok(BodyPlan::None));
        assert!(out.ends_with(b"content-length: 9\r\n\r\n"));

        let mut conn = conn_after(GET);
        let mut out = Vec::new();
        let head = ResponseHeadRef::new(204, &[], OutgoingBody::Empty);
        assert_eq!(conn.write_head(&head, None, &mut out), Ok(BodyPlan::None));
        assert_eq!(out, b"HTTP/1.1 204 No Content\r\n\r\n");
        let mut conn = conn_after(GET);
        let head = ResponseHeadRef::new(304, &[], OutgoingBody::Full(1));
        assert_eq!(
            conn.write_head(&head, None, &mut Vec::new()),
            Err(HttpError::BodyNotAllowed)
        );
    }

    #[test]
    fn test_write_head_refuses_bad_fields_and_writes_nothing() {
        for (fields, err) in [
            (
                &[("content-length", &b"5"[..])][..],
                HttpError::ReservedHeader,
            ),
            (&[("bad name", &b"x"[..])][..], HttpError::InvalidHeaderName),
            (&[("x", &b"a\r\nb"[..])][..], HttpError::BareCr),
            (&[("x", &b" pad"[..])][..], HttpError::InvalidHeaderValue),
            (&[("te", &b"trailers"[..])][..], HttpError::ReservedHeader),
        ] {
            let mut conn = conn_after(GET);
            let mut out = Vec::new();
            let head = ResponseHeadRef::new(200, fields, OutgoingBody::Empty);
            assert_eq!(
                conn.write_head(&head, None, &mut out),
                Err(err),
                "{fields:?}"
            );
            assert!(out.is_empty());
            // Nothing changed: a normal response still goes out.
            conn.respond(&Response::new(204), &mut out).unwrap();
        }
    }

    #[test]
    fn test_write_head_upgrade_rules() {
        let upgrade_req =
            b"GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n";
        let mut conn = conn_after(upgrade_req);
        let mut out = Vec::new();
        let mut head = ResponseHeadRef::new(101, &[], OutgoingBody::Empty);
        assert!(matches!(
            conn.write_head(&head, None, &mut out),
            Err(HttpError::InvalidState(_))
        ));
        head.upgrade = Some("irc");
        assert_eq!(
            conn.write_head(&head, None, &mut out),
            Err(HttpError::UpgradeNotOffered)
        );
        head.upgrade = Some("h2c");
        assert_eq!(
            conn.write_head(&head, None, &mut out),
            Err(HttpError::UpgradeNotOffered)
        );
        head.upgrade = Some("a b");
        assert_eq!(
            conn.write_head(&head, None, &mut out),
            Err(HttpError::InvalidHeaderValue)
        );
        let mut on_200 = ResponseHeadRef::new(200, &[], OutgoingBody::Empty);
        on_200.upgrade = Some("websocket");
        assert!(matches!(
            conn.write_head(&on_200, None, &mut out),
            Err(HttpError::InvalidState(_))
        ));
        assert!(out.is_empty());
        head.upgrade = Some("WebSocket");
        assert_eq!(conn.write_head(&head, None, &mut out), Ok(BodyPlan::None));
        assert_eq!(
            out,
            b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: WebSocket\r\n\r\n"
        );
        assert!(conn.is_upgraded());
    }

    #[test]
    fn test_write_head_date_unless_set() {
        let date = HttpDate::from_unix_seconds(0);
        let mut conn = conn_after(GET);
        let mut out = Vec::new();
        let head = ResponseHeadRef::new(204, &[], OutgoingBody::Empty);
        assert_eq!(
            conn.write_head(&head, Some(&date), &mut out),
            Ok(BodyPlan::None)
        );
        assert!(
            out.windows(35)
                .any(|w| w == b"date: Thu, 01 Jan 1970 00:00:00 GMT")
        );

        let mut conn = conn_after(GET);
        let mut out = Vec::new();
        let fields: &[(&str, &[u8])] = &[("Date", b"x")];
        let head = ResponseHeadRef::new(204, fields, OutgoingBody::Empty);
        assert_eq!(
            conn.write_head(&head, Some(&date), &mut out),
            Ok(BodyPlan::None)
        );
        assert!(!out.windows(4).any(|w| w == b"1970"));
    }

    #[test]
    fn test_streaming_into_output_and_state_errors() {
        let mut conn = conn_after(GET);
        let mut out = Vec::new();
        assert!(matches!(
            conn.send_body_into(b"x", &mut out),
            Err(HttpError::InvalidState(_))
        ));
        let head = ResponseHeadRef::new(200, &[], OutgoingBody::Length(3));
        assert_eq!(conn.write_head(&head, None, &mut out), Ok(BodyPlan::Stream));
        assert!(matches!(
            conn.write_head(&head, None, &mut out),
            Err(HttpError::InvalidState(_))
        ));
        conn.send_body_into(b"ab", &mut out).unwrap();
        assert_eq!(
            conn.end_body_into(&[], &mut out),
            Err(HttpError::BodyLengthMismatch)
        );
        conn.send_body_into(b"c", &mut out).unwrap();
        assert_eq!(
            conn.end_body_into(&[("x", b"1")], &mut out),
            Err(HttpError::TrailerNotAllowed)
        );
        conn.end_body_into(&[], &mut out).unwrap();
        assert!(out.ends_with(b"\r\n\r\nabc"));
    }

    #[test]
    fn test_output_by_reference_and_reserve_hint() {
        let mut v = vec![1u8];
        {
            let mut r: &mut Vec<u8> = &mut v;
            Output::reserve(&mut r, 64);
            r.put(b"23");
        }
        assert_eq!(v, b"\x0123");
        assert!(v.capacity() >= 3);
    }
}
