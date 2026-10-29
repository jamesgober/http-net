//! Tier 3: the bytes and offsets behind a parsed head, copying a head out
//! (the zero-copy passport path), owned heads, and the stateless parsers.
//!
//! A head is its bytes plus `u32` spans into them, so it can be moved or
//! copied without re-parsing: [`RequestHead::copy_into`] copies the bytes
//! and spans into a caller's reused vectors and hands back the interpreted
//! [`HeadFacts`], and [`OwnedRequestHead::from_parts`] rebuilds a view from
//! them after checking that their structure is intact. The stateless
//! parsers run the connections' own scanner and interpretation over a
//! caller's slice, with the field records written into a caller's array:
//! they allocate nothing.

use alloc::vec::Vec;
use core::fmt;

use crate::{
    error::HttpError,
    head::{
        Asked, Field, FieldSpan, HeadKind, LineScan, RequestHead, RequestInfo, ResponseHead,
        ResponseInfo, Scan, SliceSink, Span, check_target, interpret_request, interpret_response,
        parse_version,
    },
    limits::Limits,
    method::Method,
    scan::{check_field_value, find_byte, is_ows, is_token},
};

/// The bytes of a head and the spans of its parts, all relative to
/// [`bytes`](Self::bytes): what [`RequestHead::raw`] and
/// [`ResponseHead::raw`] return.
///
/// The bytes run from the first byte the connection kept for the message
/// (any empty lines a client sent before the request line, which RFC 9112
/// section 2.2 lets a server skip, are included) to the end of the blank
/// line that ends the head. Spans for parts a head does not have are empty:
/// `status` on a request, `method` and `target` on a response.
///
/// `Debug` shows lengths and spans only, never the bytes, so a raw head in
/// a log cannot leak a credential.
///
/// # Examples
///
/// ```
/// use http_net::{ServerConn, ServerEvent};
///
/// let mut conn = ServerConn::new();
/// let _ = conn.feed(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nbody bytes are not part of it");
/// let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
/// let raw = req.raw();
/// assert_eq!(raw.bytes(), b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
/// assert_eq!(raw.method().get(raw.bytes()), b"GET");
/// assert_eq!(raw.target().get(raw.bytes()), b"/a");
/// assert_eq!(raw.version().get(raw.bytes()), b"HTTP/1.1");
/// assert!(raw.status().is_empty());
/// assert_eq!(raw.fields().len(), 1);
/// ```
#[derive(Clone, Copy)]
pub struct RawHead<'a> {
    bytes: &'a [u8],
    start_line: Span,
    method: Span,
    target: Span,
    version: Span,
    status: Span,
    fields: &'a [FieldSpan],
}

impl<'a> RawHead<'a> {
    /// The head bytes, from its first byte to the end of the blank line.
    ///
    /// # Examples
    ///
    /// See [`RawHead`].
    #[must_use]
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The request line or status line, without its CRLF.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ServerConn, ServerEvent};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// let raw = req.raw();
    /// assert_eq!(raw.start_line().get(raw.bytes()), b"GET / HTTP/1.1");
    /// ```
    #[must_use]
    pub fn start_line(&self) -> Span {
        self.start_line
    }

    /// The method (requests; empty for a response).
    ///
    /// # Examples
    ///
    /// See [`RawHead`].
    #[must_use]
    pub fn method(&self) -> Span {
        self.method
    }

    /// The request target (requests; empty for a response).
    ///
    /// # Examples
    ///
    /// See [`RawHead`].
    #[must_use]
    pub fn target(&self) -> Span {
        self.target
    }

    /// The protocol version as received (`HTTP/1.0`, `HTTP/1.1`, or another
    /// `HTTP/1.x`, which `version()` reports as `Http11`).
    ///
    /// # Examples
    ///
    /// See [`RawHead`].
    #[must_use]
    pub fn version(&self) -> Span {
        self.version
    }

    /// The three status digits (responses; empty for a request).
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ClientConn, ClientEvent, Request};
    /// # let mut conn = ClientConn::new();
    /// # conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new()).unwrap();
    /// # let _ = conn.feed(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    /// # let ClientEvent::Response(resp) = conn.poll().unwrap() else { panic!() };
    /// let raw = resp.raw();
    /// assert_eq!(raw.status().get(raw.bytes()), b"404");
    /// assert!(raw.method().is_empty());
    /// ```
    #[must_use]
    pub fn status(&self) -> Span {
        self.status
    }

    /// Every field line's name and value spans, in arrival order.
    ///
    /// # Examples
    ///
    /// See [`FieldSpan`].
    #[must_use]
    pub fn fields(&self) -> &'a [FieldSpan] {
        self.fields
    }
}

impl fmt::Debug for RawHead<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawHead")
            .field("len", &self.bytes.len())
            .field("start_line", &self.start_line)
            .field("fields", &self.fields.len())
            .finish_non_exhaustive()
    }
}

/// The interpreted facts of a request head (method, version, framing,
/// keep-alive, upgrade and expectation flags, target form, and the spans of
/// the host and of the target's parts), so a view can be rebuilt from
/// copied bytes without parsing them again. Returned by
/// [`RequestHead::copy_into`], taken by [`OwnedRequestHead::from_parts`].
///
/// # Examples
///
/// ```
/// use http_net::{OwnedRequestHead, ServerConn, ServerEvent};
///
/// let mut conn = ServerConn::new();
/// let _ = conn.feed(b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n");
/// let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
/// let (mut bytes, mut fields) = (Vec::new(), Vec::new());
/// let facts = req.copy_into(&mut bytes, &mut fields)?;
/// let owned = OwnedRequestHead::from_parts(bytes, fields, facts)?;
/// assert_eq!(owned.view().path(), "/x");
/// # Ok::<(), http_net::HttpError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadFacts {
    info: RequestInfo,
}

/// The length of a validated head inside `bytes`: the line that holds the
/// last field value (or the start line) ends at the next LF, and the blank
/// line's CRLF follows it.
fn head_len(bytes: &[u8], start_line: Span, fields: &[Field]) -> usize {
    let after = fields.last().map_or(start_line.end, |f| f.value.end) as usize;
    match bytes.get(after..).and_then(|rest| find_byte(b'\n', rest)) {
        Some(lf) => (after + lf + 1 + 2).min(bytes.len()),
        None => bytes.len(),
    }
}

impl<'a> RequestHead<'a> {
    /// The head's bytes and the spans of its parts, for code that works on
    /// offsets (passports, proxies, other engines).
    ///
    /// # Examples
    ///
    /// See [`RawHead`].
    #[must_use]
    pub fn raw(&self) -> RawHead<'a> {
        let (head, fields, info) = self.parts();
        let sl = info.start_line;
        let bytes = head.get(..head_len(head, sl, fields)).unwrap_or(head);
        RawHead {
            bytes,
            start_line: sl,
            method: info.method_span,
            target: info.target,
            version: Span {
                start: info.target.end.saturating_add(1),
                end: sl.end,
            },
            status: Span::default(),
            fields,
        }
    }

    /// Copies the head bytes (one copy) and field spans into `bytes` and
    /// `fields`, which are cleared first, and returns the interpreted facts:
    /// with them, [`OwnedRequestHead::from_parts`] (or a passport) rebuilds a
    /// view without parsing again. Once the vectors have grown to the
    /// largest head seen, the copy allocates nothing.
    ///
    /// # Errors
    ///
    /// None today: a view always has a current head. The `Result` leaves
    /// room for a head that cannot be copied without reading more input.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{OwnedRequestHead, ServerConn, ServerEvent};
    ///
    /// // A passport's buffers, reused for every request.
    /// let (mut bytes, mut fields) = (Vec::with_capacity(4096), Vec::with_capacity(64));
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"POST /api HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhi");
    /// let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// let facts = req.copy_into(&mut bytes, &mut fields)?;
    /// assert_eq!(bytes, b"POST /api HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\n");
    /// let owned = OwnedRequestHead::from_parts(bytes, fields, facts)?;
    /// assert_eq!(owned.view().content_length(), Some(2));
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    pub fn copy_into(
        &self,
        bytes: &mut Vec<u8>,
        fields: &mut Vec<FieldSpan>,
    ) -> Result<HeadFacts, HttpError> {
        let raw = self.raw();
        bytes.clear();
        bytes.extend_from_slice(raw.bytes);
        fields.clear();
        fields.extend_from_slice(raw.fields);
        Ok(HeadFacts {
            info: *self.parts().2,
        })
    }

    /// An owned copy of the head, for keeping it across body events or
    /// sending it to another thread.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"GET /keep HTTP/1.1\r\nHost: a\r\n\r\n");
    /// let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// let owned = req.to_owned();
    /// drop(conn);
    /// assert_eq!(owned.view().path(), "/keep");
    /// ```
    #[must_use]
    #[allow(clippy::wrong_self_convention)]
    pub fn to_owned(&self) -> OwnedRequestHead {
        let raw = self.raw();
        OwnedRequestHead {
            bytes: raw.bytes.to_vec(),
            fields: raw.fields.to_vec(),
            facts: HeadFacts {
                info: *self.parts().2,
            },
        }
    }
}

impl<'a> ResponseHead<'a> {
    /// The head's bytes and the spans of its parts (see [`RawHead`]).
    ///
    /// # Examples
    ///
    /// See [`RawHead::status`].
    #[must_use]
    pub fn raw(&self) -> RawHead<'a> {
        let (head, fields, info) = self.parts();
        let sl = info.start_line;
        let bytes = head.get(..head_len(head, sl, fields)).unwrap_or(head);
        RawHead {
            bytes,
            start_line: sl,
            method: Span::default(),
            target: Span::default(),
            version: Span {
                start: sl.start,
                end: sl.start.saturating_add(8).min(sl.end),
            },
            status: Span {
                start: sl.start.saturating_add(9).min(sl.end),
                end: sl.start.saturating_add(12).min(sl.end),
            },
            fields,
        }
    }
}

/// A request head that owns its bytes and spans: from
/// [`RequestHead::to_owned`], or rebuilt from a passport's parts with
/// [`from_parts`](Self::from_parts). `Debug` shows the head the way
/// [`RequestHead`] does, credential values redacted.
///
/// # Examples
///
/// See [`RequestHead::to_owned`] and [`HeadFacts`].
#[derive(Clone, PartialEq, Eq)]
pub struct OwnedRequestHead {
    bytes: Vec<u8>,
    fields: Vec<FieldSpan>,
    facts: HeadFacts,
}

impl OwnedRequestHead {
    /// A view of the owned head, with every accessor of a borrowed one.
    ///
    /// # Examples
    ///
    /// See [`RequestHead::to_owned`].
    #[must_use]
    pub fn view(&self) -> RequestHead<'_> {
        RequestHead::new(&self.bytes, &self.fields, &self.facts.info)
    }

    /// Rebuilds an owned head from copied parts ([`RequestHead::copy_into`]),
    /// checking first that they still describe one head: every span lies
    /// inside `bytes`, the start line and every field line have the
    /// structure the parser accepted (method, target, and version where the
    /// facts say, each field name a token followed by a colon, each value
    /// without control bytes or surrounding whitespace, the lines in order
    /// and back to back, the blank line last), and the host and target
    /// spans in the facts point where they should. A passport whose
    /// structure was changed is refused, never read. The check is
    /// structural, not an integrity check: a change that keeps every rule (a
    /// different target, `Host`, or field value of valid bytes) is accepted,
    /// so a passport that crosses a trust boundary needs its own MAC.
    ///
    /// The framing facts themselves (body length, keep-alive) are taken as
    /// given: they come from the same trusted copy, and recomputing them
    /// would be the parse this is meant to avoid.
    ///
    /// # Errors
    ///
    /// [`HttpError::InvalidState`], naming the first rule that failed.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{HttpError, OwnedRequestHead, ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    /// let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// let (mut bytes, mut fields) = (Vec::new(), Vec::new());
    /// let facts = req.copy_into(&mut bytes, &mut fields)?;
    /// bytes[16] = b' '; // the first field name now starts with a space
    /// assert!(matches!(
    ///     OwnedRequestHead::from_parts(bytes, fields, facts),
    ///     Err(HttpError::InvalidState(_))
    /// ));
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    pub fn from_parts(
        bytes: Vec<u8>,
        fields: Vec<FieldSpan>,
        facts: HeadFacts,
    ) -> Result<Self, HttpError> {
        validate(&bytes, &fields, &facts.info).map_err(HttpError::InvalidState)?;
        Ok(Self {
            bytes,
            fields,
            facts,
        })
    }

    /// Gives the parts back, so a passport pool can reuse the vectors for
    /// the next head without allocating.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"GET /a HTTP/1.1\r\nHost: a\r\n\r\n");
    /// let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// let (mut bytes, mut fields, _facts) = req.to_owned().into_parts();
    /// let capacity = bytes.capacity();
    /// bytes.clear();
    /// fields.clear();
    /// assert_eq!(bytes.capacity(), capacity);
    /// ```
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, Vec<FieldSpan>, HeadFacts) {
        (self.bytes, self.fields, self.facts)
    }
}

impl fmt::Debug for OwnedRequestHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.view(), f)
    }
}

/// The checks behind [`OwnedRequestHead::from_parts`].
fn validate(bytes: &[u8], fields: &[Field], info: &RequestInfo) -> Result<(), &'static str> {
    let len = bytes.len();
    let sl = info.start_line;
    if !sl.fits(len) || sl.is_empty() {
        return Err("the start line span is outside the head");
    }
    // Only empty lines (RFC 9112 section 2.2) may come before the start line.
    let before = Span {
        start: 0,
        end: sl.start,
    }
    .get(bytes);
    if before.len() % 2 != 0 || !before.chunks(2).all(|c| c == b"\r\n") {
        return Err("bytes before the start line are not empty lines");
    }
    if bytes.get(sl.end as usize..sl.end as usize + 2) != Some(b"\r\n") {
        return Err("the start line does not end in CRLF");
    }
    // method SP target SP version
    let m = info.method_span;
    let t = info.target;
    if m.start != sl.start || m.is_empty() || !m.fits(len) {
        return Err("the method span does not start the start line");
    }
    if !is_token(m.get(bytes)) || Method::from_bytes(m.get(bytes)) != info.method {
        return Err("the method bytes do not match the facts");
    }
    if t.start != m.end + 1
        || t.is_empty()
        || t.end >= sl.end
        || bytes.get(m.end as usize) != Some(&b' ')
    {
        return Err("the target span is not after the method");
    }
    if bytes.get(t.end as usize) != Some(&b' ') {
        return Err("the target is not followed by a space");
    }
    if check_target(info.method, t.get(bytes)).is_err() {
        return Err("the target bytes are not a valid target for the method");
    }
    let version = Span {
        start: t.end + 1,
        end: sl.end,
    };
    if parse_version(version.get(bytes)) != Ok(info.version) {
        return Err("the version bytes do not match the facts");
    }
    let inside_target = |s: Span| s.start >= t.start && s.end <= t.end && s.start <= s.end;
    if !inside_target(info.origin) {
        return Err("the origin span is outside the target");
    }
    if info.authority.is_some_and(|a| !inside_target(a)) {
        return Err("the authority span is outside the target");
    }
    // Field lines, back to back after the start line.
    let mut pos = sl.end as usize + 2;
    for field in fields {
        let (name, value) = (field.name, field.value);
        if name.start as usize != pos || name.is_empty() || !name.fits(len) {
            return Err("a field line does not start where the previous line ended");
        }
        if !is_token(name.get(bytes)) || bytes.get(name.end as usize) != Some(&b':') {
            return Err("a field name is not a token followed by a colon");
        }
        if !value.fits(len) || value.start < name.end + 1 {
            return Err("a field value span is outside its line");
        }
        let lead = Span {
            start: name.end + 1,
            end: value.start,
        };
        if !lead.get(bytes).iter().all(|&b| is_ows(b)) {
            return Err("bytes between a colon and its value are not whitespace");
        }
        let v = value.get(bytes);
        if v.first().is_some_and(|&b| is_ows(b)) || v.last().is_some_and(|&b| is_ows(b)) {
            return Err("a field value has surrounding whitespace");
        }
        if check_field_value(v).is_err() {
            return Err("a field value holds a byte a field may not");
        }
        let mut end = value.end as usize;
        while bytes.get(end).is_some_and(|&b| is_ows(b)) {
            end += 1;
        }
        if bytes.get(end..end + 2) != Some(b"\r\n") {
            return Err("a field line does not end in CRLF after its value");
        }
        pos = end + 2;
    }
    if pos + 2 != len || bytes.get(pos..) != Some(b"\r\n") {
        return Err("the head does not end with the blank line");
    }
    if let Some(host) = info.host {
        let is_host_value = fields
            .iter()
            .any(|f| f.value == host && f.name.get(bytes).eq_ignore_ascii_case(b"host"));
        if !is_host_value {
            return Err("the host span is not the value of a Host field");
        }
    }
    Ok(())
}

/// The result of a stateless parse: a complete head and how many input
/// bytes it took, or `Partial` when the input ends before the head does.
///
/// # Examples
///
/// ```
/// use http_net::{FieldSpan, Limits, Parsed, parse_request_head};
///
/// let mut fields = [FieldSpan::default(); 16];
/// let parsed = parse_request_head(b"GET / HTTP/1.1\r\nHo", &Limits::new(), &mut fields)?;
/// assert!(matches!(parsed, Parsed::Partial));
/// # Ok::<(), http_net::HttpError>(())
/// ```
#[non_exhaustive]
#[derive(Debug)]
pub enum Parsed<T> {
    /// A whole head: `len` bytes of the input, any leading empty lines
    /// included; the body (if any) starts there.
    Complete {
        /// The parsed head.
        head: T,
        /// The bytes of input the head took.
        len: usize,
    },
    /// The input ends before the head does: call again with more input.
    Partial,
}

/// A request head from [`parse_request_head`], borrowing the input and the
/// caller's field array.
///
/// # Examples
///
/// See [`parse_request_head`].
#[derive(Clone, Copy)]
pub struct ParsedRequest<'a> {
    bytes: &'a [u8],
    fields: &'a [FieldSpan],
    info: RequestInfo,
}

impl ParsedRequest<'_> {
    /// The usual view of the head.
    ///
    /// # Examples
    ///
    /// See [`parse_request_head`].
    #[must_use]
    pub fn view(&self) -> RequestHead<'_> {
        RequestHead::new(self.bytes, self.fields, &self.info)
    }

    /// The interpreted facts, as [`RequestHead::copy_into`] returns them.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{FieldSpan, Limits, Parsed, parse_request_head};
    ///
    /// let mut fields = [FieldSpan::default(); 4];
    /// let Parsed::Complete { head, .. } = parse_request_head(b"GET / HTTP/1.0\r\n\r\n", &Limits::new(), &mut fields)? else { panic!() };
    /// let _facts = head.facts();
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    #[must_use]
    pub fn facts(&self) -> HeadFacts {
        HeadFacts { info: self.info }
    }
}

impl fmt::Debug for ParsedRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.view(), f)
    }
}

/// A response head from [`parse_response_head`].
///
/// # Examples
///
/// See [`parse_response_head`].
#[derive(Clone, Copy)]
pub struct ParsedResponse<'a> {
    bytes: &'a [u8],
    fields: &'a [FieldSpan],
    info: ResponseInfo,
}

impl ParsedResponse<'_> {
    /// The usual view of the head.
    ///
    /// # Examples
    ///
    /// See [`parse_response_head`].
    #[must_use]
    pub fn view(&self) -> ResponseHead<'_> {
        ResponseHead::new(self.bytes, self.fields, &self.info)
    }
}

impl fmt::Debug for ParsedResponse<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.view(), f)
    }
}

/// Parses one request head from the start of `input`, with the rules and
/// budgets of [`ServerConn`](crate::ServerConn) (the same scanner and
/// interpretation code), writing the field records into `fields`.
/// Allocates nothing. Unlike `ServerConn`, it does not check for the HTTP/2
/// connection preface first; call [`is_h2_preface`](crate::is_h2_preface)
/// for that.
///
/// It is stateless: given more input after `Partial`, it parses again from
/// the start. A caller that receives a head in many small pieces and needs
/// linear total work should use `ServerConn`, which resumes where it
/// stopped. A head with more fields than `fields` holds is
/// [`HttpError::TooManyHeaders`] (as is one over
/// [`Limits::max_headers`]).
///
/// # Errors
///
/// Every request parse error `ServerConn::poll` can return for a head,
/// except `UnexpectedEof` (running out of input is `Partial` here) and
/// `Http2Preface` (the preface is reported as
/// [`HttpError::UnsupportedVersion`]; call
/// [`is_h2_preface`](crate::is_h2_preface) first to tell them apart).
///
/// # Examples
///
/// ```
/// use http_net::{FieldSpan, Limits, Parsed, parse_request_head};
///
/// let input = b"POST /notes HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello";
/// let mut fields = [FieldSpan::default(); 32];
/// let Parsed::Complete { head, len } = parse_request_head(input, &Limits::new(), &mut fields)? else {
///     panic!("incomplete");
/// };
/// let req = head.view();
/// assert_eq!(req.path(), "/notes");
/// assert_eq!(req.content_length(), Some(5));
/// assert_eq!(&input[len..], b"hello");
/// # Ok::<(), http_net::HttpError>(())
/// ```
pub fn parse_request_head<'a>(
    input: &'a [u8],
    limits: &Limits,
    fields: &'a mut [FieldSpan],
) -> Result<Parsed<ParsedRequest<'a>>, HttpError> {
    let mut lines = LineScan::new();
    let mut sink = SliceSink::new(fields);
    let len = match lines.advance(input, limits, HeadKind::Request, &mut sink)? {
        Scan::Partial => return Ok(Parsed::Partial),
        Scan::Done(len) => len,
    };
    let (slots, count) = sink.into_parts();
    let slots: &'a [FieldSpan] = slots;
    let fields = slots.get(..count).unwrap_or(&[]);
    let bytes = input.get(..len).unwrap_or(input);
    let info = interpret_request(bytes, lines.start_line(), fields, limits)?;
    Ok(Parsed::Complete {
        head: ParsedRequest {
            bytes,
            fields,
            info,
        },
        len,
    })
}

/// Parses one response head from the start of `input` with the rules of
/// [`ClientConn`](crate::ClientConn), framed by what the request `asked`
/// (a `HEAD` request's response has no body; a 2xx to `CONNECT` is a
/// tunnel). Interim (1xx) heads are returned like any other; check
/// [`ResponseHead::is_informational`] and parse the next head after `len`.
/// No [`ClientLeniency`](crate::ClientLeniency) applies, so obsolete line
/// folding is always [`HttpError::ObsFold`]. Allocates nothing.
///
/// # Errors
///
/// Every response parse error `ClientConn::poll` can return for a head
/// (`UnexpectedEof` aside), and [`HttpError::TooManyHeaders`] when the head
/// has more fields than `fields` holds.
///
/// # Examples
///
/// ```
/// use http_net::{Asked, BodyFraming, FieldSpan, Limits, Parsed, parse_response_head};
///
/// let input = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
/// let mut fields = [FieldSpan::default(); 8];
/// let asked = Asked { head: true, connect: false };
/// let Parsed::Complete { head, .. } = parse_response_head(input, &Limits::new(), asked, &mut fields)? else {
///     panic!("incomplete");
/// };
/// // A response to HEAD has no body, whatever its fields say.
/// assert_eq!(head.view().framing(), BodyFraming::None);
/// assert_eq!(head.view().content_length(), Some(100));
/// # Ok::<(), http_net::HttpError>(())
/// ```
pub fn parse_response_head<'a>(
    input: &'a [u8],
    limits: &Limits,
    asked: Asked,
    fields: &'a mut [FieldSpan],
) -> Result<Parsed<ParsedResponse<'a>>, HttpError> {
    let mut lines = LineScan::new();
    let mut sink = SliceSink::new(fields);
    let len = match lines.advance(input, limits, HeadKind::Response, &mut sink)? {
        Scan::Partial => return Ok(Parsed::Partial),
        Scan::Done(len) => len,
    };
    let (slots, count) = sink.into_parts();
    let slots: &'a [FieldSpan] = slots;
    let fields = slots.get(..count).unwrap_or(&[]);
    let bytes = input.get(..len).unwrap_or(input);
    let info = interpret_response(bytes, lines.start_line(), fields, limits, asked)?;
    Ok(Parsed::Complete {
        head: ParsedResponse {
            bytes,
            fields,
            info,
        },
        len,
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::{ServerConn, ServerEvent};

    fn owned_parts(input: &[u8]) -> (Vec<u8>, Vec<FieldSpan>, HeadFacts) {
        let mut conn = ServerConn::new();
        let _ = conn.feed(input);
        let Ok(ServerEvent::Request(req)) = conn.poll() else {
            panic!("no request in {input:?}");
        };
        let (mut bytes, mut fields) = (Vec::new(), Vec::new());
        let facts = req.copy_into(&mut bytes, &mut fields).unwrap();
        (bytes, fields, facts)
    }

    #[test]
    fn test_span_get_and_len_never_panic() {
        let head = b"abc";
        assert_eq!(Span { start: 0, end: 3 }.get(head), b"abc");
        assert_eq!(Span { start: 2, end: 9 }.get(head), b"");
        assert_eq!(Span { start: 3, end: 1 }.get(head), b"");
        assert_eq!(Span { start: 3, end: 1 }.len(), 0);
        assert_eq!(
            Span {
                start: u32::MAX,
                end: u32::MAX
            }
            .get(head),
            b""
        );
        assert!(Span { start: 1, end: 1 }.is_empty());
    }

    #[test]
    fn test_raw_head_spans_point_at_the_parts() {
        let (bytes, fields, _) =
            owned_parts(b"\r\nPUT /f?q HTTP/1.0\r\nX:  v \r\nHost: h\r\n\r\nbody");
        assert_eq!(bytes, b"\r\nPUT /f?q HTTP/1.0\r\nX:  v \r\nHost: h\r\n\r\n");
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].value.get(&bytes), b"v");
        let mut conn = ServerConn::new();
        let _ = conn.feed(&bytes);
        let Ok(ServerEvent::Request(req)) = conn.poll() else {
            panic!()
        };
        let raw = req.raw();
        assert_eq!(raw.bytes(), &bytes[..]);
        assert_eq!(raw.start_line().get(raw.bytes()), b"PUT /f?q HTTP/1.0");
        assert_eq!(raw.version().get(raw.bytes()), b"HTTP/1.0");
        assert!(!alloc::format!("{raw:?}").contains("PUT"));
    }

    #[test]
    fn test_owned_head_view_equals_original() {
        let input = b"GET http://a.test/p?q=1 HTTP/1.1\r\nHost: b\r\nCookie: s=1\r\nVia: 1.1 x\r\nVia: 1.1 y\r\n\r\n";
        let mut conn = ServerConn::new();
        let _ = conn.feed(input);
        let Ok(ServerEvent::Request(req)) = conn.poll() else {
            panic!()
        };
        let owned = req.to_owned();
        let view = owned.view();
        assert_eq!(view.method_str(), req.method_str());
        assert_eq!(view.target(), req.target());
        assert_eq!(view.target_form(), req.target_form());
        assert_eq!(view.path(), req.path());
        assert_eq!(view.query(), req.query());
        assert_eq!(view.host(), req.host());
        assert_eq!(view.version(), req.version());
        assert_eq!(view.framing(), req.framing());
        assert_eq!(view.keep_alive(), req.keep_alive());
        assert!(view.headers().eq(req.headers()));
        assert!(view.header_all("via").eq(req.header_all("via")));
        assert_eq!(alloc::format!("{owned:?}"), alloc::format!("{req:?}"));
        let (b, f, facts) = owned_parts(input);
        let rebuilt = OwnedRequestHead::from_parts(b, f, facts).unwrap();
        assert_eq!(rebuilt, owned);
    }

    #[test]
    fn test_from_parts_accepts_every_valid_copy() {
        for input in [
            &b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"[..],
            b"\r\n\r\nGET / HTTP/1.0\r\n\r\n",
            b"OPTIONS * HTTP/1.1\r\nHost: a\r\nX:\r\nY: \t \r\n\r\n",
            b"CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\n",
            b"POST /x HTTP/1.1\r\nHost: \r\nTransfer-Encoding: chunked\r\n\r\n",
        ] {
            let (b, f, facts) = owned_parts(input);
            assert!(
                OwnedRequestHead::from_parts(b, f, facts).is_ok(),
                "{input:?}"
            );
        }
    }

    /// Every way a passport buffer can be changed after the copy is refused.
    #[test]
    fn test_from_parts_refuses_every_tampered_part() {
        let input = b"GET /a HTTP/1.1\r\nHost: h\r\nX-Two: v\r\n\r\n";
        let (bytes, fields, facts) = owned_parts(input);
        let refused = |b: Vec<u8>, f: Vec<FieldSpan>, facts: HeadFacts| {
            matches!(
                OwnedRequestHead::from_parts(b, f, facts),
                Err(HttpError::InvalidState(_))
            )
        };
        // Bytes changed under the spans.
        let tamper_byte = |i: usize, b: u8| {
            let mut v = bytes.clone();
            v[i] = b;
            v
        };
        assert!(refused(tamper_byte(0, b'P'), fields.clone(), facts)); // method
        assert!(refused(tamper_byte(3, b'_'), fields.clone(), facts)); // SP after method
        assert!(refused(tamper_byte(5, b'#'), fields.clone(), facts)); // target byte
        assert!(refused(tamper_byte(13, b'2'), fields.clone(), facts)); // version
        assert!(refused(tamper_byte(15, b'X'), fields.clone(), facts)); // start-line CRLF
        assert!(refused(tamper_byte(17, b' '), fields.clone(), facts)); // name
        assert!(refused(tamper_byte(21, b'='), fields.clone(), facts)); // colon
        assert!(refused(tamper_byte(23, 0), fields.clone(), facts)); // value control byte
        assert!(refused(tamper_byte(24, b'x'), fields.clone(), facts)); // field CRLF
        let mut shorter = bytes.clone();
        let _ = shorter.pop();
        assert!(refused(shorter, fields.clone(), facts)); // blank line cut
        let mut longer = bytes.clone();
        longer.push(b'x');
        assert!(refused(longer, fields.clone(), facts)); // bytes past the head
        let mut leading = b"x\r\n".to_vec();
        leading.extend_from_slice(&bytes);
        assert!(refused(leading, fields.clone(), facts)); // junk before the start line
        // Spans moved.
        let tamper_field = |i: usize, change: &dyn Fn(&mut FieldSpan)| {
            let mut f = fields.clone();
            change(&mut f[i]);
            f
        };
        assert!(refused(
            bytes.clone(),
            tamper_field(0, &|f| f.name.end += 1),
            facts
        ));
        assert!(refused(
            bytes.clone(),
            tamper_field(0, &|f| f.name.start += 1),
            facts
        ));
        assert!(refused(
            bytes.clone(),
            tamper_field(0, &|f| f.value.end += 50),
            facts
        ));
        assert!(refused(
            bytes.clone(),
            tamper_field(0, &|f| f.value.start = 0),
            facts
        ));
        assert!(refused(
            bytes.clone(),
            tamper_field(1, &|f| f.value.end -= 1),
            facts
        ));
        assert!(refused(
            bytes.clone(),
            tamper_field(1, &|f| *f = FieldSpan::default()),
            facts
        ));
        let mut swapped = fields.clone();
        swapped.swap(0, 1);
        assert!(refused(bytes.clone(), swapped, facts)); // out of order
        let mut dropped = fields.clone();
        let _ = dropped.pop();
        assert!(refused(bytes.clone(), dropped, facts)); // a line no span covers
        let mut doubled = fields.clone();
        doubled.push(fields[1]);
        assert!(refused(bytes.clone(), doubled, facts)); // overlapping
        // Facts moved.
        let tamper_facts = |change: &dyn Fn(&mut RequestInfo)| {
            let mut info = facts.info;
            change(&mut info);
            HeadFacts { info }
        };
        assert!(refused(
            bytes.clone(),
            fields.clone(),
            tamper_facts(&|i| i.start_line.end += 1)
        ));
        assert!(refused(
            bytes.clone(),
            fields.clone(),
            tamper_facts(&|i| i.target.end += 1)
        ));
        assert!(refused(
            bytes.clone(),
            fields.clone(),
            tamper_facts(&|i| i.method = Method::Post)
        ));
        assert!(refused(
            bytes.clone(),
            fields.clone(),
            tamper_facts(&|i| i.host = Some(fields[1].value))
        ));
        assert!(refused(
            bytes.clone(),
            fields.clone(),
            tamper_facts(&|i| i.origin = Span { start: 0, end: 3 })
        ));
        assert!(refused(
            bytes.clone(),
            fields.clone(),
            tamper_facts(&|i| i.authority = Some(Span { start: 0, end: 3 }))
        ));
        // The untouched parts are still accepted.
        assert!(OwnedRequestHead::from_parts(bytes, fields, facts).is_ok());
    }

    #[test]
    fn test_stateless_request_parse_complete_partial_and_errors() {
        let mut fields = [FieldSpan::default(); 4];
        let input = b"GET / HTTP/1.1\r\nHost: a\r\n\r\nGET";
        let Ok(Parsed::Complete { head, len }) =
            parse_request_head(input, &Limits::new(), &mut fields)
        else {
            panic!()
        };
        assert_eq!(len, input.len() - 3);
        assert_eq!(head.view().host(), Some("a"));
        for cut in 0..len {
            let mut fields = [FieldSpan::default(); 4];
            assert!(matches!(
                parse_request_head(&input[..cut], &Limits::new(), &mut fields),
                Ok(Parsed::Partial)
            ));
        }
        let mut fields = [FieldSpan::default(); 4];
        assert_eq!(
            parse_request_head(b"GET / HTTP/1.1\r\n\r\n", &Limits::new(), &mut fields).err(),
            Some(HttpError::MissingHost)
        );
        assert_eq!(
            parse_request_head(
                b"GET / HTTP/1.1\nHost: a\r\n\r\n",
                &Limits::new(),
                &mut fields
            )
            .err(),
            Some(HttpError::BareLf)
        );
        // More fields than the caller's array holds.
        let mut one = [FieldSpan::default(); 1];
        assert_eq!(
            parse_request_head(
                b"GET / HTTP/1.1\r\nHost: a\r\nX: 1\r\n\r\n",
                &Limits::new(),
                &mut one
            )
            .err(),
            Some(HttpError::TooManyHeaders)
        );
        let mut none: [FieldSpan; 0] = [];
        assert!(matches!(
            parse_request_head(b"GET / HTTP/1.0\r\n\r\n", &Limits::new(), &mut none),
            Ok(Parsed::Complete { .. })
        ));
    }

    #[test]
    fn test_stateless_response_parse_follows_what_was_asked() {
        let mut fields = [FieldSpan::default(); 4];
        let input = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        let Ok(Parsed::Complete { head, len }) =
            parse_response_head(input, &Limits::new(), Asked::default(), &mut fields)
        else {
            panic!()
        };
        assert_eq!(head.view().framing(), crate::BodyFraming::Length(3));
        assert_eq!(&input[len..], b"abc");
        assert_eq!(
            head.view().raw().status().get(head.view().raw().bytes()),
            b"200"
        );
        let mut fields = [FieldSpan::default(); 4];
        let connect = Asked {
            head: false,
            connect: true,
        };
        let Ok(Parsed::Complete { head, .. }) =
            parse_response_head(input, &Limits::new(), connect, &mut fields)
        else {
            panic!()
        };
        assert_eq!(head.view().framing(), crate::BodyFraming::None);
        let mut fields = [FieldSpan::default(); 4];
        assert_eq!(
            parse_response_head(
                b"\r\nHTTP/1.1 200 OK\r\n\r\n",
                &Limits::new(),
                Asked::default(),
                &mut fields
            )
            .err(),
            Some(HttpError::InvalidStartLine)
        );
        let mut fields = [FieldSpan::default(); 4];
        assert!(matches!(
            parse_response_head(b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n", &Limits::new(), Asked::default(), &mut fields),
            Ok(Parsed::Complete { head, .. }) if head.view().is_informational()
        ));
        let v = vec![b'x'; 3];
        let mut fields = [FieldSpan::default(); 4];
        assert!(matches!(
            parse_response_head(&v, &Limits::new(), Asked::default(), &mut fields),
            Ok(Parsed::Partial)
        ));
    }
}
