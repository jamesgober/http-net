//! Incremental scanning of message heads, their interpretation, and the
//! borrowed views handed to callers.
//!
//! The scanner finds one CRLF-terminated line at a time and remembers where
//! it stopped searching, so input that arrives one byte at a time is still
//! examined once: head parsing is linear in the head's length no matter how
//! it is split. Each line is fully validated when it completes; field
//! positions are stored as offsets from the message start so the head can be
//! read back without copying.

use alloc::vec::Vec;
use core::{fmt, slice};

use crate::{
    error::HttpError,
    limits::Limits,
    method::Method,
    redact::{FieldName, FieldValue},
    syntax::{
        ListSplit, check_field_value, find_byte, is_host_value, is_ows, is_reason, is_target_chars,
        is_tchar, is_token, list_elements, parse_decimal, printable_run, trim_ows,
    },
};

/// A byte range of a message head: `start..end`, as offsets into
/// [`RawHead::bytes`](crate::RawHead::bytes) (or into the input of a
/// stateless parser).
///
/// Offsets are `u32` because every budget in [`Limits`] is capped at
/// 16 MiB, so a head can never be longer. Spans stay valid when the head
/// bytes are moved or copied, which is what makes a head cheap to copy into
/// a passport ([`RequestHead::copy_into`]).
///
/// # Examples
///
/// ```
/// use http_net::Span;
///
/// let head = b"GET / HTTP/1.1\r\n";
/// let method = Span { start: 0, end: 3 };
/// assert_eq!(method.get(head), b"GET");
/// assert_eq!(method.len(), 3);
/// // Out of range: an empty slice, never a panic.
/// assert_eq!(Span { start: 10, end: 99 }.get(head), b"");
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Span {
    /// The first byte.
    pub start: u32,
    /// One past the last byte.
    pub end: u32,
}

impl Span {
    #[inline]
    pub(crate) fn new(start: usize, end: usize) -> Self {
        // Offsets are bounded by the buffer capacity, which `Limits` keeps
        // far below `u32::MAX`.
        Self {
            start: start as u32,
            end: end as u32,
        }
    }

    /// The bytes of `head` the span covers; empty when the span lies
    /// outside `head` or is reversed.
    ///
    /// # Examples
    ///
    /// ```
    /// let span = http_net::Span { start: 4, end: 5 };
    /// assert_eq!(span.get(b"GET / HTTP/1.1"), b"/");
    /// ```
    #[inline]
    #[must_use]
    pub fn get<'b>(&self, head: &'b [u8]) -> &'b [u8] {
        head.get(self.start as usize..self.end as usize)
            .unwrap_or(&[])
    }

    /// The span's length in bytes (0 for a reversed span).
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Span { start: 2, end: 7 }.len(), 5);
    /// ```
    #[inline]
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.end.saturating_sub(self.start)
    }

    /// Whether the span covers no bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(http_net::Span::default().is_empty());
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the span lies inside a head of `len` bytes, in order.
    pub(crate) const fn fits(&self, len: usize) -> bool {
        self.start <= self.end && (self.end as usize) <= len
    }
}

/// One field line of a head: the name's span and the value's span (the
/// value without surrounding whitespace), as offsets into the head bytes.
///
/// # Examples
///
/// ```
/// use http_net::{ServerConn, ServerEvent};
///
/// let mut conn = ServerConn::new();
/// let _ = conn.feed(b"GET / HTTP/1.1\r\nHost:  a \r\n\r\n");
/// let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
/// let raw = req.raw();
/// let host = raw.fields()[0];
/// assert_eq!(host.name.get(raw.bytes()), b"Host");
/// assert_eq!(host.value.get(raw.bytes()), b"a");
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FieldSpan {
    /// The field name, as received.
    pub name: Span,
    /// The field value, without leading or trailing whitespace.
    pub value: Span,
}

/// The connections' own name for a field record.
pub(crate) type Field = FieldSpan;

/// Where scanned field records go: the connection's reusable vector, a
/// caller's slice (the stateless parsers, which allocate nothing), or
/// nowhere (trailers that are validated and discarded).
pub(crate) trait FieldSink {
    fn put(&mut self, field: Field) -> Result<(), HttpError>;
}

impl FieldSink for Vec<Field> {
    #[inline]
    fn put(&mut self, field: Field) -> Result<(), HttpError> {
        self.push(field);
        Ok(())
    }
}

/// Validates fields without keeping them.
pub(crate) struct Discard;

impl FieldSink for Discard {
    #[inline]
    fn put(&mut self, _field: Field) -> Result<(), HttpError> {
        Ok(())
    }
}

/// Fills a caller's slice; a field that does not fit is `TooManyHeaders`.
pub(crate) struct SliceSink<'s> {
    slots: &'s mut [Field],
    len: usize,
}

impl<'s> SliceSink<'s> {
    pub(crate) fn new(slots: &'s mut [Field]) -> Self {
        Self { slots, len: 0 }
    }

    /// The slice back, and how many records were written to its front.
    pub(crate) fn into_parts(self) -> (&'s mut [Field], usize) {
        (self.slots, self.len)
    }
}

impl FieldSink for SliceSink<'_> {
    #[inline]
    fn put(&mut self, field: Field) -> Result<(), HttpError> {
        let slot = self
            .slots
            .get_mut(self.len)
            .ok_or(HttpError::TooManyHeaders)?;
        *slot = field;
        self.len += 1;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeadKind {
    Request,
    Response,
    Trailer,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Scan {
    Partial,
    /// The head is complete; the value is its length including the blank line.
    Done(usize),
}

/// Finds the next CRLF-terminated line starting at `line_start`, resuming
/// the search at `*scan`. Returns the end of the line content (the index of
/// its CR). `budget` bounds the line length including CRLF.
pub(crate) fn find_line(
    msg: &[u8],
    line_start: usize,
    scan: &mut usize,
    budget: usize,
    too_long: HttpError,
) -> Result<Option<usize>, HttpError> {
    let from = (*scan).max(line_start);
    let hay = msg.get(from..).unwrap_or(&[]);
    match find_byte(b'\n', hay) {
        Some(i) => {
            let lf = from + i;
            if lf + 1 - line_start > budget {
                return Err(too_long);
            }
            if lf == line_start || msg.get(lf - 1) != Some(&b'\r') {
                return Err(HttpError::BareLf);
            }
            *scan = lf + 1;
            Ok(Some(lf - 1))
        }
        None => {
            *scan = msg.len();
            if msg.len().saturating_sub(line_start) >= budget {
                Err(too_long)
            } else {
                Ok(None)
            }
        }
    }
}

/// Resumable scanner over a head (start line plus field lines) or a trailer
/// section (field lines only), keeping its fields in a reusable vector.
pub(crate) struct HeadScanner {
    lines: LineScan,
    pub(crate) fields: Vec<Field>,
}

impl HeadScanner {
    pub(crate) const fn new() -> Self {
        Self {
            lines: LineScan::new(),
            fields: Vec::new(),
        }
    }

    /// Prepares for the next message; keeps the field vector's allocation.
    pub(crate) fn reset(&mut self) {
        self.lines = LineScan::new();
        self.fields.clear();
    }

    /// Fields scanned in the current section, stored or not.
    pub(crate) fn field_count(&self) -> usize {
        self.lines.count
    }

    pub(crate) fn start_line(&self) -> Span {
        self.lines.start_line()
    }

    /// Scans `msg` (the bytes from the message start to the end of input).
    /// With `store` the fields are kept in [`fields`](Self::fields);
    /// otherwise they are validated and counted only.
    #[inline]
    pub(crate) fn advance(
        &mut self,
        msg: &[u8],
        limits: &Limits,
        kind: HeadKind,
        store: bool,
    ) -> Result<Scan, HttpError> {
        if store {
            self.lines.advance(msg, limits, kind, &mut self.fields)
        } else {
            self.lines.advance(msg, limits, kind, &mut Discard)
        }
    }
}

/// The line-by-line state of a head scan: where the search stopped and
/// what has been counted. Shared by the connections and the stateless
/// parsers; the fields go to a [`FieldSink`].
pub(crate) struct LineScan {
    scan: usize,
    line_start: usize,
    start_line: Option<Span>,
    skipped: usize,
    field_bytes: usize,
    count: usize,
}

impl LineScan {
    pub(crate) const fn new() -> Self {
        Self {
            scan: 0,
            line_start: 0,
            start_line: None,
            skipped: 0,
            field_bytes: 0,
            count: 0,
        }
    }

    pub(crate) fn start_line(&self) -> Span {
        self.start_line.unwrap_or_default()
    }

    /// Scans `msg` (the bytes from the message start to the end of input),
    /// handing each validated field to `sink`.
    pub(crate) fn advance<S: FieldSink>(
        &mut self,
        msg: &[u8],
        limits: &Limits,
        kind: HeadKind,
        sink: &mut S,
    ) -> Result<Scan, HttpError> {
        let (section_bytes, section_fields) = if kind == HeadKind::Trailer {
            (limits.max_trailer_bytes(), limits.max_trailer_fields())
        } else {
            (limits.max_header_bytes(), limits.max_headers())
        };
        loop {
            let in_start = kind != HeadKind::Trailer && self.start_line.is_none();
            let (budget, too_long) = if in_start {
                (
                    limits.max_start_line().saturating_sub(self.skipped),
                    HttpError::StartLineTooLong,
                )
            } else {
                // One line may not exceed the field-line budget, nor what is
                // left of the section; whichever is smaller decides the error.
                let section = section_bytes.saturating_sub(self.field_bytes);
                if limits.max_field_line() < section {
                    (limits.max_field_line(), HttpError::FieldLineTooLong)
                } else {
                    (section, HttpError::HeadersTooLarge)
                }
            };
            // The common field line in one pass. Anything else, and a line
            // whose search already began on earlier input, takes the general
            // path below, which decides exactly as it always has.
            if !in_start && self.scan <= self.line_start {
                if let Some((field, next)) = fast_field(msg, self.line_start) {
                    let line_len = next - self.line_start;
                    if line_len <= budget {
                        self.scan = next;
                        self.line_start = next;
                        self.field_bytes += line_len;
                        if self.field_bytes + 2 > section_bytes {
                            return Err(HttpError::HeadersTooLarge);
                        }
                        if self.count >= section_fields {
                            return Err(HttpError::TooManyHeaders);
                        }
                        self.count += 1;
                        sink.put(field)?;
                        continue;
                    }
                }
            }
            let Some(end) = find_line(msg, self.line_start, &mut self.scan, budget, too_long)?
            else {
                return Ok(Scan::Partial);
            };
            let start = self.line_start;
            let line = msg.get(start..end).unwrap_or(&[]);
            let line_len = self.scan - start;
            self.line_start = self.scan;

            if in_start {
                if line.is_empty() {
                    if kind == HeadKind::Request {
                        // RFC 9112 section 2.2: ignore empty lines before the
                        // request line. They count against its budget.
                        self.skipped += line_len;
                        continue;
                    }
                    return Err(HttpError::InvalidStartLine);
                }
                if find_byte(b'\r', line).is_some() {
                    return Err(HttpError::BareCr);
                }
                self.start_line = Some(Span::new(start, end));
                continue;
            }
            if line.is_empty() {
                return Ok(Scan::Done(self.scan));
            }
            self.field_bytes += line_len;
            // Every field line must leave room for the blank line that ends
            // the section, so the section as a whole fits the budget.
            if self.field_bytes + 2 > section_bytes {
                return Err(HttpError::HeadersTooLarge);
            }
            if self.count >= section_fields {
                return Err(HttpError::TooManyHeaders);
            }
            let field = parse_field(line, start)?;
            self.count += 1;
            sink.put(field)?;
        }
    }
}

/// Validates one field line (`line` starts at offset `base` in the head).
// Forced inline: the scanner is compiled once per field sink, and without
// it this per-field call stays out of line (about 8% on the head
// benchmark, 12% on client response parsing).
#[inline(always)]
fn parse_field(line: &[u8], base: usize) -> Result<Field, HttpError> {
    if line.first().is_some_and(|&b| is_ows(b)) {
        return Err(HttpError::ObsFold);
    }
    let Some(colon) = find_byte(b':', line) else {
        return Err(if find_byte(b'\r', line).is_some() {
            HttpError::BareCr
        } else {
            HttpError::InvalidHeaderName
        });
    };
    let name = &line[..colon];
    if name.last().is_some_and(|&b| is_ows(b)) {
        return Err(HttpError::WhitespaceBeforeColon);
    }
    if !name.iter().all(|&b| is_tchar(b)) || name.is_empty() {
        return Err(if find_byte(b'\r', name).is_some() {
            HttpError::BareCr
        } else {
            HttpError::InvalidHeaderName
        });
    }
    let raw = &line[colon + 1..];
    let lead = raw.iter().take_while(|&&b| is_ows(b)).count();
    let value = trim_ows(raw);
    check_field_value(value)?;
    let value_start = base + colon + 1 + lead;
    Ok(Field {
        name: Span::new(base, base + colon),
        value: Span::new(value_start, value_start + value.len()),
    })
}

/// The common field line in one pass, the way it nearly always arrives: a
/// token name, a colon, spaces, a value of printable ASCII, and CR LF, all
/// in `msg` from `start`. Returns the field and the offset after its LF.
///
/// `None` for anything else (a tab, obs-text, a control byte, a bare CR or
/// LF, a fold, a missing colon) and for a line not yet complete: the caller
/// then takes the general path from the line's start, which accepts and
/// refuses exactly as before. On every line this accepts, the general path
/// gives the same field (`tests` below and the fuzz targets check it).
#[inline(always)]
fn fast_field(msg: &[u8], start: usize) -> Option<(Field, usize)> {
    let line = msg.get(start..)?;
    let colon = line.iter().position(|&b| !is_tchar(b))?;
    if colon == 0 || line[colon] != b':' {
        return None;
    }
    let mut value = colon + 1;
    while line.get(value) == Some(&b' ') {
        value += 1;
    }
    let cr = value + printable_run(&line[value..]);
    if line.get(cr) != Some(&b'\r') || line.get(cr + 1) != Some(&b'\n') {
        return None;
    }
    let mut value_end = cr;
    while value_end > value && line[value_end - 1] == b' ' {
        value_end -= 1;
    }
    Some((
        Field {
            name: Span::new(start, start + colon),
            value: Span::new(start + value, start + value_end),
        },
        start + cr + 2,
    ))
}

/// The HTTP version of a message.
///
/// # Examples
///
/// ```
/// use http_net::Version;
///
/// assert_eq!(Version::Http11.as_str(), "HTTP/1.1");
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Version {
    /// HTTP/1.0: no chunked encoding, keep-alive only when asked for.
    Http10,
    /// HTTP/1.1 (also used for HTTP/1.2 through 1.9, which RFC 9110 section
    /// 2.5 says to process as the highest implemented minor version).
    Http11,
}

impl Version {
    /// The version's wire text.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Version::Http10.as_str(), "HTTP/1.0");
    /// ```
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        }
    }
}

/// How a message's body is delimited.
///
/// # Examples
///
/// ```
/// use http_net::{BodyFraming, ServerConn, ServerEvent};
///
/// let mut conn = ServerConn::new();
/// let _ = conn.feed(b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc");
/// match conn.poll().unwrap() {
///     ServerEvent::Request(req) => assert_eq!(req.framing(), BodyFraming::Length(3)),
///     other => panic!("{other:?}"),
/// }
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BodyFraming {
    /// No body.
    None,
    /// Exactly this many bytes (`Content-Length`).
    Length(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// The body runs until the peer closes the connection (responses only).
    UntilClose,
}

/// The form of a request target (RFC 9112 section 3.2).
///
/// # Examples
///
/// ```
/// use http_net::{ServerConn, ServerEvent, TargetForm};
///
/// let mut conn = ServerConn::new();
/// let _ = conn.feed(b"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n");
/// let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
/// assert_eq!(req.target_form(), TargetForm::Asterisk);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TargetForm {
    /// `/path?query`: the usual form for requests to an origin server.
    Origin,
    /// `scheme://authority/path?query`: requests to a proxy (and, per RFC
    /// 9112 section 3.2.2, acceptable to origin servers too).
    Absolute,
    /// `host:port`: only with `CONNECT`.
    Authority,
    /// `*`: only with `OPTIONS`, for the server as a whole.
    Asterisk,
}

/// The `h2c` upgrade token, which is never treated as an upgrade offer
/// (RFC 9113 section 3.1 deprecates it; forwarded blindly by a proxy, it is
/// the h2c smuggling attack).
pub(crate) fn is_h2c(protocol: &[u8]) -> bool {
    let name = protocol
        .iter()
        .position(|&b| b == b'/')
        .map_or(protocol, |i| &protocol[..i]);
    name.eq_ignore_ascii_case(b"h2c")
}

/// Whether a `101` naming `chosen` answers an `Upgrade` offer `element`:
/// ASCII case-insensitive, and a name without a version matches an offer of
/// that name with any version (`websocket` answers `websocket/13`).
pub(crate) fn protocol_matches(chosen: &[u8], element: &[u8]) -> bool {
    if is_h2c(element) || is_h2c(chosen) {
        return false;
    }
    if chosen.eq_ignore_ascii_case(element) {
        return true;
    }
    !chosen.contains(&b'/')
        && element
            .iter()
            .position(|&b| b == b'/')
            .is_some_and(|i| element[..i].eq_ignore_ascii_case(chosen))
}

pub(crate) fn parse_version(v: &[u8]) -> Result<Version, HttpError> {
    match v {
        [b'H', b'T', b'T', b'P', b'/', major, b'.', minor]
            if major.is_ascii_digit() && minor.is_ascii_digit() =>
        {
            match (major, minor) {
                (b'1', b'0') => Ok(Version::Http10),
                (b'1', _) => Ok(Version::Http11),
                _ => Err(HttpError::UnsupportedVersion),
            }
        }
        _ => Err(HttpError::InvalidVersion),
    }
}

/// What the framing-relevant fields of a message say.
#[derive(Default)]
struct FieldFacts {
    content_length: Option<u64>,
    te_seen: bool,
    te_codings: usize,
    te_chunked: usize,
    te_last_chunked: bool,
    te_other: bool,
    close: bool,
    keep_alive: bool,
    upgrade_token: bool,
    upgrade_field: bool,
    /// An `Upgrade` element other than `h2c`.
    upgrade_offer: bool,
    expect_continue: bool,
    /// An `Expect` element other than `100-continue`.
    expect_other: bool,
    hosts: usize,
    host: Option<Span>,
}

fn scan_fields(head: &[u8], fields: &[Field]) -> Result<FieldFacts, HttpError> {
    let mut facts = FieldFacts::default();
    for field in fields {
        let name = field.name.get(head);
        let value = field.value.get(head);
        if name.eq_ignore_ascii_case(b"content-length") {
            if facts.content_length.is_some() {
                return Err(HttpError::DuplicateContentLength);
            }
            facts.content_length =
                Some(parse_decimal(value).ok_or(HttpError::InvalidContentLength)?);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            facts.te_seen = true;
            for element in list_elements(value) {
                let (coding, params) = match find_byte(b';', element) {
                    Some(i) => (trim_ows(&element[..i]), true),
                    None => (element, false),
                };
                if !is_token(coding) {
                    return Err(HttpError::InvalidTransferEncoding);
                }
                facts.te_codings += 1;
                if coding.eq_ignore_ascii_case(b"chunked") {
                    if params {
                        return Err(HttpError::InvalidTransferEncoding);
                    }
                    facts.te_chunked += 1;
                    facts.te_last_chunked = true;
                } else {
                    facts.te_other = true;
                    facts.te_last_chunked = false;
                }
            }
        } else if name.eq_ignore_ascii_case(b"connection") {
            for token in list_elements(value) {
                if token.eq_ignore_ascii_case(b"close") {
                    facts.close = true;
                } else if token.eq_ignore_ascii_case(b"keep-alive") {
                    facts.keep_alive = true;
                } else if token.eq_ignore_ascii_case(b"upgrade") {
                    facts.upgrade_token = true;
                }
            }
        } else if name.eq_ignore_ascii_case(b"upgrade") {
            facts.upgrade_field |= !value.is_empty();
            facts.upgrade_offer |= list_elements(value).any(|e| !is_h2c(e));
        } else if name.eq_ignore_ascii_case(b"host") {
            facts.hosts += 1;
            facts.host = Some(field.value);
        } else if name.eq_ignore_ascii_case(b"expect") {
            // RFC 9110 section 10.1.1: the expectation is case-insensitive.
            for e in list_elements(value) {
                if e.eq_ignore_ascii_case(b"100-continue") {
                    facts.expect_continue = true;
                } else {
                    facts.expect_other = true;
                }
            }
        }
    }
    Ok(facts)
}

/// Applies RFC 9112 section 6 to the transfer-coding facts.
fn transfer_framing(
    facts: &FieldFacts,
    version: Version,
) -> Result<Option<BodyFraming>, HttpError> {
    if !facts.te_seen {
        return Ok(None);
    }
    if version == Version::Http10 {
        return Err(HttpError::TransferEncodingInHttp10);
    }
    if facts.content_length.is_some() {
        return Err(HttpError::ConflictingFraming);
    }
    if facts.te_codings == 0 || facts.te_chunked > 1 || !facts.te_last_chunked {
        return Err(HttpError::InvalidTransferEncoding);
    }
    if facts.te_other {
        return Err(HttpError::UnsupportedTransferEncoding);
    }
    Ok(Some(BodyFraming::Chunked))
}

/// Everything learned from a request head. Spans are offsets into the head
/// bytes, so the facts stay valid when the bytes are copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RequestInfo {
    pub(crate) method: Method,
    pub(crate) start_line: Span,
    pub(crate) method_span: Span,
    pub(crate) target: Span,
    target_form: TargetForm,
    pub(crate) version: Version,
    pub(crate) framing: BodyFraming,
    content_length: Option<u64>,
    pub(crate) keep_alive: bool,
    pub(crate) upgrade: bool,
    pub(crate) expect_continue: bool,
    unknown_expectation: bool,
    pub(crate) host: Option<Span>,
    /// The authority of an absolute-form target, which replaces `Host`.
    pub(crate) authority: Option<Span>,
    /// The path-and-query part of the target: the whole target except for
    /// the absolute form, where it is what follows the authority.
    pub(crate) origin: Span,
}

impl RequestInfo {
    pub(crate) const EMPTY: Self = Self {
        method: Method::Get,
        start_line: Span { start: 0, end: 0 },
        method_span: Span { start: 0, end: 0 },
        target: Span { start: 0, end: 0 },
        target_form: TargetForm::Origin,
        version: Version::Http11,
        framing: BodyFraming::None,
        content_length: None,
        keep_alive: false,
        upgrade: false,
        expect_continue: false,
        unknown_expectation: false,
        host: None,
        authority: None,
        origin: Span { start: 0, end: 0 },
    };
}

/// Validates a request target against the forms its method allows.
pub(crate) fn check_target(method: Method, target: &[u8]) -> Result<(), HttpError> {
    let ok = match target.first() {
        None => false,
        Some(b'/') => method != Method::Connect && is_target_chars(target),
        Some(b'*') if target.len() == 1 => method == Method::Options,
        Some(_) if method == Method::Connect => {
            // authority-form: host ":" port, with a non-empty host and port.
            is_authority(target)
                && target
                    .iter()
                    .rposition(|&b| b == b':')
                    .is_some_and(|c| c + 1 < target.len() && !target[c..].contains(&b']'))
        }
        Some(_) => split_absolute_form(target).is_some(),
    };
    if ok {
        Ok(())
    } else {
        Err(HttpError::InvalidTarget)
    }
}

/// `host [":" port]` with a non-empty host: RFC 9110 section 4.2.1 makes an
/// empty host in an `http` URI invalid.
fn is_authority(s: &[u8]) -> bool {
    !s.is_empty() && s[0] != b':' && is_host_value(s)
}

/// Splits an absolute-form target, `scheme "://" authority path-abempty
/// [ "?" query ]`, returning the authority's range within it.
///
/// Only the hierarchical form with an authority is accepted: it is the form
/// RFC 9112 section 3.2.2 describes (requests to proxies, and future
/// requests to origin servers), and it is the only one that names the host
/// the request is for. Userinfo is refused (RFC 9110 section 4.2.4 says to
/// treat it as an error), as is an empty host.
fn split_absolute_form(target: &[u8]) -> Option<(usize, usize)> {
    let colon = find_byte(b':', target)?;
    let scheme = &target[..colon];
    let scheme_ok = scheme.first().is_some_and(u8::is_ascii_alphabetic)
        && scheme
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'));
    if !scheme_ok || !target[colon..].starts_with(b"://") {
        return None;
    }
    let auth_start = colon + 3;
    let after = &target[auth_start..];
    let auth_len = after
        .iter()
        .position(|&b| b == b'/' || b == b'?')
        .unwrap_or(after.len());
    let authority = &after[..auth_len];
    let rest = &after[auth_len..];
    (is_authority(authority) && is_target_chars(rest))
        .then_some((auth_start, auth_start + auth_len))
}

pub(crate) fn interpret_request(
    head: &[u8],
    start: Span,
    fields: &[Field],
    limits: &Limits,
) -> Result<RequestInfo, HttpError> {
    let line = start.get(head);
    let base = start.start as usize;
    let sp1 = find_byte(b' ', line).ok_or(HttpError::InvalidStartLine)?;
    let sp2 = line
        .iter()
        .rposition(|&b| b == b' ')
        .ok_or(HttpError::InvalidStartLine)?;
    if sp2 == sp1 {
        return Err(HttpError::InvalidStartLine);
    }
    let method_bytes = &line[..sp1];
    if !is_token(method_bytes) {
        return Err(HttpError::InvalidMethod);
    }
    let version = parse_version(&line[sp2 + 1..])?;
    let method = Method::from_bytes(method_bytes);
    let target = &line[sp1 + 1..sp2];
    check_target(method, target)?;
    let target_start = base + sp1 + 1;
    let target_span = Span::new(target_start, base + sp2);
    let (target_form, authority, origin) = match target.first() {
        Some(b'/') => (TargetForm::Origin, None, target_span),
        Some(b'*') => (TargetForm::Asterisk, None, target_span),
        _ if method == Method::Connect => (TargetForm::Authority, None, target_span),
        _ => match split_absolute_form(target) {
            Some((a, b)) => (
                TargetForm::Absolute,
                Some(Span::new(target_start + a, target_start + b)),
                Span::new(target_start + b, base + sp2),
            ),
            None => return Err(HttpError::InvalidTarget),
        },
    };

    let facts = scan_fields(head, fields)?;
    let framing = match transfer_framing(&facts, version)? {
        Some(f) => f,
        None => match facts.content_length {
            Some(n) if n > limits.max_body() => return Err(HttpError::BodyTooLarge),
            Some(0) | None => BodyFraming::None,
            Some(n) => BodyFraming::Length(n),
        },
    };
    if facts.hosts > 1 {
        return Err(HttpError::InvalidHost);
    }
    if let Some(host) = facts.host {
        if !is_host_value(host.get(head)) {
            return Err(HttpError::InvalidHost);
        }
    } else if version == Version::Http11 {
        return Err(HttpError::MissingHost);
    }
    let keep_alive = match version {
        Version::Http11 => !facts.close,
        Version::Http10 => facts.keep_alive && !facts.close,
    };
    Ok(RequestInfo {
        method,
        start_line: start,
        method_span: Span::new(base, base + sp1),
        target: target_span,
        target_form,
        version,
        framing,
        content_length: facts.content_length,
        keep_alive,
        // RFC 9110 section 7.8: Upgrade in an HTTP/1.0 request is ignored.
        // An offer of only `h2c` is no offer: the request is served as
        // HTTP/1.1 (RFC 9113 section 3.1).
        upgrade: version == Version::Http11 && facts.upgrade_token && facts.upgrade_offer,
        // Reported for any version, so the caller can answer 417 (RFC 9110
        // section 10.1.1 MAY); it never changes framing.
        unknown_expectation: facts.expect_other,
        // RFC 9110 section 10.1.1: ignored in HTTP/1.0, and meaningless
        // without a body to wait for.
        expect_continue: version == Version::Http11
            && facts.expect_continue
            && framing != BodyFraming::None,
        host: facts.host,
        authority,
        origin,
    })
}

/// Everything learned from a response head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResponseInfo {
    pub(crate) status: u16,
    pub(crate) start_line: Span,
    reason: Span,
    pub(crate) version: Version,
    pub(crate) framing: BodyFraming,
    content_length: Option<u64>,
    pub(crate) keep_alive: bool,
    pub(crate) upgrade_field: bool,
}

impl ResponseInfo {
    pub(crate) const EMPTY: Self = Self {
        status: 0,
        start_line: Span { start: 0, end: 0 },
        reason: Span { start: 0, end: 0 },
        version: Version::Http11,
        framing: BodyFraming::None,
        content_length: None,
        keep_alive: false,
        upgrade_field: false,
    };
}

/// What the request asked for, which decides how its response is framed
/// (RFC 9112 section 6.3): a response to `HEAD` has no body whatever its
/// fields say, and a 2xx to `CONNECT` turns the connection into a tunnel.
/// The input to [`parse_response_head`](crate::parse_response_head).
///
/// # Examples
///
/// ```
/// use http_net::Asked;
///
/// let after_head = Asked { head: true, ..Asked::default() };
/// assert!(after_head.head && !after_head.connect);
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Asked {
    /// The request was `HEAD`.
    pub head: bool,
    /// The request was `CONNECT`.
    pub connect: bool,
}

pub(crate) fn interpret_response(
    head: &[u8],
    start: Span,
    fields: &[Field],
    limits: &Limits,
    asked: Asked,
) -> Result<ResponseInfo, HttpError> {
    let line = start.get(head);
    let base = start.start as usize;
    // status-line = HTTP-version SP status-code SP [ reason-phrase ]
    // The SP after the code is required of senders, but some servers omit
    // it when the reason is empty (`HTTP/1.1 200`); accepting that cannot
    // change framing, so the client does (RFC 9112 section 4).
    if line.len() < 12 || line[8] != b' ' || (line.len() > 12 && line[12] != b' ') {
        return Err(HttpError::InvalidStartLine);
    }
    let version = parse_version(&line[..8])?;
    let code = &line[9..12];
    if !code.iter().all(u8::is_ascii_digit) {
        return Err(HttpError::InvalidStatus);
    }
    let status = code
        .iter()
        .fold(0u16, |acc, &d| acc * 10 + u16::from(d - b'0'));
    if !(100..=599).contains(&status) {
        return Err(HttpError::InvalidStatus);
    }
    let reason_start = line.len().min(13);
    let reason = &line[reason_start..];
    if !is_reason(reason) {
        return Err(HttpError::InvalidStartLine);
    }

    let facts = scan_fields(head, fields)?;
    let bodiless = asked.head
        || (100..200).contains(&status)
        || status == 204
        || status == 304
        || (asked.connect && (200..300).contains(&status));
    let framing = if bodiless {
        BodyFraming::None
    } else {
        match transfer_framing(&facts, version)? {
            Some(f) => f,
            None => match facts.content_length {
                Some(n) if n > limits.max_body() => return Err(HttpError::BodyTooLarge),
                Some(0) => BodyFraming::None,
                Some(n) => BodyFraming::Length(n),
                None => BodyFraming::UntilClose,
            },
        }
    };
    let keep_alive = framing != BodyFraming::UntilClose
        && match version {
            Version::Http11 => !facts.close,
            Version::Http10 => facts.keep_alive && !facts.close,
        };
    Ok(ResponseInfo {
        status,
        start_line: start,
        reason: Span::new(base + reason_start, base + line.len()),
        version,
        framing,
        content_length: facts.content_length,
        keep_alive,
        upgrade_field: facts.upgrade_field,
    })
}

/// Iterator over a head's fields as `(name, value)` pairs, in arrival order.
///
/// Names are returned as received (field names are case-insensitive; compare
/// with `eq_ignore_ascii_case`). Values have surrounding whitespace removed
/// and may contain any byte RFC 9110 allows, including `obs-text` above
/// 0x7F, so they are bytes rather than `str`.
///
/// # Examples
///
/// ```
/// use http_net::{ServerConn, ServerEvent};
///
/// let mut conn = ServerConn::new();
/// let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nX-One: 1\r\n\r\n");
/// if let ServerEvent::Request(req) = conn.poll().unwrap() {
///     let names: Vec<&str> = req.headers().map(|(n, _)| n).collect();
///     assert_eq!(names, ["Host", "X-One"]);
/// }
/// ```
#[derive(Clone)]
pub struct Headers<'a> {
    head: &'a [u8],
    fields: slice::Iter<'a, Field>,
}

impl<'a> Headers<'a> {
    pub(crate) fn new(head: &'a [u8], fields: &'a [Field]) -> Self {
        Self {
            head,
            fields: fields.iter(),
        }
    }
}

impl<'a> Iterator for Headers<'a> {
    type Item = (&'a str, &'a [u8]);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let field = self.fields.next()?;
        Some((
            core::str::from_utf8(field.name.get(self.head)).unwrap_or(""),
            field.value.get(self.head),
        ))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.fields.size_hint()
    }
}

impl ExactSizeIterator for Headers<'_> {}

/// Shows the fields as `(name, value)` pairs; the values of credential
/// fields (`authorization`, `proxy-authorization`, `cookie`, `set-cookie`)
/// are replaced by `<redacted N bytes>`.
impl fmt::Debug for Headers<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let head = self.head;
        f.debug_list()
            .entries(self.fields.clone().map(|field| {
                let name = field.name.get(head);
                (
                    FieldName(name),
                    FieldValue {
                        name,
                        value: field.value.get(head),
                    },
                )
            }))
            .finish()
    }
}

/// Iterator over the values of every field with one name, in arrival
/// order: what [`RequestHead::header_all`] and
/// [`ResponseHead::header_all`] return. Each `Set-Cookie`, for example, is
/// its own field and its own item; nothing is comma-joined.
///
/// # Examples
///
/// ```
/// use http_net::{ServerConn, ServerEvent};
///
/// let mut conn = ServerConn::new();
/// let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nVia: 1.1 p1\r\nVia: 1.1 p2\r\n\r\n");
/// let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
/// let vias: Vec<&[u8]> = req.header_all("via").collect();
/// assert_eq!(vias, [&b"1.1 p1"[..], &b"1.1 p2"[..]]);
/// ```
///
/// The values borrow the head (`'a`), not the name (`'n`), so they outlive
/// a temporary name used for the lookup.
#[derive(Clone)]
pub struct HeaderValues<'a, 'n> {
    head: &'a [u8],
    fields: slice::Iter<'a, Field>,
    name: &'n [u8],
}

impl<'a> Iterator for HeaderValues<'a, '_> {
    type Item = &'a [u8];

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let (head, name) = (self.head, self.name);
        self.fields
            .find(|f| f.name.get(head).eq_ignore_ascii_case(name))
            .map(|f| f.value.get(head))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, self.fields.size_hint().1)
    }
}

impl fmt::Debug for HeaderValues<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name;
        f.debug_list()
            .entries(self.clone().map(|value| FieldValue { name, value }))
            .finish()
    }
}

/// Iterator over the elements of a list field (`#rule`) across every line
/// with one name: what [`RequestHead::header_list`],
/// [`ResponseHead::header_list`], and [`RequestHead::upgrade_protocols`]
/// return. Elements are trimmed of whitespace, empty ones are skipped, and
/// a comma inside a quoted string does not split an element.
///
/// # Examples
///
/// ```
/// use http_net::{ServerConn, ServerEvent};
///
/// let mut conn = ServerConn::new();
/// let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive, X-Trace\r\n\r\n");
/// let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
/// let options: Vec<&[u8]> = req.header_list("connection").collect();
/// assert_eq!(options, [&b"keep-alive"[..], b"X-Trace"]);
/// ```
#[derive(Clone)]
pub struct ListElements<'a, 'n> {
    head: &'a [u8],
    fields: slice::Iter<'a, Field>,
    name: &'n [u8],
    current: ListSplit<'a>,
    skip_h2c: bool,
}

impl<'a> Iterator for ListElements<'a, '_> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(e) = self.current.next() {
                if self.skip_h2c && is_h2c(e) {
                    continue;
                }
                return Some(e);
            }
            let (head, name) = (self.head, self.name);
            let field = self
                .fields
                .find(|f| f.name.get(head).eq_ignore_ascii_case(name))?;
            self.current = list_elements(field.value.get(head));
        }
    }
}

impl fmt::Debug for ListElements<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name;
        f.debug_list()
            .entries(self.clone().map(|value| FieldValue { name, value }))
            .finish()
    }
}

fn list_values<'a, 'n>(head: &'a [u8], fields: &'a [Field], name: &'n str) -> ListElements<'a, 'n> {
    ListElements {
        head,
        fields: fields.iter(),
        name: name.as_bytes(),
        current: list_elements(&[]),
        skip_h2c: false,
    }
}

fn find_header<'a>(head: &'a [u8], fields: &[Field], name: &str) -> Option<&'a [u8]> {
    fields
        .iter()
        .find(|f| f.name.get(head).eq_ignore_ascii_case(name.as_bytes()))
        .map(|f| f.value.get(head))
}

fn header_values<'a, 'n>(
    head: &'a [u8],
    fields: &'a [Field],
    name: &'n str,
) -> HeaderValues<'a, 'n> {
    HeaderValues {
        head,
        fields: fields.iter(),
        name: name.as_bytes(),
    }
}

/// A parsed request head, borrowed from the connection's buffer.
///
/// Every accessor is a slice of the bytes that arrived; nothing is copied.
/// The view stays valid until the next call that mutates the connection.
/// Read it again later with [`ServerConn::request`](crate::ServerConn::request).
///
/// # Examples
///
/// ```
/// use http_net::{Method, ServerConn, ServerEvent, Version};
///
/// let mut conn = ServerConn::new();
/// let _ = conn.feed(b"GET /search?q=rust HTTP/1.1\r\nHost: example.com\r\n\r\n");
/// let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
/// assert_eq!(req.method(), Method::Get);
/// assert_eq!(req.path(), "/search");
/// assert_eq!(req.query(), Some("q=rust"));
/// assert_eq!(req.version(), Version::Http11);
/// assert_eq!(req.host(), Some("example.com"));
/// assert!(req.keep_alive());
/// ```
#[derive(Clone, Copy)]
pub struct RequestHead<'a> {
    head: &'a [u8],
    fields: &'a [Field],
    info: &'a RequestInfo,
}

impl<'a> RequestHead<'a> {
    pub(crate) const fn new(head: &'a [u8], fields: &'a [Field], info: &'a RequestInfo) -> Self {
        Self { head, fields, info }
    }

    /// The bytes the spans index (the head, possibly followed by more
    /// input), the field records, and the interpreted facts.
    pub(crate) const fn parts(&self) -> (&'a [u8], &'a [Field], &'a RequestInfo) {
        (self.head, self.fields, self.info)
    }

    /// The method, classified.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{Method, ServerConn, ServerEvent};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"DELETE /x HTTP/1.1\r\nHost: a\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(req.method(), Method::Delete);
    /// ```
    #[must_use]
    pub fn method(&self) -> Method {
        self.info.method
    }

    /// The method exactly as received.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{Method, ServerConn, ServerEvent};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"PROPFIND /x HTTP/1.1\r\nHost: a\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(req.method(), Method::Other);
    /// assert_eq!(req.method_str(), "PROPFIND");
    /// ```
    #[must_use]
    pub fn method_str(&self) -> &'a str {
        core::str::from_utf8(self.info.method_span.get(self.head)).unwrap_or("")
    }

    /// The request target exactly as received (origin form `/path?query`,
    /// absolute form, authority form for `CONNECT`, or `*`).
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ServerConn, ServerEvent};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"GET /a%20b?x=1 HTTP/1.1\r\nHost: a\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(req.target(), "/a%20b?x=1");
    /// ```
    #[must_use]
    pub fn target(&self) -> &'a str {
        core::str::from_utf8(self.info.target.get(self.head)).unwrap_or("")
    }

    /// Which of the four RFC 9112 section 3.2 forms the target uses.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ServerConn, ServerEvent, TargetForm};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"GET http://a.test/x HTTP/1.1\r\nHost: a.test\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(req.target_form(), TargetForm::Absolute);
    /// ```
    #[must_use]
    pub fn target_form(&self) -> TargetForm {
        self.info.target_form
    }

    /// The path: the target up to (not including) the first `?`, with
    /// percent-encoding left as received.
    ///
    /// For an absolute-form target (`http://host/p?q`) this is the path
    /// after the authority (`/p`), and `/` when that path is empty, so a
    /// router sees the same path whichever form the client used. For `*`
    /// and for `CONNECT`'s authority form it is the whole target.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ServerConn, ServerEvent};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"GET /files/a.txt?v=2 HTTP/1.1\r\nHost: a\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(req.path(), "/files/a.txt");
    ///
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"GET http://a/files/b.txt HTTP/1.1\r\nHost: a\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(req.path(), "/files/b.txt");
    /// ```
    #[must_use]
    pub fn path(&self) -> &'a str {
        let origin = self.origin();
        let path = origin.split_once('?').map_or(origin, |(p, _)| p);
        if path.is_empty() && self.info.authority.is_some() {
            // RFC 9110 section 4.2.3: an empty path in an http URI is "/".
            "/"
        } else {
            path
        }
    }

    /// The query after the first `?`, if there is one.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ServerConn, ServerEvent};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(req.query(), None);
    /// ```
    #[must_use]
    pub fn query(&self) -> Option<&'a str> {
        self.origin().split_once('?').map(|(_, q)| q)
    }

    /// The path-and-query part of the target.
    fn origin(&self) -> &'a str {
        core::str::from_utf8(self.info.origin.get(self.head)).unwrap_or("")
    }

    /// The protocol version.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ServerConn, ServerEvent, Version};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"GET /x HTTP/1.0\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(req.version(), Version::Http10);
    /// ```
    #[must_use]
    pub fn version(&self) -> Version {
        self.info.version
    }

    /// All fields in arrival order.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ServerConn, ServerEvent};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"GET /x HTTP/1.1\r\nHost: a\r\nAccept: */*\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(req.headers().len(), 2);
    /// ```
    #[must_use]
    pub fn headers(&self) -> Headers<'a> {
        Headers {
            head: self.head,
            fields: self.fields.iter(),
        }
    }

    /// The value of the first field named `name` (ASCII case-insensitive).
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ServerConn, ServerEvent};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"GET /x HTTP/1.1\r\nHost: a\r\nAccept:  text/html \r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(req.header("accept"), Some(&b"text/html"[..]));
    /// assert_eq!(req.header("cookie"), None);
    /// ```
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&'a [u8]> {
        find_header(self.head, self.fields, name)
    }

    /// Like [`header`](Self::header), but only when the value is UTF-8.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ServerConn, ServerEvent};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"GET /x HTTP/1.1\r\nHost: a\r\nX: \xff\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(req.header_str("host"), Some("a"));
    /// assert_eq!(req.header_str("x"), None);
    /// ```
    #[must_use]
    pub fn header_str(&self, name: &str) -> Option<&'a str> {
        self.header(name).and_then(|v| core::str::from_utf8(v).ok())
    }

    /// The values of every field named `name` (ASCII case-insensitive), in
    /// arrival order: for fields that may be repeated, such as `via`,
    /// `forwarded`, or `cookie` from clients that send one line per cookie.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ServerConn, ServerEvent};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"GET /x HTTP/1.1\r\nHost: a\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// let cookies: Vec<&[u8]> = req.header_all("cookie").collect();
    /// assert_eq!(cookies, [&b"a=1"[..], &b"b=2"[..]]);
    /// assert_eq!(req.header_all("accept").count(), 0);
    ///
    /// // The values borrow the head, not the name.
    /// let first = {
    ///     let name = String::from("COOKIE");
    ///     req.header_all(&name).next()
    /// };
    /// assert_eq!(first, Some(&b"a=1"[..]));
    /// ```
    #[must_use]
    pub fn header_all<'n>(&self, name: &'n str) -> HeaderValues<'a, 'n> {
        header_values(self.head, self.fields, name)
    }

    /// The declared `Content-Length`, if the request has one. Unlike
    /// [`framing`](Self::framing), which reports `Content-Length: 0` as
    /// [`BodyFraming::None`], this tells `Some(0)` from an absent field.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{BodyFraming, ServerConn, ServerEvent};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(req.framing(), BodyFraming::None);
    /// assert_eq!(req.content_length(), Some(0));
    /// ```
    #[must_use]
    pub fn content_length(&self) -> Option<u64> {
        self.info.content_length
    }

    /// The authority the request is for (`host [":" port]`), if known.
    ///
    /// This is the `Host` field, except for an absolute-form target
    /// (`GET http://example.com/ HTTP/1.1`), whose authority wins: RFC 9112
    /// section 3.2.2 requires a server to ignore `Host` then, so the two can
    /// never be read differently. The raw field stays available through
    /// `header("host")`. HTTP/1.1 requests always carry a valid `Host`;
    /// HTTP/1.0 requests may not, and an empty `Host` (a target with no
    /// authority) is reported as `Some("")`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ServerConn, ServerEvent};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"GET /x HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(req.host(), Some("127.0.0.1:8080"));
    ///
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"GET http://a.test/x HTTP/1.1\r\nHost: b.test\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(req.host(), Some("a.test"));
    /// assert_eq!(req.header("host"), Some(&b"b.test"[..]));
    /// ```
    #[must_use]
    pub fn host(&self) -> Option<&'a str> {
        self.info
            .authority
            .or(self.info.host)
            .and_then(|s| core::str::from_utf8(s.get(self.head)).ok())
    }

    /// Whether the client sent `Expect: 100-continue` and is waiting for a
    /// `100 Continue` before sending the body. Only HTTP/1.1 requests that
    /// have a body report it (RFC 9110 section 10.1.1).
    ///
    /// Answer it before reading the body: either
    /// [`ServerConn::send_continue`](crate::ServerConn::send_continue), or a
    /// final response straight away (which closes the connection afterwards,
    /// since the body was not read). The blocking `Server` sends
    /// `100 Continue` itself.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ServerConn, ServerEvent};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"PUT /f HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 9\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// assert!(req.expects_continue());
    /// ```
    #[must_use]
    pub fn expects_continue(&self) -> bool {
        self.info.expect_continue
    }

    /// How the request body is delimited.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{BodyFraming, ServerConn, ServerEvent};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(req.framing(), BodyFraming::Chunked);
    /// ```
    #[must_use]
    pub fn framing(&self) -> BodyFraming {
        self.info.framing
    }

    /// Whether the client allows the connection to stay open after this
    /// exchange (HTTP/1.1 unless `Connection: close`; HTTP/1.0 only with
    /// `Connection: keep-alive`).
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ServerConn, ServerEvent};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"GET /x HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// assert!(!req.keep_alive());
    /// ```
    #[must_use]
    pub fn keep_alive(&self) -> bool {
        self.info.keep_alive
    }

    /// Whether this is an HTTP/1.1 request to switch protocols: `Connection`
    /// lists `upgrade` and an `Upgrade` field offers at least one protocol
    /// other than `h2c` (read the offer with `header("upgrade")`). Answer
    /// with [`Response::switching_protocols`](crate::Response::switching_protocols)
    /// naming an offered protocol to hand the connection over.
    ///
    /// `h2c` is never an offer: RFC 9113 section 3.1 deprecates the
    /// HTTP/2 upgrade, and a proxy that forwards it blindly is open to h2c
    /// smuggling. A request offering only `h2c` is served as HTTP/1.1.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ServerConn, ServerEvent};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// assert!(req.is_upgrade());
    /// assert_eq!(req.header("upgrade"), Some(&b"websocket"[..]));
    ///
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAoAAA\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// assert!(!req.is_upgrade());
    /// ```
    #[must_use]
    pub fn is_upgrade(&self) -> bool {
        self.info.upgrade
    }

    /// Whether the request carries an expectation other than
    /// `100-continue` (any `Expect` list element, any HTTP version), which
    /// a server may answer with `417 Expectation Failed` (RFC 9110 section
    /// 10.1.1). The core never answers it by itself; the blocking server
    /// does. The expectation never changes how the body is framed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ServerConn, ServerEvent};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"PUT /f HTTP/1.1\r\nHost: a\r\nExpect: 100-continue, x-fast\r\nContent-Length: 1\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// assert!(req.expects_continue());
    /// assert!(req.has_unknown_expectation());
    /// ```
    #[must_use]
    pub fn has_unknown_expectation(&self) -> bool {
        self.info.unknown_expectation
    }

    /// The protocols the request's `Upgrade` field offers, in order, as
    /// product tokens (`websocket`, `foo/2`), across every `Upgrade` line;
    /// `h2c` is left out (it is never an offer). Empty unless
    /// [`is_upgrade`](Self::is_upgrade).
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ServerConn, ServerEvent};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: h2c, websocket/13, irc\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// let offered: Vec<&[u8]> = req.upgrade_protocols().collect();
    /// assert_eq!(offered, [&b"websocket/13"[..], b"irc"]);
    /// ```
    #[must_use]
    pub fn upgrade_protocols(&self) -> ListElements<'a, 'static> {
        let mut list = list_values(self.head, self.fields, "upgrade");
        list.skip_h2c = true;
        if !self.info.upgrade {
            list.fields = [].iter();
        }
        list
    }

    /// The options the request's `Connection` field lists, across every
    /// `Connection` line, in order (`close`, `keep-alive`, `upgrade`, and the
    /// names of fields that are hop-by-hop for this message). Compare them
    /// ASCII case-insensitively. A proxy passes them to
    /// [`is_hop_by_hop`](crate::is_hop_by_hop).
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ServerConn, ServerEvent};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive, X-Trace\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// let options: Vec<&[u8]> = req.connection_options().collect();
    /// assert_eq!(options, [&b"keep-alive"[..], b"X-Trace"]);
    /// ```
    #[must_use]
    pub fn connection_options(&self) -> ListElements<'a, 'static> {
        list_values(self.head, self.fields, "connection")
    }

    /// The elements of a comma-separated list field (`#rule`, RFC 9110
    /// section 5.6.1) across every line with this name, in order, trimmed
    /// of whitespace, empty elements skipped. A comma inside a quoted
    /// string does not split an element.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ServerConn, ServerEvent};
    /// # let mut conn = ServerConn::new();
    /// # let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nAccept: text/html, ,\r\nAccept: x/y;q=\"0.5,1\"\r\n\r\n");
    /// # let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
    /// let accept: Vec<&[u8]> = req.header_list("accept").collect();
    /// assert_eq!(accept, [&b"text/html"[..], b"x/y;q=\"0.5,1\""]);
    /// ```
    #[must_use]
    pub fn header_list<'n>(&self, name: &'n str) -> ListElements<'a, 'n> {
        list_values(self.head, self.fields, name)
    }

    /// Whether the request's `Upgrade` field offers `protocol` (see
    /// [`Response::switching_protocols`](crate::Response::switching_protocols)).
    pub(crate) fn offers(&self, protocol: &[u8]) -> bool {
        self.info.upgrade
            && self
                .header_all("upgrade")
                .any(|v| list_elements(v).any(|e| protocol_matches(protocol, e)))
    }
}

/// Shows method, target, version, fields, and framing; the values of
/// credential fields are replaced by `<redacted N bytes>`.
impl fmt::Debug for RequestHead<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestHead")
            .field("method", &self.method_str())
            .field("target", &self.target())
            .field("version", &self.version())
            .field("headers", &self.headers())
            .field("framing", &self.framing())
            .finish()
    }
}

/// A parsed response head, borrowed from the client connection's buffer.
///
/// # Examples
///
/// ```
/// use http_net::{ClientConn, ClientEvent, Request};
///
/// let mut conn = ClientConn::new();
/// let mut out = Vec::new();
/// conn.send_request(&Request::get("/").header("host", "a"), &mut out).unwrap();
/// let _ = conn.feed(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
/// let ClientEvent::Response(resp) = conn.poll().unwrap() else { panic!() };
/// assert_eq!(resp.status(), 404);
/// assert_eq!(resp.reason(), "Not Found");
/// ```
#[derive(Clone, Copy)]
pub struct ResponseHead<'a> {
    head: &'a [u8],
    fields: &'a [Field],
    info: &'a ResponseInfo,
}

impl<'a> ResponseHead<'a> {
    pub(crate) const fn new(head: &'a [u8], fields: &'a [Field], info: &'a ResponseInfo) -> Self {
        Self { head, fields, info }
    }

    /// As [`RequestHead::parts`], for a response.
    pub(crate) const fn parts(&self) -> (&'a [u8], &'a [Field], &'a ResponseInfo) {
        (self.head, self.fields, self.info)
    }

    /// The status code (`100..=599`).
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ClientConn, ClientEvent, Request};
    /// # let mut conn = ClientConn::new();
    /// # conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new()).unwrap();
    /// # let _ = conn.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    /// # let ClientEvent::Response(resp) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(resp.status(), 200);
    /// ```
    #[must_use]
    pub fn status(&self) -> u16 {
        self.info.status
    }

    /// The reason phrase, if it is UTF-8 (it carries no meaning; RFC 9112
    /// tells clients to ignore it). Empty for a status line without one,
    /// including `HTTP/1.1 200` with no space after the code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ClientConn, ClientEvent, Request};
    /// # let mut conn = ClientConn::new();
    /// # conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new()).unwrap();
    /// # let _ = conn.feed(b"HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n");
    /// # let ClientEvent::Response(resp) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(resp.reason(), "");
    /// ```
    #[must_use]
    pub fn reason(&self) -> &'a str {
        core::str::from_utf8(self.info.reason.get(self.head)).unwrap_or("")
    }

    /// The protocol version.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ClientConn, ClientEvent, Request, Version};
    /// # let mut conn = ClientConn::new();
    /// # conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new()).unwrap();
    /// # let _ = conn.feed(b"HTTP/1.0 200 OK\r\n\r\n");
    /// # let ClientEvent::Response(resp) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(resp.version(), Version::Http10);
    /// ```
    #[must_use]
    pub fn version(&self) -> Version {
        self.info.version
    }

    /// All fields in arrival order.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ClientConn, ClientEvent, Request};
    /// # let mut conn = ClientConn::new();
    /// # conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new()).unwrap();
    /// # let _ = conn.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX: y\r\n\r\n");
    /// # let ClientEvent::Response(resp) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(resp.headers().count(), 2);
    /// ```
    #[must_use]
    pub fn headers(&self) -> Headers<'a> {
        Headers {
            head: self.head,
            fields: self.fields.iter(),
        }
    }

    /// The value of the first field named `name` (ASCII case-insensitive).
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ClientConn, ClientEvent, Request};
    /// # let mut conn = ClientConn::new();
    /// # conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new()).unwrap();
    /// # let _ = conn.feed(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n");
    /// # let ClientEvent::Response(resp) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(resp.header("content-type"), Some(&b"text/plain"[..]));
    /// ```
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&'a [u8]> {
        find_header(self.head, self.fields, name)
    }

    /// Like [`header`](Self::header), but only when the value is UTF-8.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ClientConn, ClientEvent, Request};
    /// # let mut conn = ClientConn::new();
    /// # conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new()).unwrap();
    /// # let _ = conn.feed(b"HTTP/1.1 200 OK\r\nServer: x\r\nContent-Length: 0\r\n\r\n");
    /// # let ClientEvent::Response(resp) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(resp.header_str("server"), Some("x"));
    /// ```
    #[must_use]
    pub fn header_str(&self, name: &str) -> Option<&'a str> {
        self.header(name).and_then(|v| core::str::from_utf8(v).ok())
    }

    /// The values of every field named `name`, in arrival order. Each
    /// `Set-Cookie` is its own field (they are never comma-joined), so
    /// this is how a client reads all of them.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ClientConn, ClientEvent, Request};
    /// # let mut conn = ClientConn::new();
    /// # conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new()).unwrap();
    /// # let _ = conn.feed(b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2; Path=/\r\nContent-Length: 0\r\n\r\n");
    /// # let ClientEvent::Response(resp) = conn.poll().unwrap() else { panic!() };
    /// let cookies: Vec<&[u8]> = resp.header_all("set-cookie").collect();
    /// assert_eq!(cookies, [&b"a=1"[..], &b"b=2; Path=/"[..]]);
    /// ```
    #[must_use]
    pub fn header_all<'n>(&self, name: &'n str) -> HeaderValues<'a, 'n> {
        header_values(self.head, self.fields, name)
    }

    /// The declared `Content-Length`, if the response has one, whatever the
    /// framing rules made of it (a `HEAD` response's length is reported
    /// here while [`framing`](Self::framing) is `None`).
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{BodyFraming, ClientConn, ClientEvent, Request};
    /// # let mut conn = ClientConn::new();
    /// # conn.send_request(&Request::head("/").header("host", "a"), &mut Vec::new()).unwrap();
    /// # let _ = conn.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n");
    /// # let ClientEvent::Response(resp) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(resp.framing(), BodyFraming::None);
    /// assert_eq!(resp.content_length(), Some(1234));
    /// ```
    #[must_use]
    pub fn content_length(&self) -> Option<u64> {
        self.info.content_length
    }

    /// The elements of a list field across every line with this name (see
    /// [`RequestHead::header_list`]).
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ClientConn, ClientEvent, Request};
    /// # let mut conn = ClientConn::new();
    /// # conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new()).unwrap();
    /// # let _ = conn.feed(b"HTTP/1.1 200 OK\r\nVary: accept\r\nVary: origin, cookie\r\nContent-Length: 0\r\n\r\n");
    /// # let ClientEvent::Response(resp) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(resp.header_list("vary").count(), 3);
    /// ```
    #[must_use]
    pub fn header_list<'n>(&self, name: &'n str) -> ListElements<'a, 'n> {
        list_values(self.head, self.fields, name)
    }

    /// Whether this is an interim (1xx) response head, as reported by
    /// [`ClientEvent::Informational`](crate::ClientEvent::Informational).
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ClientConn, ClientEvent, Request};
    /// # let mut conn = ClientConn::new();
    /// # conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new()).unwrap();
    /// # let _ = conn.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    /// # let ClientEvent::Response(resp) = conn.poll().unwrap() else { panic!() };
    /// assert!(!resp.is_informational());
    /// ```
    #[must_use]
    pub fn is_informational(&self) -> bool {
        (100..200).contains(&self.info.status)
    }

    /// How the response body is delimited (accounts for `HEAD` requests and
    /// bodiless status codes).
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{BodyFraming, ClientConn, ClientEvent, Request};
    /// # let mut conn = ClientConn::new();
    /// # conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new()).unwrap();
    /// # let _ = conn.feed(b"HTTP/1.1 200 OK\r\n\r\n");
    /// # let ClientEvent::Response(resp) = conn.poll().unwrap() else { panic!() };
    /// assert_eq!(resp.framing(), BodyFraming::UntilClose);
    /// ```
    #[must_use]
    pub fn framing(&self) -> BodyFraming {
        self.info.framing
    }

    /// Whether the connection can carry another request after this response.
    ///
    /// # Examples
    ///
    /// ```
    /// # use http_net::{ClientConn, ClientEvent, Request};
    /// # let mut conn = ClientConn::new();
    /// # conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new()).unwrap();
    /// # let _ = conn.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    /// # let ClientEvent::Response(resp) = conn.poll().unwrap() else { panic!() };
    /// assert!(resp.keep_alive());
    /// ```
    #[must_use]
    pub fn keep_alive(&self) -> bool {
        self.info.keep_alive
    }
}

/// Shows status, reason, version, fields, and framing; the values of
/// credential fields (`set-cookie` above all) are replaced by
/// `<redacted N bytes>`.
impl fmt::Debug for ResponseHead<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseHead")
            .field("status", &self.status())
            .field("reason", &self.reason())
            .field("version", &self.version())
            .field("headers", &self.headers())
            .field("framing", &self.framing())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    /// Lines built from the bytes that decide field parsing, at random.
    fn random_lines(count: usize) -> Vec<Vec<u8>> {
        const BYTES: &[u8] = b"aZ09-!~:: \t\r\n\x00\x7f\x80\xff\"(,";
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        // Mostly the shape a field line has (a name, a colon, a value), with
        // the deciding bytes mixed in now and then, so lines land on both
        // sides of what the fast path accepts.
        let mut pick = move |plain: &[u8]| {
            if next() % 12 == 0 {
                BYTES[(next() % BYTES.len() as u64) as usize]
            } else {
                plain[(next() % plain.len() as u64) as usize]
            }
        };
        (0..count)
            .map(|i| {
                let mut line = Vec::new();
                for _ in 0..(i % 9) {
                    line.push(pick(b"abcXYZ019-_.!~"));
                }
                line.push(pick(b":"));
                for _ in 0..(i % 23) {
                    line.push(pick(b"  abc XYZ 019 ,;=/\"()[]{}"));
                }
                if i % 5 != 0 {
                    line.extend_from_slice(b"\r\n");
                }
                line
            })
            .collect()
    }

    #[test]
    fn test_fast_field_agrees_with_the_general_path() {
        let mut fast = 0;
        for line in random_lines(300_000).into_iter().chain([
            b"Host: a\r\n".to_vec(),
            b"X:\r\n".to_vec(),
            b"X:   \r\n".to_vec(),
            b"X:  a  b  \r\n".to_vec(),
            b"X: a\tb\r\n".to_vec(),
            b"X: a\r".to_vec(),
            b"X: a\n".to_vec(),
            b" X: a\r\n".to_vec(),
            b"X : a\r\n".to_vec(),
            b"X: \x80\r\n".to_vec(),
            b"X: a\rb\r\n".to_vec(),
        ]) {
            let Some((field, next)) = fast_field(&line, 0) else {
                continue;
            };
            fast += 1;
            // The general path on the same line: the LF it finds, then the
            // field it parses.
            let lf = find_byte(b'\n', &line).expect("an accepted line has an LF");
            assert_eq!(next, lf + 1, "{line:?}");
            assert_eq!(line[lf - 1], b'\r', "{line:?}");
            assert_eq!(parse_field(&line[..lf - 1], 0), Ok(field), "{line:?}");
        }
        assert!(fast > 1_000, "the fast path accepted only {fast} lines");
    }

    #[test]
    fn test_scan_with_and_without_the_fast_path_agree_at_every_split() {
        // Whole input takes the fast path; one byte at a time cannot (a
        // line is never complete when its search starts), so it exercises
        // the general path. Both must report the same fields and errors.
        let heads: [&[u8]; 6] = [
            b"GET / HTTP/1.1\r\nHost: a\r\nX:  b  \r\nY:\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nX: a\tb\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nX: a\rb\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nX : b\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\n X: b\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nX: \x80\x81\r\n\r\n",
        ];
        let fields = |s: &HeadScanner| {
            s.fields
                .iter()
                .map(|f| (f.name, f.value))
                .collect::<Vec<_>>()
        };
        for head in heads {
            let mut whole = HeadScanner::new();
            let whole_result = whole.advance(head, &Limits::new(), HeadKind::Request, true);
            let mut split = HeadScanner::new();
            let mut split_result = Ok(Scan::Partial);
            for end in 1..=head.len() {
                split_result = split.advance(&head[..end], &Limits::new(), HeadKind::Request, true);
                if !matches!(split_result, Ok(Scan::Partial)) {
                    break;
                }
            }
            assert_eq!(whole_result, split_result, "{head:?}");
            assert_eq!(fields(&whole), fields(&split), "{head:?}");
        }
    }

    fn scan(msg: &[u8], kind: HeadKind) -> Result<(HeadScanner, usize), HttpError> {
        let mut s = HeadScanner::new();
        match s.advance(msg, &Limits::new(), kind, true)? {
            Scan::Done(n) => Ok((s, n)),
            Scan::Partial => Err(HttpError::UnexpectedEof),
        }
    }

    #[test]
    fn test_scanner_resumes_without_rescanning() {
        let msg = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        let mut s = HeadScanner::new();
        for end in 1..msg.len() {
            assert!(matches!(
                s.advance(&msg[..end], &Limits::new(), HeadKind::Request, true),
                Ok(Scan::Partial)
            ));
        }
        assert!(matches!(
            s.advance(msg, &Limits::new(), HeadKind::Request, true),
            Ok(Scan::Done(n)) if n == msg.len()
        ));
        assert_eq!(s.fields.len(), 1);
    }

    #[test]
    fn test_scanner_rejects_line_shapes() {
        let cases: &[(&[u8], HttpError)] = &[
            (b"GET / HTTP/1.1\nHost: a\r\n\r\n", HttpError::BareLf),
            (b"GET / HTTP/1.1\r\n Host: a\r\n\r\n", HttpError::ObsFold),
            (
                b"GET / HTTP/1.1\r\nHost : a\r\n\r\n",
                HttpError::WhitespaceBeforeColon,
            ),
            (
                b"GET / HTTP/1.1\r\nHost\r\n\r\n",
                HttpError::InvalidHeaderName,
            ),
            (
                b"GET / HTTP/1.1\r\n: a\r\n\r\n",
                HttpError::InvalidHeaderName,
            ),
            (b"GET / HTTP/1.1\r\nHo\rst: a\r\n\r\n", HttpError::BareCr),
            (b"GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n", HttpError::BareCr),
            (b"GET /\r HTTP/1.1\r\n\r\n", HttpError::BareCr),
            (
                b"GET / HTTP/1.1\r\nHost: a\x00\r\n\r\n",
                HttpError::InvalidHeaderValue,
            ),
        ];
        for (msg, err) in cases {
            assert_eq!(scan(msg, HeadKind::Request).err(), Some(*err), "{msg:?}");
        }
    }

    #[test]
    fn test_scanner_skips_leading_empty_lines_for_requests_only() {
        assert!(scan(b"\r\n\r\nGET / HTTP/1.1\r\n\r\n", HeadKind::Request).is_ok());
        assert_eq!(
            scan(b"\r\nHTTP/1.1 200 OK\r\n\r\n", HeadKind::Response).err(),
            Some(HttpError::InvalidStartLine)
        );
    }

    #[test]
    fn test_scanner_enforces_limits_at_boundaries() {
        let limits = Limits::new().with_max_start_line(16);
        // "GET / HTTP/1.1\r\n" is exactly 16 bytes.
        let mut s = HeadScanner::new();
        assert!(
            s.advance(b"GET / HTTP/1.1\r\n\r\n", &limits, HeadKind::Request, true)
                .is_ok()
        );
        let mut s = HeadScanner::new();
        assert_eq!(
            s.advance(b"GET /a HTTP/1.1\r\n\r\n", &limits, HeadKind::Request, true)
                .err(),
            Some(HttpError::StartLineTooLong)
        );
        // Partial input already at the budget fails without waiting for LF.
        let mut s = HeadScanner::new();
        assert_eq!(
            s.advance(b"GET /aaaaaaaaaaaa", &limits, HeadKind::Request, true)
                .err(),
            Some(HttpError::StartLineTooLong)
        );

        let limits = Limits::new().with_max_headers(1);
        let mut s = HeadScanner::new();
        assert_eq!(
            s.advance(
                b"GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\n\r\n",
                &limits,
                HeadKind::Request,
                true
            )
            .err(),
            Some(HttpError::TooManyHeaders)
        );

        // "A: 1\r\n" is 6 bytes; with 8 the final CRLF still fits.
        let limits = Limits::new().with_max_header_bytes(8);
        let mut s = HeadScanner::new();
        assert!(
            s.advance(
                b"GET / HTTP/1.1\r\nA: 1\r\n\r\n",
                &limits,
                HeadKind::Request,
                true
            )
            .is_ok()
        );
        let mut s = HeadScanner::new();
        assert_eq!(
            s.advance(
                b"GET / HTTP/1.1\r\nA: 12\r\nB: 1\r\n\r\n",
                &limits,
                HeadKind::Request,
                true
            )
            .err(),
            Some(HttpError::HeadersTooLarge)
        );
    }

    fn response(line: &[u8]) -> Result<ResponseInfo, HttpError> {
        let mut msg = line.to_vec();
        msg.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
        let (s, _) = scan(&msg, HeadKind::Response)?;
        interpret_response(
            &msg,
            s.start_line(),
            &s.fields,
            &Limits::new(),
            Asked {
                head: false,
                connect: false,
            },
        )
    }

    #[test]
    fn test_status_line_without_space_after_code_is_accepted() {
        let info = response(b"HTTP/1.1 200").unwrap();
        assert_eq!(info.status, 200);
        assert_eq!(info.reason, Span::new(12, 12));
        assert_eq!(response(b"HTTP/1.1 200 ").unwrap().status, 200);
        assert_eq!(response(b"HTTP/1.1 204 No Content").unwrap().status, 204);
        assert_eq!(
            response(b"HTTP/1.1 20").err(),
            Some(HttpError::InvalidStartLine)
        );
        assert_eq!(
            response(b"HTTP/1.1 2000").err(),
            Some(HttpError::InvalidStartLine)
        );
        assert_eq!(
            response(b"HTTP/1.1200 OK").err(),
            Some(HttpError::InvalidStartLine)
        );
        assert_eq!(
            response(b"HTTP/1.1 600").err(),
            Some(HttpError::InvalidStatus)
        );
    }

    #[test]
    fn test_protocol_matching_rules() {
        assert!(protocol_matches(b"websocket", b"websocket"));
        assert!(protocol_matches(b"WebSocket", b"websocket"));
        assert!(protocol_matches(b"websocket", b"websocket/13"));
        assert!(protocol_matches(b"foo/2", b"FOO/2"));
        assert!(!protocol_matches(b"foo/2", b"foo/3"));
        assert!(!protocol_matches(b"foo/2", b"foo"));
        assert!(!protocol_matches(b"ws", b"websocket"));
        assert!(!protocol_matches(b"h2c", b"h2c"));
        assert!(!protocol_matches(b"H2C", b"h2c"));
        assert!(is_h2c(b"h2c/1") && is_h2c(b"H2c") && !is_h2c(b"h2"));
    }

    #[test]
    fn test_authority_targets_refuse_empty_host_and_bad_escapes() {
        assert!(check_target(Method::Connect, b"a%41:443").is_ok());
        assert!(check_target(Method::Connect, b"a%4:443").is_err());
        assert!(check_target(Method::Get, b"http://a%zz/").is_err());
        assert!(check_target(Method::Get, b"http://a%41b/").is_ok());
        assert!(check_target(Method::Get, b"ftp://h/").is_ok());
    }

    #[test]
    fn test_versions() {
        assert_eq!(parse_version(b"HTTP/1.1"), Ok(Version::Http11));
        assert_eq!(parse_version(b"HTTP/1.0"), Ok(Version::Http10));
        assert_eq!(parse_version(b"HTTP/1.9"), Ok(Version::Http11));
        assert_eq!(
            parse_version(b"HTTP/2.0"),
            Err(HttpError::UnsupportedVersion)
        );
        assert_eq!(
            parse_version(b"HTTP/0.9"),
            Err(HttpError::UnsupportedVersion)
        );
        assert_eq!(parse_version(b"http/1.1"), Err(HttpError::InvalidVersion));
        assert_eq!(parse_version(b"HTTP/1.10"), Err(HttpError::InvalidVersion));
        assert_eq!(parse_version(b"HTTP/1"), Err(HttpError::InvalidVersion));
    }

    #[test]
    fn test_target_forms_follow_method() {
        assert!(check_target(Method::Get, b"/").is_ok());
        assert!(check_target(Method::Options, b"*").is_ok());
        assert!(check_target(Method::Get, b"*").is_err());
        assert!(check_target(Method::Connect, b"example.com:443").is_ok());
        assert!(check_target(Method::Connect, b"[::1]:443").is_ok());
        assert!(check_target(Method::Connect, b"example.com").is_err());
        assert!(check_target(Method::Connect, b"/").is_err());
        assert!(check_target(Method::Get, b"http://example.com/a?b").is_ok());
        assert!(check_target(Method::Get, b"http://[::1]:80/").is_ok());
        assert!(check_target(Method::Get, b"http://x").is_ok());
        assert!(check_target(Method::Get, b"http://x?q").is_ok());
        assert!(check_target(Method::Get, b"http://u@x/").is_err());
        assert!(check_target(Method::Get, b"http:x").is_err());
        assert!(check_target(Method::Get, b"http://:80/").is_err());
        assert!(check_target(Method::Get, b"http://x/[a]").is_err());
        assert!(check_target(Method::Connect, b":443").is_err());
        assert!(check_target(Method::Get, b"1http://x").is_err());
        assert!(check_target(Method::Get, b"example.com").is_err());
        assert!(check_target(Method::Get, b"").is_err());
    }
}
