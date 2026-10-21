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
        check_field_value, find_byte, is_host_value, is_ows, is_reason, is_target_chars, is_tchar,
        is_token, list_elements, parse_decimal, trim_ows,
    },
};

/// An offset range into a message head.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Span {
    start: u32,
    end: u32,
}

impl Span {
    #[inline]
    fn new(start: usize, end: usize) -> Self {
        // Offsets are bounded by the buffer capacity, which `Limits` keeps
        // far below `u32::MAX`.
        Self {
            start: start as u32,
            end: end as u32,
        }
    }

    #[inline]
    pub(crate) fn get<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        buf.get(self.start as usize..self.end as usize)
            .unwrap_or(&[])
    }
}

/// One field line: name and (OWS-trimmed) value.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Field {
    name: Span,
    value: Span,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeadKind {
    Request,
    Response,
    Trailer,
}

pub(crate) enum Progress {
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
/// section (field lines only).
pub(crate) struct HeadScanner {
    scan: usize,
    line_start: usize,
    start_line: Option<Span>,
    skipped: usize,
    field_bytes: usize,
    count: usize,
    pub(crate) fields: Vec<Field>,
}

impl HeadScanner {
    pub(crate) const fn new() -> Self {
        Self {
            scan: 0,
            line_start: 0,
            start_line: None,
            skipped: 0,
            field_bytes: 0,
            count: 0,
            fields: Vec::new(),
        }
    }

    /// Prepares for the next message; keeps the field vector's allocation.
    pub(crate) fn reset(&mut self) {
        self.scan = 0;
        self.line_start = 0;
        self.start_line = None;
        self.skipped = 0;
        self.field_bytes = 0;
        self.count = 0;
        self.fields.clear();
    }

    /// Resets only the line state, for a trailer section, keeping the head's
    /// stored fields readable.
    pub(crate) fn reset_lines(&mut self) {
        self.scan = 0;
        self.line_start = 0;
        self.skipped = 0;
        self.field_bytes = 0;
        self.count = 0;
    }

    pub(crate) fn start_line(&self) -> Span {
        self.start_line.unwrap_or_default()
    }

    /// Scans `msg` (the bytes from the message start to the end of input).
    pub(crate) fn advance(
        &mut self,
        msg: &[u8],
        limits: &Limits,
        kind: HeadKind,
        store: bool,
    ) -> Result<Progress, HttpError> {
        loop {
            let in_start = kind != HeadKind::Trailer && self.start_line.is_none();
            let (budget, too_long) = if in_start {
                (
                    limits.max_start_line().saturating_sub(self.skipped),
                    HttpError::StartLineTooLong,
                )
            } else {
                (
                    limits.max_header_bytes().saturating_sub(self.field_bytes),
                    HttpError::HeadersTooLarge,
                )
            };
            let Some(end) = find_line(msg, self.line_start, &mut self.scan, budget, too_long)?
            else {
                return Ok(Progress::Partial);
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
                return Ok(Progress::Done(self.scan));
            }
            self.field_bytes += line_len;
            // Every field line must leave room for the blank line that ends
            // the section, so the section as a whole fits the budget.
            if self.field_bytes + 2 > limits.max_header_bytes() {
                return Err(HttpError::HeadersTooLarge);
            }
            if self.count >= limits.max_headers() {
                return Err(HttpError::TooManyHeaders);
            }
            let field = parse_field(line, start)?;
            self.count += 1;
            if store {
                self.fields.push(field);
            }
        }
    }
}

/// Validates one field line (`line` starts at offset `base` in the head).
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

fn parse_version(v: &[u8]) -> Result<Version, HttpError> {
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
            facts.expect_continue |=
                list_elements(value).any(|e| e.eq_ignore_ascii_case(b"100-continue"));
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

/// Everything learned from a request head.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RequestInfo {
    pub(crate) method: Method,
    method_span: Span,
    target: Span,
    target_form: TargetForm,
    pub(crate) version: Version,
    pub(crate) framing: BodyFraming,
    content_length: Option<u64>,
    pub(crate) keep_alive: bool,
    pub(crate) upgrade: bool,
    pub(crate) expect_continue: bool,
    host: Option<Span>,
    /// The authority of an absolute-form target, which replaces `Host`.
    authority: Option<Span>,
    /// The path-and-query part of the target: the whole target except for
    /// the absolute form, where it is what follows the authority.
    origin: Span,
}

impl RequestInfo {
    pub(crate) const EMPTY: Self = Self {
        method: Method::Get,
        method_span: Span { start: 0, end: 0 },
        target: Span { start: 0, end: 0 },
        target_form: TargetForm::Origin,
        version: Version::Http11,
        framing: BodyFraming::None,
        content_length: None,
        keep_alive: false,
        upgrade: false,
        expect_continue: false,
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
#[derive(Clone, Copy, Debug)]
pub(crate) struct ResponseInfo {
    pub(crate) status: u16,
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
        reason: Span { start: 0, end: 0 },
        version: Version::Http11,
        framing: BodyFraming::None,
        content_length: None,
        keep_alive: false,
        upgrade_field: false,
    };
}

/// What the client asked for, which decides how the response is framed.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Asked {
    pub(crate) head: bool,
    pub(crate) connect: bool,
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
    use super::*;

    fn scan(msg: &[u8], kind: HeadKind) -> Result<(HeadScanner, usize), HttpError> {
        let mut s = HeadScanner::new();
        match s.advance(msg, &Limits::new(), kind, true)? {
            Progress::Done(n) => Ok((s, n)),
            Progress::Partial => Err(HttpError::UnexpectedEof),
        }
    }

    #[test]
    fn test_scanner_resumes_without_rescanning() {
        let msg = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        let mut s = HeadScanner::new();
        for end in 1..msg.len() {
            assert!(matches!(
                s.advance(&msg[..end], &Limits::new(), HeadKind::Request, true),
                Ok(Progress::Partial)
            ));
        }
        assert!(matches!(
            s.advance(msg, &Limits::new(), HeadKind::Request, true),
            Ok(Progress::Done(n)) if n == msg.len()
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
