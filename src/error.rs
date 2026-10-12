//! The crate-wide error type.

use core::fmt;

/// Why a message was refused, or why a call was out of order.
///
/// Parse errors are final for the connection: HTTP/1.1 framing cannot be
/// resynchronised after a malformed message without risking request
/// smuggling, so after any parse error the connection must be closed. A
/// server should first answer with [`status`](HttpError::status) (for
/// example through [`ServerConn::respond`](crate::ServerConn::respond),
/// which still accepts one response after a parse error and marks it
/// `connection: close`).
///
/// Builder errors ([`ReservedHeader`](HttpError::ReservedHeader),
/// [`InvalidHeaderName`](HttpError::InvalidHeaderName) on an outgoing message,
/// and so on) and [`InvalidState`](HttpError::InvalidState) are programming
/// errors on the caller's side and leave the connection usable.
///
/// # Examples
///
/// ```
/// use http_net::{HttpError, ServerConn, ServerEvent};
///
/// let mut conn = ServerConn::new();
/// let n = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n");
/// assert!(n > 0);
/// let err = conn.poll().unwrap_err();
/// assert_eq!(err, HttpError::ConflictingFraming);
/// assert_eq!(err.status(), Some(400));
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HttpError {
    /// The request line or status line does not have the shape
    /// `method SP target SP version` / `version SP code SP reason`.
    InvalidStartLine,
    /// The method is not a token.
    InvalidMethod,
    /// The request target contains characters outside RFC 3986, a bad
    /// percent-encoding, or a form the method does not allow (`*` outside
    /// `OPTIONS`, authority-form outside `CONNECT`).
    InvalidTarget,
    /// The protocol version is not of the form `HTTP/DIGIT.DIGIT`.
    InvalidVersion,
    /// The version is well formed but not HTTP/1.0 or HTTP/1.1. Answer 505.
    UnsupportedVersion,
    /// A status code outside `100..=599`, or not three digits.
    InvalidStatus,
    /// The request line (or status line) exceeds
    /// [`Limits::max_start_line`](crate::Limits::max_start_line). Answer 414.
    StartLineTooLong,
    /// The header section exceeds
    /// [`Limits::max_header_bytes`](crate::Limits::max_header_bytes). Answer 431.
    HeadersTooLarge,
    /// More header (or trailer) fields than
    /// [`Limits::max_headers`](crate::Limits::max_headers). Answer 431.
    TooManyHeaders,
    /// A carriage return that is not followed by a line feed. Refused because
    /// recipients disagree on what it means, which is a smuggling vector.
    BareCr,
    /// A line feed not preceded by a carriage return. RFC 9112 permits
    /// accepting it; this crate refuses it so that every hop agrees on where
    /// lines end.
    BareLf,
    /// A field line begins with whitespace: obsolete line folding, or
    /// whitespace between the start line and the first field.
    ObsFold,
    /// A field name is empty, contains a non-token character, or the line
    /// has no colon.
    InvalidHeaderName,
    /// Whitespace between a field name and its colon (RFC 9112 section 5.1
    /// requires rejecting it).
    WhitespaceBeforeColon,
    /// A field value contains a control character other than horizontal tab.
    InvalidHeaderValue,
    /// An HTTP/1.1 request without a `Host` field.
    MissingHost,
    /// More than one `Host` field, or a `Host` value that is not
    /// `host [":" port]`.
    InvalidHost,
    /// `Content-Length` is not a plain decimal number that fits in 64 bits
    /// (signs, lists, spaces, and empty values are all refused).
    InvalidContentLength,
    /// `Content-Length` appears more than once. Refused even when the values
    /// agree, so no intermediary can pick a different one.
    DuplicateContentLength,
    /// Both `Content-Length` and `Transfer-Encoding` are present: the classic
    /// request smuggling vector, refused outright.
    ConflictingFraming,
    /// `Transfer-Encoding` is empty, repeats `chunked`, or does not end in
    /// `chunked`.
    InvalidTransferEncoding,
    /// A transfer coding other than `chunked` (for example `gzip`). Answer 501.
    UnsupportedTransferEncoding,
    /// `Transfer-Encoding` in an HTTP/1.0 message, whose framing is then
    /// faulty by RFC 9112 section 6.1.
    TransferEncodingInHttp10,
    /// A chunk-size line is not hexadecimal, or overflows 64 bits.
    InvalidChunkSize,
    /// A chunk extension does not follow the `;name[=value]` grammar.
    InvalidChunkExtension,
    /// Chunk data is not followed by CRLF.
    InvalidChunkTerminator,
    /// A chunk-size line is longer than
    /// [`Limits::max_start_line`](crate::Limits::max_start_line).
    ChunkLineTooLong,
    /// The chunk extensions of one message add up to more than
    /// [`Limits::max_header_bytes`](crate::Limits::max_header_bytes). Each
    /// line is short, but without a total a peer could make a small body
    /// cost an unbounded amount of input (the CVE-2024-22019 pattern).
    ChunkExtensionsTooLarge,
    /// The body exceeds [`Limits::max_body`](crate::Limits::max_body), detected
    /// from the declared length before any of it is buffered. Answer 413.
    BodyTooLarge,
    /// The peer closed the connection in the middle of a message.
    UnexpectedEof,
    /// Bytes arrived when no message was expected: a response with no
    /// request outstanding, or data after the connection finished.
    UnexpectedData,
    /// A `101 Switching Protocols` (or a 2xx to `CONNECT`) arrived for a
    /// request that did not ask to switch.
    UnexpectedUpgrade,
    /// An outgoing message tried to set a header the connection owns
    /// (`content-length`, `transfer-encoding`, `connection`, `upgrade`); use
    /// the builder methods instead.
    ReservedHeader,
    /// A body was given for a status that cannot carry one (1xx, 204, 304).
    BodyNotAllowed,
    /// A streamed body's length differs from the `content_length` declared
    /// for it.
    BodyLengthMismatch,
    /// A call made in the wrong state, for example `respond` twice for one
    /// request. The text names the rule that was broken.
    InvalidState(&'static str),
}

impl HttpError {
    /// The status code a server should answer with when this error came from
    /// parsing a request, or `None` for errors that are not about a request
    /// (response parsing, builder misuse, connection state).
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::HttpError;
    ///
    /// assert_eq!(HttpError::BodyTooLarge.status(), Some(413));
    /// assert_eq!(HttpError::TooManyHeaders.status(), Some(431));
    /// assert_eq!(HttpError::InvalidState("x").status(), None);
    /// ```
    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        match self {
            Self::StartLineTooLong => Some(414),
            Self::HeadersTooLarge | Self::TooManyHeaders => Some(431),
            Self::BodyTooLarge => Some(413),
            Self::UnsupportedVersion => Some(505),
            Self::UnsupportedTransferEncoding => Some(501),
            Self::InvalidStartLine
            | Self::InvalidMethod
            | Self::InvalidTarget
            | Self::InvalidVersion
            | Self::BareCr
            | Self::BareLf
            | Self::ObsFold
            | Self::InvalidHeaderName
            | Self::WhitespaceBeforeColon
            | Self::InvalidHeaderValue
            | Self::MissingHost
            | Self::InvalidHost
            | Self::InvalidContentLength
            | Self::DuplicateContentLength
            | Self::ConflictingFraming
            | Self::InvalidTransferEncoding
            | Self::TransferEncodingInHttp10
            | Self::InvalidChunkSize
            | Self::InvalidChunkExtension
            | Self::InvalidChunkTerminator
            | Self::ChunkLineTooLong
            | Self::ChunkExtensionsTooLarge => Some(400),
            Self::InvalidStatus
            | Self::UnexpectedEof
            | Self::UnexpectedData
            | Self::UnexpectedUpgrade
            | Self::ReservedHeader
            | Self::BodyNotAllowed
            | Self::BodyLengthMismatch
            | Self::InvalidState(_) => None,
        }
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InvalidStartLine => "malformed start line: expected three space-separated parts",
            Self::InvalidMethod => "invalid method: must be a token",
            Self::InvalidTarget => "invalid request target",
            Self::InvalidVersion => "invalid HTTP version: expected HTTP/DIGIT.DIGIT",
            Self::UnsupportedVersion => "unsupported HTTP version: only HTTP/1.0 and HTTP/1.1",
            Self::InvalidStatus => "invalid status code: expected three digits in 100..=599",
            Self::StartLineTooLong => "start line exceeds the configured limit",
            Self::HeadersTooLarge => "header section exceeds the configured byte limit",
            Self::TooManyHeaders => "more header fields than the configured limit",
            Self::BareCr => "carriage return not followed by line feed",
            Self::BareLf => "line feed not preceded by carriage return",
            Self::ObsFold => "field line starts with whitespace (obsolete line folding)",
            Self::InvalidHeaderName => "invalid field name or missing colon",
            Self::WhitespaceBeforeColon => "whitespace between field name and colon",
            Self::InvalidHeaderValue => "control character in field value",
            Self::MissingHost => "HTTP/1.1 request without a Host field",
            Self::InvalidHost => "duplicate or malformed Host field",
            Self::InvalidContentLength => "Content-Length is not a single decimal number",
            Self::DuplicateContentLength => "Content-Length appears more than once",
            Self::ConflictingFraming => "both Content-Length and Transfer-Encoding are present",
            Self::InvalidTransferEncoding => "Transfer-Encoding must end in a single chunked",
            Self::UnsupportedTransferEncoding => "transfer coding other than chunked",
            Self::TransferEncodingInHttp10 => "Transfer-Encoding in an HTTP/1.0 message",
            Self::InvalidChunkSize => "invalid chunk size",
            Self::InvalidChunkExtension => "invalid chunk extension",
            Self::InvalidChunkTerminator => "chunk data not followed by CRLF",
            Self::ChunkLineTooLong => "chunk-size line exceeds the configured limit",
            Self::ChunkExtensionsTooLarge => {
                "chunk extensions exceed the header byte limit for the message"
            }
            Self::BodyTooLarge => "body exceeds the configured limit",
            Self::UnexpectedEof => "connection closed in the middle of a message",
            Self::UnexpectedData => "data received when no message was expected",
            Self::UnexpectedUpgrade => "protocol switch that the request did not ask for",
            Self::ReservedHeader => {
                "header is managed by the connection; use the builder method instead"
            }
            Self::BodyNotAllowed => "this status code cannot carry a body",
            Self::BodyLengthMismatch => "streamed body length differs from the declared length",
            Self::InvalidState(rule) => return write!(f, "invalid call order: {rule}"),
        };
        f.write_str(msg)
    }
}

impl core::error::Error for HttpError {}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn test_status_mapping_covers_request_errors() {
        assert_eq!(HttpError::StartLineTooLong.status(), Some(414));
        assert_eq!(HttpError::UnsupportedVersion.status(), Some(505));
        assert_eq!(HttpError::UnsupportedTransferEncoding.status(), Some(501));
        assert_eq!(HttpError::BareCr.status(), Some(400));
        assert_eq!(HttpError::UnexpectedEof.status(), None);
    }

    #[test]
    fn test_display_is_actionable() {
        assert_eq!(
            HttpError::InvalidState("respond called twice").to_string(),
            "invalid call order: respond called twice"
        );
        assert!(
            HttpError::ConflictingFraming
                .to_string()
                .contains("Content-Length")
        );
    }
}
