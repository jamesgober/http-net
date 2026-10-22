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
    /// `OPTIONS`, authority-form outside `CONNECT`); or an absolute form
    /// without `//authority`, with userinfo, or with an empty host.
    InvalidTarget,
    /// The protocol version is not of the form `HTTP/DIGIT.DIGIT`.
    InvalidVersion,
    /// The version is well formed but not HTTP/1.0 or HTTP/1.1. Answer 505.
    UnsupportedVersion,
    /// The connection starts with the HTTP/2 connection preface
    /// (`PRI * HTTP/2.0`, RFC 9113 section 3.4): a client speaking HTTP/2
    /// with prior knowledge. Route the connection to an HTTP/2 engine if
    /// the listener allows prior knowledge; otherwise answer 505 and close.
    Http2Preface,
    /// A status code outside `100..=599`, or not three digits.
    InvalidStatus,
    /// The request line (or status line) exceeds
    /// [`Limits::max_start_line`](crate::Limits::max_start_line). Answer 414.
    StartLineTooLong,
    /// The header section exceeds
    /// [`Limits::max_header_bytes`](crate::Limits::max_header_bytes). Answer 431.
    HeadersTooLarge,
    /// More header fields than
    /// [`Limits::max_headers`](crate::Limits::max_headers), or more trailer
    /// fields than [`Limits::max_trailer_fields`](crate::Limits::max_trailer_fields).
    /// Answer 431.
    TooManyHeaders,
    /// One field line is longer than
    /// [`Limits::max_field_line`](crate::Limits::max_field_line). Answer 431.
    FieldLineTooLong,
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
    /// `host [":" port]`: also an empty host before a port (`:80`) and a
    /// `%` not followed by two hex digits.
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
    /// The client received more interim (1xx) responses to one request
    /// than [`Limits::max_interim`](crate::Limits::max_interim): a server
    /// that never sends its final response. Close the connection.
    TooManyInterim,
    /// An outgoing message tried to set a header the connection owns
    /// (`content-length`, `transfer-encoding`, `connection`, `upgrade`,
    /// `trailer`, `keep-alive`, `proxy-connection`, and `te` on a response);
    /// use the builder methods instead.
    ReservedHeader,
    /// A body was given for a status that cannot carry one (1xx, 204, 304).
    BodyNotAllowed,
    /// A streamed body's length differs from the `content_length` declared
    /// for it.
    BodyLengthMismatch,
    /// A `101 Switching Protocols` names a protocol the request's `Upgrade`
    /// field did not offer (RFC 9110 section 7.8: a server MUST NOT switch
    /// to it), or names `h2c`, whose upgrade RFC 9113 section 3.1
    /// deprecates. Also raised by `Request::upgrade("h2c")`. Answer with a
    /// protocol the client offered, or with a normal response.
    UpgradeNotOffered,
    /// An interim (1xx) response the connection may not send now: to an
    /// HTTP/1.0 request (RFC 9110 section 15.2 forbids it), after the final
    /// response started, or a `100 Continue` after the body began or twice.
    /// Skip the interim response.
    InterimNotAllowed,
    /// An outgoing trailer field that RFC 9110 section 6.5.1 keeps out of
    /// trailers (framing, routing, authentication, request modifiers,
    /// response control, content handling), or trailers on a body that is
    /// not chunked. Send the field in the header section instead.
    TrailerNotAllowed,
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
            Self::HeadersTooLarge | Self::TooManyHeaders | Self::FieldLineTooLong => Some(431),
            Self::BodyTooLarge => Some(413),
            Self::UnsupportedVersion | Self::Http2Preface => Some(505),
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
            | Self::TooManyInterim
            | Self::ReservedHeader
            | Self::BodyNotAllowed
            | Self::BodyLengthMismatch
            | Self::UpgradeNotOffered
            | Self::InterimNotAllowed
            | Self::TrailerNotAllowed
            | Self::InvalidState(_) => None,
        }
    }

    /// Whether parsing bytes from the peer can produce this error. After
    /// such an error from `poll`, the connection is finished: send at most
    /// one error response, then close.
    ///
    /// Some variants are also usage errors (for example
    /// [`InvalidTarget`](HttpError::InvalidTarget) comes from a bad request
    /// line or from `Request::new` with a bad target): the call that
    /// returned the error tells which it was, since `poll` returns only
    /// peer errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::HttpError;
    ///
    /// assert!(HttpError::ConflictingFraming.is_peer_error());
    /// assert!(!HttpError::ReservedHeader.is_peer_error());
    /// ```
    #[must_use]
    pub const fn is_peer_error(&self) -> bool {
        !matches!(
            self,
            Self::ReservedHeader
                | Self::BodyNotAllowed
                | Self::BodyLengthMismatch
                | Self::UpgradeNotOffered
                | Self::InterimNotAllowed
                | Self::TrailerNotAllowed
                | Self::InvalidState(_)
        )
    }

    /// Whether a caller mistake (builder misuse, a call in the wrong state)
    /// can produce this error. Such an error leaves the connection usable:
    /// nothing was written.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::HttpError;
    ///
    /// assert!(HttpError::ReservedHeader.is_usage_error());
    /// assert!(!HttpError::BareLf.is_usage_error());
    /// // Raised by parsing or by a builder: both.
    /// assert!(HttpError::InvalidTarget.is_peer_error() && HttpError::InvalidTarget.is_usage_error());
    /// ```
    #[must_use]
    pub const fn is_usage_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidMethod
                | Self::InvalidTarget
                | Self::InvalidStatus
                | Self::BareCr
                | Self::InvalidHeaderName
                | Self::InvalidHeaderValue
                | Self::MissingHost
                | Self::InvalidHost
                | Self::UnexpectedData
                | Self::ReservedHeader
                | Self::BodyNotAllowed
                | Self::BodyLengthMismatch
                | Self::UpgradeNotOffered
                | Self::InterimNotAllowed
                | Self::TrailerNotAllowed
                | Self::InvalidState(_)
        )
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
            Self::Http2Preface => {
                "HTTP/2 connection preface on an HTTP/1.1 connection: route it to an HTTP/2 \
                 engine or answer 505"
            }
            Self::InvalidStatus => "invalid status code: expected three digits in 100..=599",
            Self::StartLineTooLong => "start line exceeds the configured limit",
            Self::HeadersTooLarge => "header section exceeds the configured byte limit",
            Self::TooManyHeaders => "more header fields than the configured limit",
            Self::FieldLineTooLong => "a field line exceeds the configured limit",
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
            Self::TooManyInterim => "more interim responses than the configured limit",
            Self::ReservedHeader => {
                "header is managed by the connection; use the builder method instead"
            }
            Self::BodyNotAllowed => "this status code cannot carry a body",
            Self::BodyLengthMismatch => "streamed body length differs from the declared length",
            Self::InterimNotAllowed => {
                "interim response not allowed now (HTTP/1.0 peer, after the final response,                  or 100 Continue after the body began)"
            }
            Self::TrailerNotAllowed => {
                "field not allowed in trailers, or trailers on a body that is not chunked"
            }
            Self::UpgradeNotOffered => {
                "101 names a protocol the request did not offer (or h2c); \
                 answer with an offered protocol or a normal response"
            }
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

    /// Every variant, so the category and text tests cannot miss one.
    const ALL: &[HttpError] = &[
        HttpError::InvalidStartLine,
        HttpError::InvalidMethod,
        HttpError::InvalidTarget,
        HttpError::InvalidVersion,
        HttpError::UnsupportedVersion,
        HttpError::Http2Preface,
        HttpError::InvalidStatus,
        HttpError::StartLineTooLong,
        HttpError::HeadersTooLarge,
        HttpError::TooManyHeaders,
        HttpError::FieldLineTooLong,
        HttpError::BareCr,
        HttpError::BareLf,
        HttpError::ObsFold,
        HttpError::InvalidHeaderName,
        HttpError::WhitespaceBeforeColon,
        HttpError::InvalidHeaderValue,
        HttpError::MissingHost,
        HttpError::InvalidHost,
        HttpError::InvalidContentLength,
        HttpError::DuplicateContentLength,
        HttpError::ConflictingFraming,
        HttpError::InvalidTransferEncoding,
        HttpError::UnsupportedTransferEncoding,
        HttpError::TransferEncodingInHttp10,
        HttpError::InvalidChunkSize,
        HttpError::InvalidChunkExtension,
        HttpError::InvalidChunkTerminator,
        HttpError::ChunkLineTooLong,
        HttpError::ChunkExtensionsTooLarge,
        HttpError::BodyTooLarge,
        HttpError::UnexpectedEof,
        HttpError::UnexpectedData,
        HttpError::UnexpectedUpgrade,
        HttpError::TooManyInterim,
        HttpError::ReservedHeader,
        HttpError::BodyNotAllowed,
        HttpError::BodyLengthMismatch,
        HttpError::UpgradeNotOffered,
        HttpError::InterimNotAllowed,
        HttpError::TrailerNotAllowed,
        HttpError::InvalidState("rule"),
    ];

    #[test]
    fn test_every_variant_has_a_category() {
        for e in ALL {
            assert!(e.is_peer_error() || e.is_usage_error(), "{e:?}");
            // A usage-only error never maps to a status: it is not about a request.
            if !e.is_peer_error() {
                assert_eq!(e.status(), None, "{e:?}");
            }
        }
        assert!(HttpError::UpgradeNotOffered.is_usage_error());
        assert!(!HttpError::UpgradeNotOffered.is_peer_error());
        assert!(HttpError::BareLf.is_peer_error() && !HttpError::BareLf.is_usage_error());
    }

    /// Threat T-37: error text is static and never reflects input bytes.
    #[test]
    fn test_display_every_variant_is_static_ascii_text() {
        for e in ALL {
            let text = e.to_string();
            assert!(!text.is_empty(), "{e:?}");
            assert!(
                text.bytes().all(|b| b.is_ascii_graphic() || b == b' '),
                "{e:?}: {text}"
            );
        }
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
