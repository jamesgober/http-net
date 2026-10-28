//! Budgets that bound what a peer can make a connection buffer or accept.

/// Upper bound for the start-line and header-section budgets. Keeps every
/// buffer offset inside `u32` and every buffer allocation sane.
const HARD_CAP: usize = 16 * 1024 * 1024;

/// Bytes of buffer space, beyond the head budget, used to stream body data.
const BODY_WINDOW: usize = 16 * 1024;

/// The budgets a connection enforces on incoming messages.
///
/// Every limit is checked **before** the bytes it governs are buffered or
/// allocated: a declared `Content-Length` above [`max_body`](Limits::max_body)
/// is refused on the header line, a chunk size is checked against the
/// remaining body budget before its data is read, and the connection's input
/// buffer can never grow past [`buffer_capacity`](Limits::buffer_capacity):
/// `head + max(head, max_trailer_bytes) + 16 KiB`, where
/// `head = max_start_line + max_header_bytes` (64 KiB with the defaults):
/// room for a pinned head plus one partial chunk line or trailer section.
///
/// The defaults are the budgets of LexerSketch Studio's localhost server:
///
/// | Budget | Default |
/// |---|---|
/// | request line / status line / chunk-size line | 8 KiB |
/// | header section (all field lines) | 16 KiB |
/// | one field line (headers and trailers) | 8 KiB |
/// | header fields | 100 |
/// | trailer section, trailer fields | the header budgets |
/// | interim (1xx) responses per request (client) | 16 |
/// | body | 1 MiB |
/// | requests outstanding at once (client pipelining) | 1, clamped to `1..=32` |
///
/// # Examples
///
/// ```
/// use http_net::Limits;
///
/// let limits = Limits::new().with_max_body(64 * 1024).with_max_headers(32);
/// assert_eq!(limits.max_body(), 64 * 1024);
/// assert_eq!(limits.max_headers(), 32);
/// assert_eq!(limits.max_start_line(), 8 * 1024);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Limits {
    start_line: usize,
    header_bytes: usize,
    headers: usize,
    field_line: usize,
    /// `None`: the same as the header budget.
    trailer_bytes: Option<usize>,
    /// `None`: the same as the header count.
    trailer_fields: Option<usize>,
    interim: u16,
    pipeline_depth: u8,
    body: u64,
}

/// The most requests a client may have outstanding at once.
pub(crate) const MAX_PIPELINE_DEPTH: u8 = 32;

impl Default for Limits {
    fn default() -> Self {
        Self::new()
    }
}

impl Limits {
    /// The default budgets (see the table on [`Limits`]).
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Limits::new(), http_net::Limits::default());
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            start_line: 8 * 1024,
            header_bytes: 16 * 1024,
            headers: 100,
            field_line: 8 * 1024,
            trailer_bytes: None,
            trailer_fields: None,
            interim: 16,
            pipeline_depth: 1,
            body: 1024 * 1024,
        }
    }

    /// Sets the longest accepted request line, status line, or chunk-size
    /// line, in bytes including the CRLF. Clamped to `16..=16 MiB`.
    ///
    /// # Examples
    ///
    /// ```
    /// let l = http_net::Limits::new().with_max_start_line(1);
    /// assert_eq!(l.max_start_line(), 16);
    /// ```
    #[must_use]
    pub const fn with_max_start_line(mut self, bytes: usize) -> Self {
        self.start_line = clamp(bytes, 16, HARD_CAP);
        self
    }

    /// Sets the largest accepted header section (every field line plus the
    /// blank line that ends it), in bytes. Clamped to `2..=16 MiB`.
    ///
    /// # Examples
    ///
    /// ```
    /// let l = http_net::Limits::new().with_max_header_bytes(4096);
    /// assert_eq!(l.max_header_bytes(), 4096);
    /// ```
    #[must_use]
    pub const fn with_max_header_bytes(mut self, bytes: usize) -> Self {
        self.header_bytes = clamp(bytes, 2, HARD_CAP);
        self
    }

    /// Sets the most header fields accepted in one message (trailer fields
    /// are counted against the same number separately). Clamped to
    /// `0..=65536`.
    ///
    /// # Examples
    ///
    /// ```
    /// let l = http_net::Limits::new().with_max_headers(8);
    /// assert_eq!(l.max_headers(), 8);
    /// ```
    #[must_use]
    pub const fn with_max_headers(mut self, count: usize) -> Self {
        self.headers = clamp(count, 0, 65_536);
        self
    }

    /// Sets the longest accepted single field line (name, colon, value, and
    /// CRLF), in headers and trailers alike. Clamped to `4..=16 MiB`. A line
    /// over it is [`HttpError::FieldLineTooLong`](crate::HttpError::FieldLineTooLong)
    /// (431), checked before the rest of the line is buffered. The whole
    /// section is still bounded by
    /// [`max_header_bytes`](Self::max_header_bytes).
    ///
    /// # Examples
    ///
    /// ```
    /// let l = http_net::Limits::new().with_max_field_line(1024);
    /// assert_eq!(l.max_field_line(), 1024);
    /// ```
    #[must_use]
    pub const fn with_max_field_line(mut self, bytes: usize) -> Self {
        self.field_line = clamp(bytes, 4, HARD_CAP);
        self
    }

    /// Sets the largest accepted trailer section, in bytes (every trailer
    /// field line plus the blank line that ends it). Clamped to
    /// `2..=16 MiB`. Until it is set it follows
    /// [`max_header_bytes`](Self::max_header_bytes).
    ///
    /// # Examples
    ///
    /// ```
    /// let l = http_net::Limits::new().with_max_trailer_bytes(512);
    /// assert_eq!(l.max_trailer_bytes(), 512);
    /// assert_eq!(http_net::Limits::new().max_trailer_bytes(), 16 * 1024);
    /// ```
    #[must_use]
    pub const fn with_max_trailer_bytes(mut self, bytes: usize) -> Self {
        self.trailer_bytes = Some(clamp(bytes, 2, HARD_CAP));
        self
    }

    /// Sets the most trailer fields accepted in one message. Clamped to
    /// `0..=65536`. Until it is set it follows
    /// [`max_headers`](Self::max_headers).
    ///
    /// # Examples
    ///
    /// ```
    /// let l = http_net::Limits::new().with_max_trailer_fields(4);
    /// assert_eq!(l.max_trailer_fields(), 4);
    /// ```
    #[must_use]
    pub const fn with_max_trailer_fields(mut self, count: usize) -> Self {
        self.trailer_fields = Some(clamp(count, 0, 65_536));
        self
    }

    /// Sets the most interim (1xx) responses a client accepts before the
    /// final response to one request; one more is
    /// [`HttpError::TooManyInterim`](crate::HttpError::TooManyInterim). The
    /// interim heads together also count against
    /// [`max_header_bytes`](Self::max_header_bytes).
    ///
    /// # Examples
    ///
    /// ```
    /// let l = http_net::Limits::new().with_max_interim(2);
    /// assert_eq!(l.max_interim(), 2);
    /// ```
    #[must_use]
    pub const fn with_max_interim(mut self, count: u16) -> Self {
        self.interim = count;
        self
    }

    /// Sets the largest accepted body, in bytes after chunked decoding.
    ///
    /// # Examples
    ///
    /// ```
    /// let l = http_net::Limits::new().with_max_body(0);
    /// assert_eq!(l.max_body(), 0);
    /// ```
    #[must_use]
    pub const fn with_max_body(mut self, bytes: u64) -> Self {
        self.body = bytes;
        self
    }

    /// The longest accepted start line or chunk-size line, CRLF included.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Limits::new().max_start_line(), 8192);
    /// ```
    #[must_use]
    pub const fn max_start_line(&self) -> usize {
        self.start_line
    }

    /// The largest accepted header section, in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Limits::new().max_header_bytes(), 16384);
    /// ```
    #[must_use]
    pub const fn max_header_bytes(&self) -> usize {
        self.header_bytes
    }

    /// The most header fields accepted in one message.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Limits::new().max_headers(), 100);
    /// ```
    #[must_use]
    pub const fn max_headers(&self) -> usize {
        self.headers
    }

    /// The longest accepted single field line, CRLF included.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Limits::new().max_field_line(), 8192);
    /// ```
    #[must_use]
    pub const fn max_field_line(&self) -> usize {
        self.field_line
    }

    /// The largest accepted trailer section, in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let l = http_net::Limits::new().with_max_header_bytes(4096);
    /// assert_eq!(l.max_trailer_bytes(), 4096);
    /// ```
    #[must_use]
    pub const fn max_trailer_bytes(&self) -> usize {
        match self.trailer_bytes {
            Some(n) => n,
            None => self.header_bytes,
        }
    }

    /// The most trailer fields accepted in one message.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Limits::new().max_trailer_fields(), 100);
    /// ```
    #[must_use]
    pub const fn max_trailer_fields(&self) -> usize {
        match self.trailer_fields {
            Some(n) => n,
            None => self.headers,
        }
    }

    /// The most interim responses a client accepts per request.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Limits::new().max_interim(), 16);
    /// ```
    #[must_use]
    pub const fn max_interim(&self) -> u16 {
        self.interim
    }

    /// Sets how many requests a client may have outstanding at once
    /// (pipelining, RFC 9112 section 9.3.2). Clamped to `1..=32`; 1 (the
    /// default) means one request at a time. Only idempotent requests with
    /// full bodies are pipelined; see
    /// [`ClientConn::can_send`](crate::ClientConn::can_send).
    ///
    /// # Examples
    ///
    /// ```
    /// let l = http_net::Limits::new().with_pipeline_depth(8);
    /// assert_eq!(l.pipeline_depth(), 8);
    /// assert_eq!(http_net::Limits::new().with_pipeline_depth(0).pipeline_depth(), 1);
    /// assert_eq!(http_net::Limits::new().with_pipeline_depth(200).pipeline_depth(), 32);
    /// ```
    #[must_use]
    pub const fn with_pipeline_depth(mut self, depth: u8) -> Self {
        self.pipeline_depth = if depth == 0 {
            1
        } else if depth > MAX_PIPELINE_DEPTH {
            MAX_PIPELINE_DEPTH
        } else {
            depth
        };
        self
    }

    /// How many requests a client may have outstanding at once.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Limits::new().pipeline_depth(), 1);
    /// ```
    #[must_use]
    pub const fn pipeline_depth(&self) -> u8 {
        self.pipeline_depth
    }

    /// The largest accepted body, in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Limits::new().max_body(), 1 << 20);
    /// ```
    #[must_use]
    pub const fn max_body(&self) -> u64 {
        self.body
    }

    /// The input buffer's hard capacity, `head + max(head,
    /// max_trailer_bytes) + 16 KiB` where `head = max_start_line +
    /// max_header_bytes` (64 KiB with the defaults), so a driver can plan
    /// memory per connection.
    ///
    /// The current message's head stays pinned while its body streams, and
    /// the decoder may need one whole chunk-size line or trailer section on
    /// top of it, so this always fits whatever the parser is waiting to
    /// complete. A connection's memory is this buffer plus `max_headers`
    /// field records of 16 bytes each (and as many for trailers when they
    /// are reported).
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::Limits;
    ///
    /// assert_eq!(Limits::new().buffer_capacity(), 64 * 1024);
    /// let small = Limits::new().with_max_start_line(1024).with_max_header_bytes(4096);
    /// assert_eq!(small.buffer_capacity(), 2 * (1024 + 4096) + 16 * 1024);
    /// ```
    #[must_use]
    pub const fn buffer_capacity(&self) -> usize {
        let head = self.start_line + self.header_bytes;
        let trailers = self.max_trailer_bytes();
        let tail = if trailers > head { trailers } else { head };
        head + tail + BODY_WINDOW
    }
}

const fn clamp(v: usize, lo: usize, hi: usize) -> usize {
    if v < lo {
        lo
    } else if v > hi {
        hi
    } else {
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_limits_clamp_to_hard_bounds() {
        let l = Limits::new()
            .with_max_start_line(usize::MAX)
            .with_max_header_bytes(0)
            .with_max_headers(usize::MAX);
        assert_eq!(l.max_start_line(), HARD_CAP);
        assert_eq!(l.max_header_bytes(), 2);
        assert_eq!(l.max_headers(), 65_536);
        assert!(l.buffer_capacity() <= u32::MAX as usize);
        let l = l.with_max_trailer_bytes(usize::MAX).with_max_field_line(0);
        assert!(l.buffer_capacity() <= u32::MAX as usize);
        assert_eq!(l.max_field_line(), 4);
    }

    #[test]
    fn test_buffer_capacity_covers_a_larger_trailer_section() {
        let base = Limits::new();
        assert_eq!(base.buffer_capacity(), 64 * 1024);
        let big = base.with_max_trailer_bytes(100 * 1024);
        assert_eq!(big.buffer_capacity(), 24 * 1024 + 100 * 1024 + 16 * 1024);
        let small = base.with_max_trailer_bytes(10);
        assert_eq!(small.buffer_capacity(), 64 * 1024);
    }
}
