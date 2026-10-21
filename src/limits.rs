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
/// buffer can never grow past `2 * (max_start_line + max_header_bytes)` plus a
/// fixed 16 KiB body window (64 KiB with the defaults): room for a pinned
/// head plus one partial chunk line or trailer section.
///
/// The defaults are the budgets of LexerSketch Studio's localhost server:
///
/// | Budget | Default |
/// |---|---|
/// | request line / status line / chunk-size line | 8 KiB |
/// | header section (all field lines) | 16 KiB |
/// | header fields (and, separately, trailer fields) | 100 |
/// | body | 1 MiB |
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
    body: u64,
}

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

    /// The input buffer's hard capacity, `2 * (max_start_line +
    /// max_header_bytes) + 16 KiB` (64 KiB with the defaults), so a driver
    /// can plan memory per connection.
    ///
    /// The current message's head stays pinned while its body streams, and
    /// the decoder may need one whole chunk-size line or trailer section on
    /// top of it, so twice the head budget plus the body window always fits
    /// whatever the parser is waiting to complete. A connection's memory is
    /// this buffer plus `max_headers` field records of 16 bytes each.
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
        2 * (self.start_line + self.header_bytes) + BODY_WINDOW
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
    }
}
