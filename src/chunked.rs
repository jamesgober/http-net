//! A standalone chunked-body decoder, for code that holds the bytes itself
//! (a proxy streaming a body through, a client built on another buffer).
//!
//! It runs the connection's own decoder: the same chunk-size grammar (at
//! most 16 hex digits, checked arithmetic), extension grammar and per-message
//! extension budget, body budget checked before each chunk's data, CRLF
//! after the data, and trailer validation with the trailer budgets.

use crate::{
    body::{Decoder, Step, TrailerMode},
    error::HttpError,
    head::{BodyFraming, HeadScanner},
    limits::Limits,
};

/// One step of [`ChunkedDecoder::decode`], with explicit byte accounting so
/// a caller can decode in place in its own buffer. Offsets are relative to
/// the `input` of that call.
///
/// # Examples
///
/// See [`ChunkedDecoder`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChunkStep {
    /// Skip `skip` framing bytes, then `len` bytes are body data; consume
    /// both (`skip + len`) and call again with what follows.
    Data {
        /// Framing bytes before the data.
        skip: usize,
        /// Body data bytes.
        len: usize,
    },
    /// More input is needed: drop the first `consumed` bytes (framing that
    /// was read), keep the rest, append more, and call again.
    NeedMore {
        /// Framing bytes consumed.
        consumed: usize,
    },
    /// Skip `skip` framing bytes, then `len` bytes are the trailer section
    /// (its field lines and the blank line), already validated; consume
    /// both, and the next call reports [`ChunkStep::Done`]. Only reported for
    /// a section that has at least one field.
    Trailers {
        /// Framing bytes before the section.
        skip: usize,
        /// Bytes of the trailer section, the final CRLF included.
        len: usize,
    },
    /// The body is complete after `consumed` more bytes (the last chunk and
    /// an empty trailer section); what follows belongs to the next message.
    Done {
        /// Bytes consumed.
        consumed: usize,
    },
}

/// Decodes a chunked body (RFC 9112 section 7.1) from input the caller owns,
/// with the exact grammar and budgets of the connections. Nothing is
/// allocated.
///
/// # Examples
///
/// ```
/// use http_net::{ChunkStep, ChunkedDecoder, Limits};
///
/// let wire = b"4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\nDigest: x\r\n\r\nNEXT";
/// let mut decoder = ChunkedDecoder::new(&Limits::new());
/// let (mut pos, mut body) = (0, Vec::new());
/// loop {
///     match decoder.decode(&wire[pos..], false)? {
///         ChunkStep::Data { skip, len } => {
///             body.extend_from_slice(&wire[pos + skip..pos + skip + len]);
///             pos += skip + len;
///         }
///         ChunkStep::Trailers { skip, len } => {
///             assert_eq!(&wire[pos + skip..pos + skip + len], b"Digest: x\r\n\r\n");
///             pos += skip + len;
///         }
///         ChunkStep::Done { consumed } => {
///             pos += consumed;
///             break;
///         }
///         ChunkStep::NeedMore { .. } => unreachable!("the whole body is here"),
///         _ => unreachable!(),
///     }
/// }
/// assert_eq!(body, b"Wikipedia");
/// assert_eq!(&wire[pos..], b"NEXT");
/// assert!(decoder.is_done());
/// assert_eq!(decoder.total(), 9);
/// # Ok::<(), http_net::HttpError>(())
/// ```
pub struct ChunkedDecoder {
    decoder: Decoder,
    /// Scans trailer sections; with [`TrailerMode::Locate`] it stores no
    /// fields, so its field vector never allocates.
    trailers: HeadScanner,
    limits: Limits,
    total: u64,
    /// The trailer section of the last step was handed to the caller, who
    /// consumes it.
    trailers_handed: bool,
}

/// Shows progress and limits; never body bytes.
impl core::fmt::Debug for ChunkedDecoder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChunkedDecoder")
            .field("total", &self.total)
            .field("done", &self.is_done())
            .field("limits", &self.limits)
            .finish()
    }
}

impl ChunkedDecoder {
    /// A decoder for one chunked body, with `limits` (body size, chunk-size
    /// line, extension budget, trailer budgets).
    ///
    /// # Examples
    ///
    /// ```
    /// let decoder = http_net::ChunkedDecoder::new(&http_net::Limits::new().with_max_body(64));
    /// assert!(!decoder.is_done());
    /// ```
    #[must_use]
    pub fn new(limits: &Limits) -> Self {
        let mut decoder = Decoder::new();
        decoder.start(BodyFraming::Chunked);
        Self {
            decoder,
            trailers: HeadScanner::new(),
            limits: *limits,
            total: 0,
            trailers_handed: false,
        }
    }

    /// Decodes from `input`, which starts where the previous call's consumed
    /// bytes ended. `eof` says no more input will come.
    ///
    /// # Errors
    ///
    /// Every chunk error of the connections: [`HttpError::InvalidChunkSize`],
    /// [`HttpError::InvalidChunkExtension`],
    /// [`HttpError::InvalidChunkTerminator`], [`HttpError::ChunkLineTooLong`],
    /// [`HttpError::ChunkExtensionsTooLarge`], [`HttpError::BareLf`],
    /// [`HttpError::BodyTooLarge`]; the field errors of the trailer section;
    /// [`HttpError::UnexpectedEof`] when `eof` comes before the end. After an
    /// error the body cannot be resynchronised: drop the connection.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ChunkStep, ChunkedDecoder, HttpError, Limits};
    ///
    /// let mut d = ChunkedDecoder::new(&Limits::new());
    /// // A partial chunk-size line: nothing consumed, more needed.
    /// assert_eq!(d.decode(b"1", false)?, ChunkStep::NeedMore { consumed: 0 });
    /// assert_eq!(d.decode(b"1", true), Err(HttpError::UnexpectedEof));
    ///
    /// let mut d = ChunkedDecoder::new(&Limits::new());
    /// assert_eq!(d.decode(b"5\nhello", false), Err(HttpError::BareLf));
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    pub fn decode(&mut self, input: &[u8], eof: bool) -> Result<ChunkStep, HttpError> {
        if self.trailers_handed {
            self.trailers_handed = false;
            self.decoder.take_trailers();
        }
        let mut consumed = 0;
        let step = self.decoder.step_with(
            input,
            eof,
            &self.limits,
            &mut self.trailers,
            TrailerMode::Locate,
            &mut consumed,
        )?;
        Ok(match step {
            Step::Data(len) => {
                self.total += len as u64;
                ChunkStep::Data {
                    skip: consumed,
                    len,
                }
            }
            Step::Trailers => {
                self.trailers_handed = true;
                ChunkStep::Trailers {
                    skip: consumed,
                    len: self.decoder.trailer_len(),
                }
            }
            Step::Done => ChunkStep::Done { consumed },
            Step::NeedMore => ChunkStep::NeedMore { consumed },
        })
    }

    /// Whether the whole body, trailers included, has been decoded.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ChunkStep, ChunkedDecoder, Limits};
    ///
    /// let mut d = ChunkedDecoder::new(&Limits::new());
    /// assert_eq!(d.decode(b"0\r\n\r\n", false)?, ChunkStep::Done { consumed: 5 });
    /// assert!(d.is_done());
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    #[must_use]
    pub fn is_done(&self) -> bool {
        !self.trailers_handed && self.decoder.is_done()
    }

    /// The body bytes delivered so far, after chunked decoding.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ChunkedDecoder, Limits};
    ///
    /// let mut d = ChunkedDecoder::new(&Limits::new());
    /// let _ = d.decode(b"3\r\nabc\r\n", false)?;
    /// assert_eq!(d.total(), 3);
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    /// The body, the trailer bytes, and what followed.
    type Decoded = (Vec<u8>, Vec<u8>, Vec<u8>);

    /// Feeds `wire` in `piece`-sized appends, as a caller with its own buffer
    /// would.
    fn run(wire: &[u8], piece: usize, limits: &Limits) -> Result<Decoded, HttpError> {
        let mut d = ChunkedDecoder::new(limits);
        let mut buf: Vec<u8> = Vec::new();
        let mut fed = 0;
        let (mut body, mut trailers) = (Vec::new(), Vec::new());
        loop {
            let eof = fed == wire.len();
            match d.decode(&buf, eof)? {
                ChunkStep::Data { skip, len } => {
                    body.extend_from_slice(&buf[skip..skip + len]);
                    let _ = buf.drain(..skip + len);
                }
                ChunkStep::Trailers { skip, len } => {
                    trailers.extend_from_slice(&buf[skip..skip + len]);
                    let _ = buf.drain(..skip + len);
                }
                ChunkStep::Done { consumed } => {
                    let _ = buf.drain(..consumed);
                    buf.extend_from_slice(&wire[fed..]);
                    return Ok((body, trailers, buf));
                }
                ChunkStep::NeedMore { consumed } => {
                    let _ = buf.drain(..consumed);
                    let end = (fed + piece).min(wire.len());
                    buf.extend_from_slice(&wire[fed..end]);
                    fed = end;
                }
            }
        }
    }

    #[test]
    fn test_decode_any_split_gives_the_same_body_and_trailers() {
        let wire = b"4;a=b\r\nWiki\r\n5\r\npedia\r\n0\r\nX-T: 1\r\nY: 2\r\n\r\nGET";
        let whole = run(wire, wire.len(), &Limits::new()).unwrap();
        assert_eq!(whole.0, b"Wikipedia");
        assert_eq!(whole.1, b"X-T: 1\r\nY: 2\r\n\r\n");
        assert_eq!(whole.2, b"GET");
        for piece in 1..wire.len() {
            assert_eq!(run(wire, piece, &Limits::new()).unwrap(), whole, "{piece}");
        }
    }

    #[test]
    fn test_decode_without_trailers_reports_done() {
        let (body, trailers, rest) = run(b"1\r\nx\r\n0\r\n\r\n", 3, &Limits::new()).unwrap();
        assert_eq!(body, b"x");
        assert!(trailers.is_empty());
        assert!(rest.is_empty());
    }

    #[test]
    fn test_decode_errors_match_the_connection_grammar() {
        let cases: &[(&[u8], HttpError)] = &[
            (b"x\r\n", HttpError::InvalidChunkSize),
            (b"00000000000000001\r\n", HttpError::InvalidChunkSize),
            (b"5;\r\n", HttpError::InvalidChunkExtension),
            (b"1\r\naX", HttpError::InvalidChunkTerminator),
            (b"5;a=b\nX", HttpError::BareLf),
            (b"0\r\nBad Name: x\r\n\r\n", HttpError::InvalidHeaderName),
            (b"0\r\n folded\r\n\r\n", HttpError::ObsFold),
            (b"3\r\nab", HttpError::UnexpectedEof),
        ];
        for (wire, err) in cases {
            assert_eq!(
                run(wire, wire.len(), &Limits::new()).err(),
                Some(*err),
                "{wire:?}"
            );
        }
        let limits = Limits::new().with_max_body(4);
        assert_eq!(
            run(b"5\r\nhello\r\n0\r\n\r\n", 64, &limits).err(),
            Some(HttpError::BodyTooLarge)
        );
        let limits = Limits::new().with_max_trailer_fields(1);
        assert_eq!(
            run(b"0\r\nA: 1\r\nB: 2\r\n\r\n", 64, &limits).err(),
            Some(HttpError::TooManyHeaders)
        );
    }

    #[test]
    fn test_total_and_done_track_the_body() {
        let mut d = ChunkedDecoder::new(&Limits::new());
        assert_eq!(
            d.decode(b"2\r\nab\r\n", false),
            Ok(ChunkStep::Data { skip: 3, len: 2 })
        );
        assert_eq!(d.total(), 2);
        assert!(!d.is_done());
        assert_eq!(
            d.decode(b"\r\n0\r\nT: v\r\n\r\n", false),
            Ok(ChunkStep::Trailers { skip: 5, len: 8 })
        );
        assert!(!d.is_done());
        assert_eq!(d.decode(b"", false), Ok(ChunkStep::Done { consumed: 0 }));
        assert!(d.is_done());
        assert_eq!(
            d.decode(b"more", false),
            Ok(ChunkStep::Done { consumed: 0 })
        );
    }
}
