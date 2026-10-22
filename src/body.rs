//! Body decoding (Content-Length, chunked, read-until-close) and encoding.

use crate::{
    error::HttpError,
    head::{BodyFraming, HeadKind, HeadScanner, Scan, find_line},
    limits::Limits,
    syntax::{hex_value, is_ows, is_qdtext, is_tchar, push_decimal, push_hex},
    write::Output,
};

/// The most hex digits a chunk size may have before it is certain to
/// overflow; leading zeros beyond this are refused too, which costs nothing
/// legitimate and keeps the size check trivially exact.
const MAX_CHUNK_DIGITS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Length {
        remaining: u64,
    },
    ChunkSize,
    ChunkData {
        remaining: u64,
    },
    ChunkDataEnd,
    Trailers,
    /// The trailer section (the first `len` unread bytes) was reported; it
    /// is consumed on the next step.
    TrailersReady {
        len: usize,
    },
    UntilClose,
    Done,
}

/// One decoding step's result. Data is the first `n` unread bytes, which the
/// caller emits and then consumes. Trailers are the first `n` unread bytes,
/// with their fields in the trailer scanner; the caller reports them and
/// leaves them unconsumed.
pub(crate) enum Step {
    Data(usize),
    Trailers,
    Done,
    NeedMore,
}

/// What the decoder does with a trailer section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrailerMode {
    /// Validate and consume it.
    Discard,
    /// Validate it, store its fields, and report it.
    Store,
    /// Validate it and report where it is, without storing its fields.
    Locate,
}

pub(crate) struct Decoder {
    state: State,
    scan: usize,
    total: u64,
    /// Chunk-extension bytes seen in this message, against the header
    /// budget: each chunk line is bounded, but their number is not.
    ext_bytes: usize,
}

impl Decoder {
    pub(crate) const fn new() -> Self {
        Self {
            state: State::Done,
            scan: 0,
            total: 0,
            ext_bytes: 0,
        }
    }

    /// Whether every byte of the message has been read: done, or only the
    /// already-received trailer section is left to hand over.
    pub(crate) fn is_read(&self) -> bool {
        matches!(self.state, State::Done | State::TrailersReady { .. })
    }

    /// Whether the whole body has been decoded and handed over.
    pub(crate) fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// The length of the trailer section reported by the last
    /// [`Step::Trailers`] (zero otherwise).
    pub(crate) fn trailer_len(&self) -> usize {
        match self.state {
            State::TrailersReady { len } => len,
            _ => 0,
        }
    }

    /// The caller consumed the reported trailer section itself: the body is
    /// done without consuming it again on the next step.
    pub(crate) fn take_trailers(&mut self) {
        if let State::TrailersReady { .. } = self.state {
            self.state = State::Done;
        }
    }

    pub(crate) fn start(&mut self, framing: BodyFraming) {
        self.scan = 0;
        self.total = 0;
        self.ext_bytes = 0;
        self.state = match framing {
            BodyFraming::None | BodyFraming::Length(0) => State::Done,
            BodyFraming::Length(n) => State::Length { remaining: n },
            BodyFraming::Chunked => State::ChunkSize,
            BodyFraming::UntilClose => State::UntilClose,
        };
    }

    /// Advances over `unread`, consuming framing bytes through `consume` and
    /// stopping at the first data run or when more input is needed.
    /// `trailers` scans the trailer section; with `report` its fields are
    /// stored and a non-empty section is returned as [`Step::Trailers`]
    /// before [`Step::Done`], otherwise they are validated and discarded.
    pub(crate) fn step(
        &mut self,
        unread: &[u8],
        eof: bool,
        limits: &Limits,
        trailers: &mut HeadScanner,
        report: bool,
        consume: &mut usize,
    ) -> Result<Step, HttpError> {
        let mode = if report {
            TrailerMode::Store
        } else {
            TrailerMode::Discard
        };
        self.step_with(unread, eof, limits, trailers, mode, consume)
    }

    /// As [`step`](Self::step), with the trailer handling spelled out:
    /// [`TrailerMode::Locate`] reports a non-empty trailer section as
    /// [`Step::Trailers`] (its length in [`trailer_len`](Self::trailer_len))
    /// without storing its fields, so nothing is allocated.
    pub(crate) fn step_with(
        &mut self,
        unread: &[u8],
        eof: bool,
        limits: &Limits,
        trailers: &mut HeadScanner,
        mode: TrailerMode,
        consume: &mut usize,
    ) -> Result<Step, HttpError> {
        let store = mode == TrailerMode::Store;
        loop {
            let input = unread.get(*consume..).unwrap_or(&[]);
            match self.state {
                State::Done => return Ok(Step::Done),
                State::TrailersReady { len } => {
                    *consume += len;
                    self.state = State::Done;
                    return Ok(Step::Done);
                }
                State::Length { remaining } | State::ChunkData { remaining } => {
                    if input.is_empty() {
                        return if eof {
                            Err(HttpError::UnexpectedEof)
                        } else {
                            Ok(Step::NeedMore)
                        };
                    }
                    let n = usize::try_from(remaining)
                        .unwrap_or(usize::MAX)
                        .min(input.len());
                    let left = remaining - n as u64;
                    self.state = match self.state {
                        State::Length { .. } if left == 0 => State::Done,
                        State::Length { .. } => State::Length { remaining: left },
                        _ if left == 0 => State::ChunkDataEnd,
                        _ => State::ChunkData { remaining: left },
                    };
                    return Ok(Step::Data(n));
                }
                State::UntilClose => {
                    if input.is_empty() {
                        if eof {
                            self.state = State::Done;
                            return Ok(Step::Done);
                        }
                        return Ok(Step::NeedMore);
                    }
                    // Deliver up to the budget and refuse only the byte
                    // past it, so the events do not depend on how the input
                    // was split into reads.
                    let room = limits.max_body().saturating_sub(self.total);
                    if room == 0 {
                        return Err(HttpError::BodyTooLarge);
                    }
                    let n = usize::try_from(room).unwrap_or(usize::MAX).min(input.len());
                    self.total += n as u64;
                    return Ok(Step::Data(n));
                }
                State::ChunkSize => {
                    let Some(end) = find_line(
                        input,
                        0,
                        &mut self.scan,
                        limits.max_start_line(),
                        HttpError::ChunkLineTooLong,
                    )?
                    else {
                        return if eof {
                            Err(HttpError::UnexpectedEof)
                        } else {
                            Ok(Step::NeedMore)
                        };
                    };
                    let (size, ext_len) = parse_chunk_line(&input[..end])?;
                    self.ext_bytes += ext_len;
                    if self.ext_bytes > limits.max_header_bytes() {
                        return Err(HttpError::ChunkExtensionsTooLarge);
                    }
                    *consume += self.scan;
                    self.scan = 0;
                    if size == 0 {
                        trailers.reset();
                        self.state = State::Trailers;
                        continue;
                    }
                    // Check the declared size against the budget before a
                    // single data byte is read.
                    self.total = self
                        .total
                        .checked_add(size)
                        .filter(|&t| t <= limits.max_body())
                        .ok_or(HttpError::BodyTooLarge)?;
                    self.state = State::ChunkData { remaining: size };
                }
                State::ChunkDataEnd => match input {
                    [b'\r', b'\n', ..] => {
                        *consume += 2;
                        self.state = State::ChunkSize;
                    }
                    [] | [b'\r'] => {
                        return if eof {
                            Err(HttpError::UnexpectedEof)
                        } else {
                            Ok(Step::NeedMore)
                        };
                    }
                    _ => return Err(HttpError::InvalidChunkTerminator),
                },
                State::Trailers => {
                    match trailers.advance(input, limits, HeadKind::Trailer, store)? {
                        Scan::Done(n)
                            if mode != TrailerMode::Discard && trailers.field_count() > 0 =>
                        {
                            // Framing bytes before the section are consumed
                            // now, so the section starts the unread input.
                            self.state = State::TrailersReady { len: n };
                            return Ok(Step::Trailers);
                        }
                        Scan::Done(n) => {
                            *consume += n;
                            self.state = State::Done;
                            return Ok(Step::Done);
                        }
                        Scan::Partial => {
                            return if eof {
                                Err(HttpError::UnexpectedEof)
                            } else {
                                Ok(Step::NeedMore)
                            };
                        }
                    }
                }
            }
        }
    }
}

/// Parses `chunk-size [ chunk-ext ]` (the line without its CRLF), returning
/// the size and the length of the extension part.
///
/// `chunk-ext = *( BWS ";" BWS ext-name [ BWS "=" BWS ext-val ] )`, where
/// `ext-val` is a token or a quoted string. Extensions are validated and
/// discarded: their meaning is defined per extension and none is in use.
pub(crate) fn parse_chunk_line(line: &[u8]) -> Result<(u64, usize), HttpError> {
    let digits = line.iter().take_while(|b| b.is_ascii_hexdigit()).count();
    if digits == 0 || digits > MAX_CHUNK_DIGITS {
        return Err(HttpError::InvalidChunkSize);
    }
    let mut size: u64 = 0;
    for &b in &line[..digits] {
        let d = hex_value(b).ok_or(HttpError::InvalidChunkSize)?;
        size = size
            .checked_mul(16)
            .and_then(|s| s.checked_add(u64::from(d)))
            .ok_or(HttpError::InvalidChunkSize)?;
    }
    let mut rest = &line[digits..];
    if rest.first().is_some_and(|&b| b != b';' && !is_ows(b)) {
        return Err(HttpError::InvalidChunkSize);
    }
    while !rest.is_empty() {
        rest = skip_ows(rest);
        let [b';', after @ ..] = rest else {
            return Err(HttpError::InvalidChunkExtension);
        };
        rest = skip_ows(after);
        let name_len = rest.iter().take_while(|&&b| is_tchar(b)).count();
        if name_len == 0 {
            return Err(HttpError::InvalidChunkExtension);
        }
        rest = &rest[name_len..];
        let after_bws = skip_ows(rest);
        if let [b'=', value @ ..] = after_bws {
            rest = skip_value(skip_ows(value))?;
        }
        // Whitespace that is not followed by another extension is not part
        // of the grammar.
        if !rest.is_empty() && skip_ows(rest).is_empty() {
            return Err(HttpError::InvalidChunkExtension);
        }
    }
    Ok((size, line.len() - digits))
}

fn skip_ows(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|&&b| is_ows(b)).count();
    &s[n..]
}

/// Skips a token or a quoted string, returning what follows it.
fn skip_value(s: &[u8]) -> Result<&[u8], HttpError> {
    if let [b'"', body @ ..] = s {
        let mut i = 0;
        while i < body.len() {
            match body[i] {
                b'"' => return Ok(&body[i + 1..]),
                b'\\' => match body.get(i + 1) {
                    Some(&b)
                        if b == b'\t' || b == b' ' || (0x21..=0x7e).contains(&b) || b >= 0x80 =>
                    {
                        i += 2;
                    }
                    _ => return Err(HttpError::InvalidChunkExtension),
                },
                b if is_qdtext(b) => i += 1,
                _ => return Err(HttpError::InvalidChunkExtension),
            }
        }
        Err(HttpError::InvalidChunkExtension)
    } else {
        let n = s.iter().take_while(|&&b| is_tchar(b)).count();
        if n == 0 {
            return Err(HttpError::InvalidChunkExtension);
        }
        Ok(&s[n..])
    }
}

/// How an outgoing body is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Encoder {
    /// Exactly `remaining` more bytes.
    Length {
        remaining: u64,
    },
    Chunked,
    /// HTTP/1.0 peer and unknown length: raw bytes, end by closing.
    CloseDelimited,
    /// The body is not sent (HEAD, or a bodiless status): bytes are dropped.
    Discard,
}

impl Encoder {
    pub(crate) fn write<O: Output + ?Sized>(
        &mut self,
        data: &[u8],
        out: &mut O,
    ) -> Result<(), HttpError> {
        match self {
            Self::Length { remaining } => {
                let n = data.len() as u64;
                if n > *remaining {
                    return Err(HttpError::BodyLengthMismatch);
                }
                *remaining -= n;
                out.put(data);
            }
            Self::Chunked => {
                // An empty chunk would end the body, so it is skipped.
                if !data.is_empty() {
                    push_hex(out, data.len() as u64);
                    out.put(b"\r\n");
                    out.put(data);
                    out.put(b"\r\n");
                }
            }
            Self::CloseDelimited => out.put(data),
            Self::Discard => {}
        }
        Ok(())
    }

    pub(crate) fn finish<O: Output + ?Sized>(&mut self, out: &mut O) -> Result<(), HttpError> {
        match self {
            Self::Length { remaining } if *remaining != 0 => Err(HttpError::BodyLengthMismatch),
            Self::Chunked => {
                out.put(b"0\r\n\r\n");
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// Writes the framing header line(s) for a body.
pub(crate) fn push_framing<O: Output + ?Sized>(
    out: &mut O,
    encoder: Encoder,
    declared_len: Option<u64>,
) {
    match (encoder, declared_len) {
        (Encoder::Chunked, _) => out.put(b"transfer-encoding: chunked\r\n"),
        (_, Some(n)) => {
            out.put(b"content-length: ");
            push_decimal(out, n);
            out.put(b"\r\n");
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    fn decode_all(
        framing: BodyFraming,
        input: &[u8],
        limits: &Limits,
    ) -> Result<Vec<u8>, HttpError> {
        let mut d = Decoder::new();
        d.start(framing);
        let mut trailers = HeadScanner::new();
        let mut pos = 0;
        let mut body = Vec::new();
        loop {
            let mut consumed = 0;
            let step = d.step(
                &input[pos..],
                true,
                limits,
                &mut trailers,
                true,
                &mut consumed,
            )?;
            pos += consumed;
            match step {
                Step::Data(n) => {
                    body.extend_from_slice(&input[pos..pos + n]);
                    pos += n;
                }
                // Reported trailers are consumed on the next step.
                Step::Trailers => assert!(!trailers.fields.is_empty()),
                Step::Done => return Ok(body),
                Step::NeedMore => return Err(HttpError::UnexpectedEof),
            }
        }
    }

    #[test]
    fn test_chunked_decodes_with_extensions_and_trailers() {
        let input = b"4;a=b;c=\"q\\\"x\"\r\nWiki\r\n5 ; ext\r\npedia\r\n0\r\nX-T: 1\r\n\r\n";
        let body = decode_all(BodyFraming::Chunked, input, &Limits::new());
        assert_eq!(body.as_deref(), Ok(&b"Wikipedia"[..]));
    }

    #[test]
    fn test_chunk_line_grammar() {
        assert_eq!(parse_chunk_line(b"ff"), Ok((255, 0)));
        assert_eq!(parse_chunk_line(b"0000000000000001"), Ok((1, 0)));
        assert_eq!(
            parse_chunk_line(b"00000000000000001"),
            Err(HttpError::InvalidChunkSize)
        );
        assert_eq!(parse_chunk_line(b"ffffffffffffffff"), Ok((u64::MAX, 0)));
        assert_eq!(parse_chunk_line(b""), Err(HttpError::InvalidChunkSize));
        assert_eq!(parse_chunk_line(b" 5"), Err(HttpError::InvalidChunkSize));
        assert_eq!(parse_chunk_line(b"5x"), Err(HttpError::InvalidChunkSize));
        assert_eq!(parse_chunk_line(b"0x5"), Err(HttpError::InvalidChunkSize));
        assert_eq!(
            parse_chunk_line(b"5 "),
            Err(HttpError::InvalidChunkExtension)
        );
        assert_eq!(
            parse_chunk_line(b"5;"),
            Err(HttpError::InvalidChunkExtension)
        );
        assert_eq!(
            parse_chunk_line(b"5;a="),
            Err(HttpError::InvalidChunkExtension)
        );
        assert_eq!(
            parse_chunk_line(b"5;a=\"x"),
            Err(HttpError::InvalidChunkExtension)
        );
        assert_eq!(
            parse_chunk_line(b"5;a b"),
            Err(HttpError::InvalidChunkExtension)
        );
        assert_eq!(parse_chunk_line(b"5 ;a = b ;c"), Ok((5, 10)));
    }

    #[test]
    fn test_chunk_budget_checked_before_data() {
        let limits = Limits::new().with_max_body(10);
        let r = decode_all(BodyFraming::Chunked, b"b\r\n", &limits);
        assert_eq!(r, Err(HttpError::BodyTooLarge));
        let r = decode_all(BodyFraming::Chunked, b"5\r\n12345\r\n6\r\n", &limits);
        assert_eq!(r, Err(HttpError::BodyTooLarge));
        let r = decode_all(
            BodyFraming::Chunked,
            b"5\r\n12345\r\n5\r\n12345\r\n0\r\n\r\n",
            &limits,
        );
        assert_eq!(r.as_deref(), Ok(&b"1234512345"[..]));
    }

    #[test]
    fn test_chunk_terminator_and_eof_errors() {
        let r = decode_all(BodyFraming::Chunked, b"1\r\naXY", &Limits::new());
        assert_eq!(r, Err(HttpError::InvalidChunkTerminator));
        let r = decode_all(BodyFraming::Chunked, b"1\r\na\r", &Limits::new());
        assert_eq!(r, Err(HttpError::UnexpectedEof));
        let r = decode_all(BodyFraming::Length(5), b"abc", &Limits::new());
        assert_eq!(r, Err(HttpError::UnexpectedEof));
        let r = decode_all(BodyFraming::UntilClose, b"abc", &Limits::new());
        assert_eq!(r.as_deref(), Ok(&b"abc"[..]));
        let r = decode_all(
            BodyFraming::UntilClose,
            b"abc",
            &Limits::new().with_max_body(2),
        );
        assert_eq!(r, Err(HttpError::BodyTooLarge));
    }

    #[test]
    fn test_encoder_chunked_skips_empty_and_terminates() {
        let mut out = Vec::new();
        let mut e = Encoder::Chunked;
        e.write(b"", &mut out).unwrap();
        e.write(b"hello world, this is longer", &mut out).unwrap();
        e.finish(&mut out).unwrap();
        assert_eq!(out, b"1b\r\nhello world, this is longer\r\n0\r\n\r\n");
    }

    #[test]
    fn test_encoder_length_mismatch() {
        let mut out = Vec::new();
        let mut e = Encoder::Length { remaining: 3 };
        assert_eq!(
            e.write(b"abcd", &mut out),
            Err(HttpError::BodyLengthMismatch)
        );
        e.write(b"ab", &mut out).unwrap();
        assert_eq!(e.finish(&mut out), Err(HttpError::BodyLengthMismatch));
        e.write(b"c", &mut out).unwrap();
        assert_eq!(e.finish(&mut out), Ok(()));
    }
}
