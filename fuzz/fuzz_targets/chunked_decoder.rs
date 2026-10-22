//! The standalone `ChunkedDecoder` against the connection it shares code
//! with. The same bytes, sent as the chunked body of a request on
//! `ServerConn` and decoded by `ChunkedDecoder` at fuzzer-chosen splits,
//! must give the same body, the same trailers and the same error, and the
//! bytes left after the body must parse on a fresh connection exactly as
//! they did after the body on the first.

#![no_main]

use arbitrary::Arbitrary;
use http_net::{ChunkStep, ChunkedDecoder, Limits};
use http_net_fuzz::{Ev, Options, drive_server_with, split};
use libfuzzer_sys::fuzz_target;

const HEAD: &[u8] = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n";

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    body: &'a [u8],
    cuts: Vec<u16>,
    max_body: Option<u16>,
    trailer_bytes: Option<u16>,
    trailer_fields: Option<u8>,
}

/// The trailer fields of a section the decoder has validated, as the
/// connection reports them: names as sent, values without the OWS around
/// them.
fn fields(section: &[u8]) -> Vec<(String, Vec<u8>)> {
    let ows = |b: &u8| *b == b' ' || *b == b'\t';
    section
        .split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .take_while(|line| !line.is_empty())
        .map(|line| {
            let colon = line.iter().position(|&b| b == b':').expect("validated");
            let mut value = &line[colon + 1..];
            while value.first().is_some_and(ows) {
                value = &value[1..];
            }
            while value.last().is_some_and(ows) {
                value = &value[..value.len() - 1];
            }
            let name = String::from_utf8(line[..colon].to_vec()).expect("a token");
            (name, value.to_vec())
        })
        .collect()
}

/// The decoder's record of the body, in the connection driver's terms,
/// and the bytes after it when it ended.
fn decode(pieces: &[&[u8]], limits: &Limits) -> (Vec<Ev>, Option<Vec<u8>>) {
    let mut decoder = ChunkedDecoder::new(limits);
    let mut events: Vec<Ev> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    let mut next = 0;
    let mut total = 0u64;
    loop {
        let eof = next == pieces.len();
        match decoder.decode(&buf, eof) {
            Ok(ChunkStep::Data { skip, len }) => {
                assert!(len > 0, "an empty data step");
                let data = &buf[skip..skip + len];
                if let Some(Ev::Body(b)) = events.last_mut() {
                    b.extend_from_slice(data);
                } else {
                    events.push(Ev::Body(data.to_vec()));
                }
                total += len as u64;
                assert_eq!(decoder.total(), total, "total miscounted");
                let _ = buf.drain(..skip + len);
            }
            Ok(ChunkStep::Trailers { skip, len }) => {
                let section = fields(&buf[skip..skip + len]);
                assert!(!section.is_empty(), "an empty trailer section was reported");
                events.push(Ev::Trailers(section));
                let _ = buf.drain(..skip + len);
            }
            Ok(ChunkStep::Done { consumed }) => {
                assert!(decoder.is_done(), "Done but not is_done");
                let _ = buf.drain(..consumed);
                for p in &pieces[next..] {
                    buf.extend_from_slice(p);
                }
                events.push(Ev::End);
                return (events, Some(buf));
            }
            Ok(ChunkStep::NeedMore { consumed }) => {
                assert!(!eof, "NeedMore at EOF");
                let _ = buf.drain(..consumed);
                buf.extend_from_slice(pieces[next]);
                next += 1;
            }
            Ok(other) => panic!("unknown step {other:?}"),
            Err(e) => {
                events.push(Ev::Err(e));
                return (events, None);
            }
        }
    }
}

fuzz_target!(|input: Input<'_>| {
    let mut limits = Limits::new();
    if let Some(n) = input.max_body {
        limits = limits.with_max_body(u64::from(n));
    }
    if let Some(n) = input.trailer_bytes {
        limits = limits.with_max_trailer_bytes(usize::from(n));
    }
    if let Some(n) = input.trailer_fields {
        limits = limits.with_max_trailer_fields(usize::from(n));
    }
    let opts = Options {
        report_trailers: true,
        ..Options::default()
    };

    let mut wire = HEAD.to_vec();
    wire.extend_from_slice(input.body);
    let by_conn = drive_server_with(&[&wire], limits, opts);
    assert!(
        matches!(by_conn.first(), Some(Ev::Head { .. })),
        "the head was refused"
    );
    let end = by_conn
        .iter()
        .position(|e| matches!(e, Ev::End | Ev::Err(_)))
        .expect("the body ended or failed");

    let pieces = split(input.body, &input.cuts);
    let (by_decoder, rest) = decode(&pieces, &limits);
    assert_eq!(
        &by_conn[1..=end],
        &by_decoder[..],
        "the decoder and the connection disagree"
    );

    if let Some(rest) = rest {
        let next = drive_server_with(&[&rest], limits, opts);
        assert_eq!(
            &by_conn[end + 1..],
            &next[..],
            "the bytes after the body differ"
        );
    }
});
