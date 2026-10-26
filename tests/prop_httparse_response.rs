//! Differential test against `httparse` (dev-dependency only), response side.
//!
//! For every input on which `parse_response_head` (the stateless parser,
//! which runs `ClientConn`'s own scanner and interpretation) accepts a
//! complete response head, `httparse` (default, strict configuration) must
//! accept the same head: the same length, status, version, reason, and
//! field list. A client and an intermediary that disagree on any of those
//! are a response smuggling (desync) setup, so every disagreement is either
//! a documented place where `http-net` is stricter (it refused, `httparse`
//! accepted) or a bug.
//!
//! The one documented place where `http-net` accepts and `httparse` does
//! not is `HTTP/1.2` to `HTTP/1.9`, which RFC 9110 section 2.5 says to
//! process as HTTP/1.1 and `httparse` refuses. A status line without the
//! space after the code (`HTTP/1.1 200` CRLF) is accepted by both.

use std::collections::BTreeMap;

use http_net::{
    Asked, ClientConn, ClientEvent, FieldSpan, HttpError, Limits, Parsed, Request, ResponseHead,
    Version, parse_response_head,
};
use proptest::prelude::*;

#[derive(Debug, PartialEq, Eq)]
struct Head {
    len: usize,
    status: u16,
    minor: u8,
    reason: Vec<u8>,
    fields: Vec<(Vec<u8>, Vec<u8>)>,
}

enum Ours {
    Head(Head),
    Refused(HttpError),
    Incomplete,
}

/// The head as http-net reports it, `len` bytes of input long.
fn head_of(resp: &ResponseHead<'_>, len: usize) -> Head {
    let raw = resp.raw();
    let line = raw.start_line().get(raw.bytes());
    Head {
        len,
        status: resp.status(),
        minor: match resp.version() {
            Version::Http10 => 0,
            _ => 1,
        },
        reason: comparable_reason(line.get(13..).unwrap_or(&[])),
        fields: resp
            .headers()
            .map(|(n, v)| (n.as_bytes().to_vec(), v.to_vec()))
            .collect(),
    }
}

/// httparse hands out its reason as `&str`, and an empty one when the
/// reason holds obs-text (bytes 0x80 to 0xFF, its documented fallback).
/// RFC 9112 section 4 says the reason carries no meaning, and both parsers
/// accepted the same bytes, so ours is reported the same way: a
/// representation difference, not a disagreement about the status line.
fn comparable_reason(reason: &[u8]) -> Vec<u8> {
    if reason.iter().any(|&b| b >= 0x80) {
        Vec::new()
    } else {
        reason.to_vec()
    }
}

fn ours(input: &[u8]) -> Ours {
    // As many slots as `Limits::new().max_headers()`, so the array is never
    // the reason for a refusal.
    let mut fields = [FieldSpan::default(); 100];
    match parse_response_head(input, &Limits::new(), Asked::default(), &mut fields) {
        Ok(Parsed::Complete { head, len }) => Ours::Head(head_of(&head.view(), len)),
        Ok(_) => Ours::Incomplete,
        Err(e) => Ours::Refused(e),
    }
}

/// The same input through `ClientConn`, after a `GET` that offers an
/// upgrade to `websocket` (so a `101` to it is allowed), with interim heads
/// reported: the first head it hands out.
fn client(input: &[u8]) -> Ours {
    let mut conn = ClientConn::new();
    conn.set_report_informational(true);
    let req = Request::get("/").header("host", "a").upgrade("websocket");
    conn.send_request(&req, &mut Vec::new())
        .expect("the request is valid");
    let fed = conn.feed(input);
    let head = match conn.poll() {
        Ok(ClientEvent::Response(r) | ClientEvent::Informational(r)) => head_of(&r, 0),
        Ok(_) => return Ours::Incomplete,
        Err(e) => return Ours::Refused(e),
    };
    // What is left unread after the head event is the body and anything
    // after it, so the head is the rest.
    let len = fed - conn.remaining_input().len();
    Ours::Head(Head { len, ..head })
}

enum Theirs {
    Head(Head),
    Partial,
    Refused(httparse::Error),
}

fn theirs(input: &[u8]) -> Theirs {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(input) {
        Ok(httparse::Status::Complete(len)) => Theirs::Head(Head {
            len,
            status: resp.code.unwrap_or(0),
            minor: resp.version.unwrap_or(255),
            reason: resp.reason.unwrap_or("").as_bytes().to_vec(),
            fields: resp
                .headers
                .iter()
                // httparse removes leading whitespace from values but keeps
                // trailing SP / HTAB; RFC 9110 section 5.5 says OWS around a
                // value is not part of it, and http-net trims both ends. The
                // trailing trim is a representation difference (what the
                // view hands out), not a disagreement about where the field
                // or the head ends, so it is normalised here.
                .map(|h| {
                    (
                        h.name.as_bytes().to_vec(),
                        trim_trailing_ows(h.value).to_vec(),
                    )
                })
                .collect(),
        }),
        Ok(httparse::Status::Partial) => Theirs::Partial,
        Err(e) => Theirs::Refused(e),
    }
}

fn trim_trailing_ows(mut v: &[u8]) -> &[u8] {
    while let [rest @ .., b' ' | b'\t'] = v {
        v = rest;
    }
    v
}

/// Whether the status line says `HTTP/1.2` to `HTTP/1.9`.
fn has_later_minor_version(input: &[u8]) -> bool {
    input.len() > 8
        && input.starts_with(b"HTTP/1.")
        && (b'2'..=b'9').contains(&input[7])
        && input[8] == b' '
}

/// Refusals where http-net is stricter than httparse on purpose, each with
/// the rule it enforces. An httparse-accepted input refused for any other
/// reason is a failure. Two variants are documented only for one shape
/// each, so the input and the head httparse read are needed to tell.
fn stricter_reason(e: HttpError, input: &[u8], theirs: &Head) -> Option<&'static str> {
    Some(match e {
        HttpError::BareLf => {
            "LF must follow CR (RFC 9112 2.2 MAY accept; refused so every hop agrees on line ends)"
        }
        HttpError::InvalidStartLine if matches!(input.first(), Some(b'\r' | b'\n')) => {
            "an empty line before the status line (RFC 9112 2.2 lets only a server skip them)"
        }
        HttpError::InvalidStatus if !(100..=599).contains(&theirs.status) => {
            "status code outside 100..=599 (RFC 9110 15); httparse takes any three digits"
        }
        HttpError::InvalidContentLength => "Content-Length is 1*DIGIT (RFC 9112 6.3)",
        HttpError::DuplicateContentLength => "a second Content-Length refused even when equal",
        HttpError::ConflictingFraming => {
            "Content-Length with Transfer-Encoding refused (RFC 9112 6.1)"
        }
        HttpError::InvalidTransferEncoding => {
            "Transfer-Encoding must end in one chunked; RFC 9112 6.3 reads anything else to close"
        }
        HttpError::UnsupportedTransferEncoding => "codings other than chunked are not implemented",
        HttpError::TransferEncodingInHttp10 => {
            "Transfer-Encoding in HTTP/1.0 is faulty framing (RFC 9112 6.1)"
        }
        HttpError::BodyTooLarge => "declared body above max_body, refused on the header line",
        // The size budgets (StartLineTooLong, HeadersTooLarge,
        // TooManyHeaders) would belong here too, but no input in this file
        // is large enough to reach them.
        _ => return None,
    })
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Both accepted the same head.
    Agreed,
    /// http-net refused a head httparse accepted, for a documented reason.
    Stricter(HttpError),
    /// http-net processed HTTP/1.2..1.9 as 1.1; httparse refused it.
    LaterMinor,
    /// Neither accepted a complete head.
    Neither,
}

fn compare(input: &[u8]) -> Result<Outcome, String> {
    let show = || format!("{:?}", String::from_utf8_lossy(input));
    match (ours(input), theirs(input)) {
        (Ours::Head(a), Theirs::Head(b)) => {
            if a == b {
                Ok(Outcome::Agreed)
            } else {
                Err(format!(
                    "heads differ for {}:\n http-net {a:?}\n httparse {b:?}",
                    show()
                ))
            }
        }
        (Ours::Head(_), Theirs::Refused(httparse::Error::Version))
            if has_later_minor_version(input) =>
        {
            Ok(Outcome::LaterMinor)
        }
        (Ours::Head(a), other) => Err(format!(
            "http-net accepted a head httparse did not ({}) for {}: {a:?}",
            match other {
                Theirs::Partial => "partial".to_string(),
                Theirs::Refused(e) => format!("{e:?}"),
                Theirs::Head(_) => unreachable!(),
            },
            show()
        )),
        (Ours::Refused(e), Theirs::Head(b)) => match stricter_reason(e, input, &b) {
            Some(_) => Ok(Outcome::Stricter(e)),
            None => Err(format!(
                "http-net refused with {e:?} a head httparse accepts: {}\n httparse {b:?}",
                show()
            )),
        },
        _ => Ok(Outcome::Neither),
    }
}

const SEEDS: &[&[u8]] = &[
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello",
    b"HTTP/1.1 204 No Content\r\nDate: Thu, 22 Oct 2026 10:00:00 GMT\r\n\r\n",
    b"HTTP/1.1 304 Not Modified\r\nETag: \"abc\"\r\nCache-Control: max-age=60\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\n\r\n",
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
    b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style\r\n\r\n",
    b"HTTP/1.1 100 Continue\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1; Path=/; HttpOnly\r\nSet-Cookie: b=2\r\nContent-Length: 0\r\n\r\n",
    b"HTTP/1.1 404 Not Found At All\r\nContent-Length: 0\r\n\r\n",
    b"HTTP/1.1 299 \r\nContent-Length: 0\r\n\r\n",
    b"HTTP/1.1 200 caf\xc3\xa9 \x80\xff\r\nContent-Length: 0\r\n\r\n",
    b"HTTP/1.0 200 OK\r\nServer: test/1.0\r\nX-A: \t2 \r\n\r\nread until close",
];

const INTERESTING: &[u8] = b"\r\n \t:;,=\"\\\x00\x01\x0b\x7f\x80\xffaZ0159+%/?*-#@[]";

#[derive(Clone, Debug)]
enum Op {
    Insert(usize, u8),
    Replace(usize, u8),
    Remove(usize),
}

fn op() -> impl Strategy<Value = Op> {
    let byte = prop_oneof![
        3 => proptest::sample::select(INTERESTING),
        1 => any::<u8>(),
    ];
    prop_oneof![
        (any::<usize>(), byte.clone()).prop_map(|(p, b)| Op::Insert(p, b)),
        (any::<usize>(), byte).prop_map(|(p, b)| Op::Replace(p, b)),
        any::<usize>().prop_map(Op::Remove),
    ]
}

fn mutate(seed: &[u8], ops: &[Op]) -> Vec<u8> {
    let mut v = seed.to_vec();
    for op in ops {
        match *op {
            Op::Insert(p, b) => v.insert(p % (v.len() + 1), b),
            Op::Replace(p, b) if !v.is_empty() => {
                let i = p % v.len();
                v[i] = b;
            }
            Op::Remove(p) if !v.is_empty() => {
                let _ = v.remove(p % v.len());
            }
            _ => {}
        }
    }
    v
}

/// Every single-byte mutation of every seed: each interesting byte inserted
/// and substituted at each position, and each byte removed.
fn single_mutations() -> Vec<Vec<u8>> {
    let mut all = Vec::new();
    for seed in SEEDS {
        for pos in 0..=seed.len() {
            for &b in INTERESTING {
                all.push(mutate(seed, &[Op::Insert(pos, b)]));
                if pos < seed.len() {
                    all.push(mutate(seed, &[Op::Replace(pos, b)]));
                }
            }
            if pos < seed.len() {
                all.push(mutate(seed, &[Op::Remove(pos)]));
            }
        }
    }
    all
}

#[test]
fn test_seeds_are_accepted_identically_by_both() {
    for seed in SEEDS {
        assert_eq!(
            compare(seed),
            Ok(Outcome::Agreed),
            "{:?}",
            String::from_utf8_lossy(seed)
        );
    }
}

#[test]
fn test_seeds_parse_the_same_through_client_conn() {
    // The stateless parser shares ClientConn's scanner and interpretation;
    // on the seeds both hand out the same head as httparse.
    for seed in SEEDS {
        let (Ours::Head(stateless), Ours::Head(conn), Theirs::Head(them)) =
            (ours(seed), client(seed), theirs(seed))
        else {
            panic!("a parser refused {:?}", String::from_utf8_lossy(seed));
        };
        assert_eq!(stateless, conn, "{:?}", String::from_utf8_lossy(seed));
        assert_eq!(conn, them, "{:?}", String::from_utf8_lossy(seed));
    }
}

#[test]
fn test_client_conn_and_stateless_parser_agree_on_every_mutation() {
    // Beyond the seeds: on every single-byte mutation the connection and
    // the stateless parser give the same head or the same refusal. The
    // connection alone refuses a 101 that does not switch to the offered
    // protocol (RFC 9110 section 7.8), which the stateless parser leaves to
    // its caller.
    let mut failures = Vec::new();
    for input in single_mutations() {
        let same = match (ours(&input), client(&input)) {
            (Ours::Head(a), Ours::Head(b)) => a == b,
            (Ours::Head(a), Ours::Refused(HttpError::UnexpectedUpgrade)) => a.status == 101,
            (Ours::Refused(a), Ours::Refused(b)) => a == b,
            (Ours::Incomplete, Ours::Incomplete) => true,
            _ => false,
        };
        if !same {
            failures.push(format!("{:?}", String::from_utf8_lossy(&input)));
        }
    }
    assert!(
        failures.is_empty(),
        "{} inputs where ClientConn and parse_response_head differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn test_every_single_byte_mutation_agrees_or_is_a_documented_refusal() {
    let mut failures = Vec::new();
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    for input in single_mutations() {
        match compare(&input) {
            Ok(outcome) => {
                let key = match outcome {
                    Outcome::Stricter(e) => format!("stricter: {e:?}"),
                    other => format!("{other:?}"),
                };
                *tally.entry(key).or_default() += 1;
            }
            Err(msg) => failures.push(msg),
        }
    }
    assert!(
        failures.is_empty(),
        "{} disagreements:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!("single-byte mutations, by outcome: {tally:?}");
    // Both verdicts are well represented, so the comparison is not vacuous.
    let agreed = tally.get("Agreed").copied().unwrap_or(0);
    let stricter: usize = tally
        .iter()
        .filter(|(k, _)| k.starts_with("stricter"))
        .map(|(_, v)| *v)
        .sum();
    assert!(agreed > 2000 && stricter > 100, "{tally:#?}");
}

#[test]
fn test_stricter_refusals_are_counted_by_variant() {
    // Where http-net refuses what httparse accepts, grouped by variant: the
    // published "where http-net is stricter than httparse" numbers for
    // responses.
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    for input in single_mutations() {
        if let Ok(Outcome::Stricter(e)) = compare(&input) {
            *tally.entry(format!("{e:?}")).or_default() += 1;
        }
    }
    // Printed for the release notes and docs/SECURITY.md:
    // `cargo test --test prop_httparse_response -- --nocapture stricter`.
    eprintln!("stricter than httparse on responses, by variant: {tally:?}");
    // The classes that must show up from these seeds: line endings, the
    // status code, and framing rules. (httparse refuses whitespace before a
    // colon, obs-fold, and bare CR in responses too, so those never appear
    // here. An empty line before the status line takes two bytes, so it
    // shows up in the targeted shapes and in `near_http`, not here.)
    for expected in [
        "BareLf",
        "InvalidStatus",
        "InvalidContentLength",
        "InvalidTransferEncoding",
    ] {
        assert!(
            tally.contains_key(expected),
            "no {expected} refusal in {tally:#?}"
        );
    }
    for name in tally.keys() {
        assert!(
            [
                "BareLf",
                "InvalidStartLine",
                "InvalidStatus",
                "InvalidContentLength",
                "DuplicateContentLength",
                "ConflictingFraming",
                "InvalidTransferEncoding",
                "UnsupportedTransferEncoding",
                "TransferEncodingInHttp10",
                "BodyTooLarge",
            ]
            .contains(&name.as_str()),
            "undocumented stricter refusal {name}"
        );
    }
}

#[test]
fn test_targeted_smuggling_shapes_never_disagree() {
    // Shapes that split a client from an intermediary in the wild. Either
    // both accept the same head, or http-net refuses for a documented
    // reason.
    let inputs: &[&[u8]] = &[
        // Line endings.
        b"HTTP/1.1 200 OK\nContent-Length: 5\n\nhello",
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\n\r\nhello",
        b"HTTP/1.1 200 OK\rContent-Length: 5\r\n\r\nhello",
        b"HTTP/1.1 200 OK\r\nX: a\rContent-Length: 5\r\n\r\nhello",
        b"HTTP/1.1 200 O\rK\r\nContent-Length: 0\r\n\r\n",
        b"\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        b"\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        // Content-Length.
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!",
        b"HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\nhello",
        b"HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\nhello",
        b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0x5\r\n\r\nhello",
        b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2000000\r\n\r\n",
        b"HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
        // Transfer-Encoding.
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 204 No Content\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: xchunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, identity\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked;q=1\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding:\r\n\r\n",
        b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        // Field syntax.
        b"HTTP/1.1 200 OK\r\nX: 1\r\n continued\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n Folded: x\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX: 1\r\n\tcontinued\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length : 5\r\n\r\nhello",
        b"HTTP/1.1 200 OK\r\nContent-Length\t: 5\r\n\r\nhello",
        b"HTTP/1.1 200 OK\r\nContent-Length:\t \t5 \t\r\n\r\nhello",
        b"HTTP/1.1 200 OK\r\nX-\x00: v\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX: a\x00b\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n: novalue\r\n\r\n",
        // Status code.
        b"HTTP/1.1 2 00 OK\r\n\r\n",
        b"HTTP/1.1 20 0 OK\r\n\r\n",
        b"HTTP/1.1  200 OK\r\n\r\n",
        b"HTTP/1.1 200  OK\r\n\r\n",
        b"HTTP/1.1 200\tOK\r\n\r\n",
        b"HTTP/1.1\t200 OK\r\n\r\n",
        b"HTTP/1.1 0200 OK\r\n\r\n",
        b"HTTP/1.1 020 OK\r\n\r\n",
        b"HTTP/1.1 002 OK\r\n\r\n",
        b"HTTP/1.1 +20 OK\r\n\r\n",
        b"HTTP/1.1 -20 OK\r\n\r\n",
        b"HTTP/1.1 000 OK\r\n\r\n",
        b"HTTP/1.1 099 OK\r\n\r\n",
        b"HTTP/1.1 600 OK\r\n\r\n",
        b"HTTP/1.1 999 OK\r\n\r\n",
        b"HTTP/1.1 20 OK\r\n\r\n",
        b"HTTP/1.1 2000 OK\r\n\r\n",
        b"HTTP/1.1 20\r\n\r\n",
        b"HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 2\xd9\xa0\xd9\xa0 OK\r\n\r\n",
        // Reason phrase.
        b"HTTP/1.1 200 O\x00K\r\n\r\n",
        b"HTTP/1.1 200 O\x7fK\r\n\r\n",
        b"HTTP/1.1 200 O\tK \t\r\n\r\n",
        b"HTTP/1.1 200 \xff\r\n\r\n",
        // Version.
        b"HTTP/1.5 200 OK\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/2.0 200 OK\r\n\r\n",
        b"HTTP/1.10 200 OK\r\n\r\n",
        b"http/1.1 200 OK\r\n\r\n",
        b"HTTP/1 200 OK\r\n\r\n",
        b"HTTP/1.1200 OK\r\n\r\n",
        b" HTTP/1.1 200 OK\r\n\r\n",
    ];
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    for input in inputs {
        let outcome = compare(input);
        assert!(outcome.is_ok(), "{}", outcome.unwrap_err());
        *tally.entry(format!("{:?}", outcome.unwrap())).or_default() += 1;
    }
    eprintln!(
        "targeted response shapes ({}), by outcome: {tally:?}",
        inputs.len()
    );
}

/// Near-HTTP built from a dictionary, so many inputs reach the field and
/// framing rules instead of failing on the first byte.
fn near_http() -> impl Strategy<Value = Vec<u8>> {
    // Valid choices are weighted up, so most inputs get past the status line.
    let lead = prop_oneof![8 => Just(""), 1 => Just("\r\n"), 1 => Just("\n")];
    let version = prop_oneof![
        8 => Just("HTTP/1.1"),
        2 => Just("HTTP/1.0"),
        1 => proptest::sample::select(
            &["HTTP/1.9", "HTTP/2.0", "http/1.1", "HTTP/1.10", "HTTP/1"][..]
        ),
    ];
    let status = prop_oneof![
        6 => proptest::sample::select(
            &["200", "204", "304", "101", "100", "103", "404", "599"][..]
        ),
        1 => proptest::sample::select(
            &["099", "600", "999", "000", "20", "2000", "+20", " 200", "2 0"][..]
        ),
    ];
    let reason = proptest::sample::select(
        &[
            " OK",
            " OK",
            " ",
            "",
            " Not Found",
            " caf\u{e9}",
            "  two",
            "\tOK",
            " a\tb",
            "x",
        ][..],
    );
    let field = proptest::sample::select(
        &[
            "Content-Length: 3",
            "Content-Length: 0",
            "Content-Length: 3, 3",
            "Content-Length: -1",
            "Content-Length: 2000000",
            "content-length: 3",
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: gzip, chunked",
            "Transfer-Encoding: gzip",
            "Transfer-Encoding: chunked;q=1",
            "Connection: close",
            "Connection: keep-alive, Upgrade",
            "Upgrade: websocket",
            "Set-Cookie: a=1; Path=/",
            "X-Empty:",
            "X-Tab:\tv\t",
            "X-Obs: \u{e9}",
            " Leading: x",
            "Space : x",
            "NoColon",
            ": novalue",
        ][..],
    );
    let eol =
        proptest::sample::select(&["\r\n", "\r\n", "\r\n", "\r\n", "\r\n", "\r\n", "\n", "\r"][..]);
    (
        lead,
        version,
        status,
        reason,
        proptest::collection::vec((field, eol.clone()), 0..6),
        eol,
        proptest::sample::select(&["", "abc", "0\r\n\r\n", "3\r\nabc\r\n0\r\n\r\n"][..]),
    )
        .prop_map(|(lead, v, s, r, fields, end, body)| {
            let mut out = format!("{lead}{v} {s}{r}\r\n");
            for (f, e) in fields {
                out.push_str(f);
                out.push_str(e);
            }
            out.push_str(end);
            out.push_str(body);
            out.into_bytes()
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8192))]

    #[test]
    fn prop_mutated_responses_agree_with_httparse(
        seed in proptest::sample::select(SEEDS),
        ops in proptest::collection::vec(op(), 1..5),
    ) {
        let input = mutate(seed, &ops);
        let outcome = compare(&input);
        prop_assert!(outcome.is_ok(), "{}", outcome.unwrap_err());
    }

    #[test]
    fn prop_near_http_responses_agree_with_httparse(input in near_http()) {
        let outcome = compare(&input);
        prop_assert!(outcome.is_ok(), "{}", outcome.unwrap_err());
    }

    #[test]
    fn prop_arbitrary_bytes_agree_with_httparse(input in proptest::collection::vec(any::<u8>(), 0..256)) {
        let outcome = compare(&input);
        prop_assert!(outcome.is_ok(), "{}", outcome.unwrap_err());
    }
}
