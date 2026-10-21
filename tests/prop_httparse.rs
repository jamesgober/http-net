//! Differential test against `httparse` (dev-dependency only).
//!
//! For every input on which `ServerConn` accepts a complete request head,
//! `httparse` (default, strict configuration) must accept the same head:
//! the same length, method, target, version, and field list. A front end and
//! a back end that disagree on any of those are a request smuggling setup,
//! so every disagreement is either a documented place where `http-net` is
//! stricter (it refused, `httparse` accepted) or a bug.
//!
//! The one documented place where `http-net` accepts and `httparse` does
//! not is `HTTP/1.2` to `HTTP/1.9`, which RFC 9110 section 2.5 says to
//! process as HTTP/1.1 and `httparse` refuses.

use std::collections::BTreeMap;

use http_net::{HttpError, ServerConn, ServerEvent, Version};
use proptest::prelude::*;

#[derive(Debug, PartialEq, Eq)]
struct Head {
    len: usize,
    method: Vec<u8>,
    target: Vec<u8>,
    minor: u8,
    fields: Vec<(Vec<u8>, Vec<u8>)>,
}

enum Ours {
    Head(Head),
    Refused(HttpError),
    Incomplete,
}

fn ours(input: &[u8]) -> Ours {
    let mut conn = ServerConn::new();
    let fed = conn.feed(input);
    let head = match conn.poll() {
        Ok(ServerEvent::Request(r)) => Head {
            len: 0,
            method: r.method_str().as_bytes().to_vec(),
            target: r.target().as_bytes().to_vec(),
            minor: match r.version() {
                Version::Http10 => 0,
                _ => 1,
            },
            fields: r
                .headers()
                .map(|(n, v)| (n.as_bytes().to_vec(), v.to_vec()))
                .collect(),
        },
        Ok(_) => return Ours::Incomplete,
        Err(e) => return Ours::Refused(e),
    };
    // What is left unread after the head event is the body and anything
    // after it, so the head (with any skipped empty lines) is the rest.
    let len = fed - conn.remaining_input().len();
    Ours::Head(Head { len, ..head })
}

enum Theirs {
    Head(Head),
    Partial,
    Refused(httparse::Error),
}

fn theirs(input: &[u8]) -> Theirs {
    let mut headers = [httparse::EMPTY_HEADER; 256];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(input) {
        Ok(httparse::Status::Complete(len)) => Theirs::Head(Head {
            len,
            method: req.method.unwrap_or("").as_bytes().to_vec(),
            target: req.path.unwrap_or("").as_bytes().to_vec(),
            minor: req.version.unwrap_or(255),
            fields: req
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

/// Whether the request line says `HTTP/1.2` to `HTTP/1.9`.
fn has_later_minor_version(input: &[u8]) -> bool {
    let start = input
        .iter()
        .position(|&b| b != b'\r' && b != b'\n')
        .unwrap_or(input.len());
    let line_end = input[start..]
        .iter()
        .position(|&b| b == b'\r')
        .map_or(input.len(), |i| start + i);
    let line = &input[start..line_end];
    line.len() >= 8 && {
        let v = &line[line.len() - 8..];
        v.starts_with(b"HTTP/1.") && (b'2'..=b'9').contains(&v[7])
    }
}

/// Refusals where http-net is stricter than httparse on purpose, each with
/// the rule it enforces. An httparse-accepted input refused for any other
/// reason is a failure.
fn stricter_reason(e: HttpError) -> Option<&'static str> {
    Some(match e {
        HttpError::BareLf => {
            "LF must follow CR (RFC 9112 2.2 MAY accept; refused so every hop agrees on line ends)"
        }
        HttpError::BareCr => "bare CR refused (RFC 9112 2.2)",
        HttpError::MissingHost => "HTTP/1.1 requires Host (RFC 9112 3.2)",
        HttpError::InvalidHost => "one valid Host (RFC 9112 3.2)",
        HttpError::InvalidTarget => {
            "target characters, %XX escapes, and the form the method allows (RFC 9112 3.2)"
        }
        HttpError::InvalidContentLength => "Content-Length is 1*DIGIT (RFC 9112 6.3)",
        HttpError::DuplicateContentLength => "a second Content-Length refused even when equal",
        HttpError::ConflictingFraming => {
            "Content-Length with Transfer-Encoding refused (RFC 9112 6.1)"
        }
        HttpError::InvalidTransferEncoding => {
            "Transfer-Encoding must end in one chunked (RFC 9112 6.3)"
        }
        HttpError::UnsupportedTransferEncoding => {
            "codings other than chunked are not implemented (501)"
        }
        HttpError::TransferEncodingInHttp10 => {
            "Transfer-Encoding in HTTP/1.0 is faulty framing (RFC 9112 6.1)"
        }
        HttpError::ObsFold => {
            "obs-fold and whitespace before the first field refused (RFC 9112 5.2, 2.2)"
        }
        HttpError::WhitespaceBeforeColon => "whitespace before the colon (RFC 9112 5.1 MUST)",
        HttpError::BodyTooLarge => "declared body above max_body, refused on the header line",
        HttpError::StartLineTooLong | HttpError::HeadersTooLarge | HttpError::TooManyHeaders => {
            "configured budgets"
        }
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
        (Ours::Refused(e), Theirs::Head(_)) => match stricter_reason(e) {
            Some(_) => Ok(Outcome::Stricter(e)),
            None => Err(format!(
                "http-net refused with {e:?} a head httparse accepts: {}",
                show()
            )),
        },
        _ => Ok(Outcome::Neither),
    }
}

const SEEDS: &[&[u8]] = &[
    b"GET /index.html?x=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n",
    b"POST /form HTTP/1.1\r\nHost: a:8080\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello",
    b"POST /up HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\n\r\n",
    b"OPTIONS * HTTP/1.1\r\nHost: [::1]:80\r\n\r\n",
    b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
    b"GET http://example.com/a%20b HTTP/1.1\r\nHost: example.com\r\n\r\n",
    b"GET / HTTP/1.0\r\nUser-Agent: test/1.0\r\n\r\n",
    b"\r\nPUT /x HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\nX-A: 1\r\nX-B: \t2 \r\n\r\n",
    b"GET /a HTTP/1.1\r\nHost: h\r\nCookie: a=1\r\nCookie: b=2\r\nX-Obs: caf\xc3\xa9 \x80\xff\r\n\r\n",
];

const INTERESTING: &[u8] = b"\r\n \t:;,=\"\\\x00\x01\x0b\x7f\x80\xffaZ09%/?*-#@[]";

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
    // published "where http-net is stricter than httparse" numbers.
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    for input in single_mutations() {
        if let Ok(Outcome::Stricter(e)) = compare(&input) {
            *tally.entry(format!("{e:?}")).or_default() += 1;
        }
    }
    // Printed for the release notes and docs/SECURITY.md:
    // `cargo test --test prop_httparse -- --nocapture stricter`.
    println!("stricter than httparse, by variant: {tally:?}");
    // The classes that must show up from these seeds: line endings, Host,
    // target rules, and framing rules. (httparse refuses whitespace before
    // a colon and obs-fold in requests too, so those never appear here.)
    for expected in [
        "BareLf",
        "MissingHost",
        "InvalidHost",
        "InvalidTarget",
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
                "BareCr",
                "MissingHost",
                "InvalidHost",
                "InvalidTarget",
                "InvalidContentLength",
                "DuplicateContentLength",
                "ConflictingFraming",
                "InvalidTransferEncoding",
                "UnsupportedTransferEncoding",
                "TransferEncodingInHttp10",
                "ObsFold",
                "WhitespaceBeforeColon",
                "BodyTooLarge",
                "StartLineTooLong",
                "HeadersTooLarge",
                "TooManyHeaders",
            ]
            .contains(&name.as_str()),
            "undocumented stricter refusal {name}"
        );
    }
}

#[test]
fn test_targeted_smuggling_shapes_never_disagree() {
    // Shapes that split hops in the wild. Either both accept the same head,
    // or http-net refuses for a documented reason.
    let inputs: &[&[u8]] = &[
        b"GET / HTTP/1.1\nHost: a\n\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
        b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 5, 5\r\n\r\nhello",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: xchunked\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, identity\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a b\r\n\r\n",
        b"GET /a#frag HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET * HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET example.com:443 HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET http://u@a/ HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\n Folded: x\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nX: 1\r\n Continued\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost : a\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost:\ta\r\nX:\t \tv \t\r\n\r\n",
        b"\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET / HTTP/1.5\r\nHost: a\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 18446744073709551616\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: +5\r\n\r\n",
    ];
    for input in inputs {
        let outcome = compare(input);
        assert!(outcome.is_ok(), "{}", outcome.unwrap_err());
    }
}

/// Near-HTTP built from a dictionary, so many inputs reach the field and
/// framing rules instead of failing on the first byte.
fn near_http() -> impl Strategy<Value = Vec<u8>> {
    let method = proptest::sample::select(
        &[
            "GET", "POST", "PUT", "HEAD", "OPTIONS", "CONNECT", "PATCH", "get", "X-Y", "G T",
        ][..],
    );
    let target = proptest::sample::select(
        &[
            "/",
            "/a?b=c",
            "*",
            "example.com:443",
            "http://a/b",
            "http://a",
            "/a%20b",
            "/a%2",
            "/a b",
            "//",
            "/?",
            "http://u@a/",
            "a:",
            "[::1]:80",
        ][..],
    );
    let version = proptest::sample::select(
        &[
            "HTTP/1.1",
            "HTTP/1.0",
            "HTTP/1.9",
            "HTTP/2.0",
            "http/1.1",
            "HTTP/1.10",
            "HTTP/1",
        ][..],
    );
    let field = proptest::sample::select(
        &[
            "Host: a",
            "Host: a:80",
            "Host: :80",
            "Host: [::1]",
            "Host:",
            "host: b",
            "Content-Length: 3",
            "Content-Length: 0",
            "Content-Length: 3, 3",
            "Content-Length: -1",
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: gzip, chunked",
            "Transfer-Encoding: chunked;q=1",
            "Connection: close",
            "Connection: keep-alive, Upgrade",
            "Upgrade: websocket",
            "Expect: 100-continue",
            "X-Empty:",
            "X-Tab:\tv\t",
            "X-Obs: \u{e9}",
            "Cookie: a=1",
            " Leading: x",
            "Space : x",
            "NoColon",
            ": novalue",
        ][..],
    );
    let eol = proptest::sample::select(&["\r\n", "\r\n", "\r\n", "\n", "\r"][..]);
    (
        method,
        target,
        version,
        proptest::collection::vec((field, eol.clone()), 0..6),
        eol,
        proptest::sample::select(&["", "abc", "0\r\n\r\n", "3\r\nabc\r\n0\r\n\r\n"][..]),
    )
        .prop_map(|(m, t, v, fields, end, body)| {
            let mut s = format!("{m} {t} {v}\r\n");
            for (f, e) in fields {
                s.push_str(f);
                s.push_str(e);
            }
            s.push_str(end);
            s.push_str(body);
            s.into_bytes()
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8192))]

    #[test]
    fn prop_mutated_requests_agree_with_httparse(
        seed in proptest::sample::select(SEEDS),
        ops in proptest::collection::vec(op(), 1..5),
    ) {
        let input = mutate(seed, &ops);
        let outcome = compare(&input);
        prop_assert!(outcome.is_ok(), "{}", outcome.unwrap_err());
    }

    #[test]
    fn prop_near_http_agrees_with_httparse(input in near_http()) {
        let outcome = compare(&input);
        prop_assert!(outcome.is_ok(), "{}", outcome.unwrap_err());
    }

    #[test]
    fn prop_arbitrary_bytes_agree_with_httparse(input in proptest::collection::vec(any::<u8>(), 0..256)) {
        let outcome = compare(&input);
        prop_assert!(outcome.is_ok(), "{}", outcome.unwrap_err());
    }
}
