//! Differential test against a reference parser.
//!
//! The reference (`tests/common/reference.rs`, shared with the fuzz
//! targets) is written straight from the RFC 9112 / RFC 9110
//! ABNF, independently of the crate's code: it takes a complete message,
//! splits it into lines, and checks each rule in the most obvious way, with
//! no incremental state, no buffer management, and its own character
//! classes. Valid seed requests are mutated (bytes inserted, replaced, or
//! removed, biased towards the bytes that matter to framing) and both
//! parsers must agree on whether the first message is valid and, if it is,
//! on its method, target, version, fields, and body.

mod common;

use common::reference::{crate_first, reference};
use proptest::prelude::*;

const SEEDS: &[&[u8]] = &[
    b"GET /index.html?x=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n",
    b"POST /form HTTP/1.1\r\nHost: a:8080\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello",
    b"POST /up HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n4;x=\"y\"\r\nWiki\r\n5\r\npedia\r\n0\r\nT: v\r\n\r\n",
    b"OPTIONS * HTTP/1.1\r\nHost: [::1]:80\r\n\r\n",
    b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
    b"GET http://example.com/a%20b HTTP/1.1\r\nHost: example.com\r\n\r\n",
    b"GET / HTTP/1.0\r\nUser-Agent: test/1.0\r\n\r\n",
    b"\r\nPUT /x HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\nX-A: 1\r\nX-B: \t2 \r\n\r\n",
];

const INTERESTING: &[u8] = b"\r\n \t:;,=\"\\\x00\x7f\x80\xffaZ09%/?*-";

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

#[test]
fn test_seeds_are_valid_for_both() {
    for seed in SEEDS {
        let r = reference(seed);
        assert!(
            r.is_some(),
            "reference refuses {:?}",
            String::from_utf8_lossy(seed)
        );
        assert_eq!(r, crate_first(seed), "{:?}", String::from_utf8_lossy(seed));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8192))]

    #[test]
    fn prop_agrees_with_reference(
        seed in proptest::sample::select(SEEDS),
        ops in proptest::collection::vec(op(), 1..4),
    ) {
        let input = mutate(seed, &ops);
        prop_assert_eq!(
            reference(&input),
            crate_first(&input),
            "input {:?}",
            String::from_utf8_lossy(&input)
        );
    }
}

#[test]
fn test_every_single_byte_mutation_agrees() {
    // Exhaustive over one mutation: every position of every seed, every
    // interesting byte inserted and substituted, and every byte removed.
    let mut accepted = 0usize;
    let mut refused = 0usize;
    for seed in SEEDS {
        for pos in 0..=seed.len() {
            let mut ops: Vec<Op> = INTERESTING
                .iter()
                .flat_map(|&b| [Op::Insert(pos, b), Op::Replace(pos, b)])
                .collect();
            ops.push(Op::Remove(pos));
            for op in ops {
                if !matches!(op, Op::Insert(..)) && pos == seed.len() {
                    continue;
                }
                let input = mutate(seed, &[op]);
                let expected = reference(&input);
                assert_eq!(
                    expected,
                    crate_first(&input),
                    "input {:?}",
                    String::from_utf8_lossy(&input)
                );
                if expected.is_some() {
                    accepted += 1;
                } else {
                    refused += 1;
                }
            }
        }
    }
    // Both verdicts are well represented, so the comparison is not vacuous.
    assert!(
        accepted > 1000 && refused > 1000,
        "accepted {accepted}, refused {refused}"
    );
}
