//! RFC 9112 cases as data: requests and responses that must parse, with
//! what they must parse to, and malformed messages with the exact error
//! each must produce. Every case is run fed whole and fed one byte at a
//! time, and both runs must agree.

mod common;

use common::{Ev, drive_client, drive_server};
use http_net::{
    BodyFraming, ClientConn, ClientEvent, HttpError, Limits, Request, Response, ServerConn,
    ServerEvent, TargetForm, Version,
};

struct Accept {
    name: &'static str,
    input: &'static [u8],
    method: &'static str,
    target: &'static str,
    version: Version,
    framing: BodyFraming,
    body: &'static [u8],
    keep_alive: bool,
}

const ACCEPT: &[Accept] = &[
    Accept {
        name: "RFC 9112 3.2.1 origin-form",
        input: b"GET /where?q=now HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        method: "GET",
        target: "/where?q=now",
        version: Version::Http11,
        framing: BodyFraming::None,
        body: b"",
        keep_alive: true,
    },
    Accept {
        name: "RFC 9112 3.2.2 absolute-form",
        input: b"GET http://www.example.org/pub/WWW/TheProject.html HTTP/1.1\r\nHost: www.example.org\r\n\r\n",
        method: "GET",
        target: "http://www.example.org/pub/WWW/TheProject.html",
        version: Version::Http11,
        framing: BodyFraming::None,
        body: b"",
        keep_alive: true,
    },
    Accept {
        name: "RFC 9112 3.2.3 authority-form",
        input: b"CONNECT www.example.com:80 HTTP/1.1\r\nHost: www.example.com:80\r\n\r\n",
        method: "CONNECT",
        target: "www.example.com:80",
        version: Version::Http11,
        framing: BodyFraming::None,
        body: b"",
        keep_alive: true,
    },
    Accept {
        name: "RFC 9112 3.2.4 asterisk-form",
        input: b"OPTIONS * HTTP/1.1\r\nHost: www.example.org:8001\r\n\r\n",
        method: "OPTIONS",
        target: "*",
        version: Version::Http11,
        framing: BodyFraming::None,
        body: b"",
        keep_alive: true,
    },
    Accept {
        name: "RFC 9112 7.1 chunked with extensions and trailer",
        input: b"POST /upload HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n\
                 4;name=value\r\nWiki\r\n5;q=\"quoted \\\" text\"\r\npedia\r\n\
                 e\r\n in\r\n\r\nchunks.\r\n0\r\nExpires: never\r\n\r\n",
        method: "POST",
        target: "/upload",
        version: Version::Http11,
        framing: BodyFraming::Chunked,
        body: b"Wikipedia in\r\n\r\nchunks.",
        keep_alive: true,
    },
    Accept {
        name: "Content-Length body",
        input: b"PUT /f HTTP/1.1\r\nHost: a\r\nContent-Length: 11\r\n\r\nhello world",
        method: "PUT",
        target: "/f",
        version: Version::Http11,
        framing: BodyFraming::Length(11),
        body: b"hello world",
        keep_alive: true,
    },
    Accept {
        name: "RFC 9112 2.2 leading empty lines ignored",
        input: b"\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n",
        method: "GET",
        target: "/",
        version: Version::Http11,
        framing: BodyFraming::None,
        body: b"",
        keep_alive: true,
    },
    Accept {
        name: "HTTP/1.0 needs no Host and closes by default",
        input: b"GET /old HTTP/1.0\r\n\r\n",
        method: "GET",
        target: "/old",
        version: Version::Http10,
        framing: BodyFraming::None,
        body: b"",
        keep_alive: false,
    },
    Accept {
        name: "HTTP/1.0 keep-alive",
        input: b"GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n",
        method: "GET",
        target: "/",
        version: Version::Http10,
        framing: BodyFraming::None,
        body: b"",
        keep_alive: true,
    },
    Accept {
        name: "Connection: close",
        input: b"GET / HTTP/1.1\r\nHost: a\r\nConnection: foo, close\r\n\r\n",
        method: "GET",
        target: "/",
        version: Version::Http11,
        framing: BodyFraming::None,
        body: b"",
        keep_alive: false,
    },
    Accept {
        name: "RFC 9110 2.5 higher minor version processed as 1.1",
        input: b"GET / HTTP/1.7\r\nHost: a\r\n\r\n",
        method: "GET",
        target: "/",
        version: Version::Http11,
        framing: BodyFraming::None,
        body: b"",
        keep_alive: true,
    },
    Accept {
        name: "extension method and empty Host",
        input: b"M-SEARCH /upnp HTTP/1.1\r\nHost:\r\n\r\n",
        method: "M-SEARCH",
        target: "/upnp",
        version: Version::Http11,
        framing: BodyFraming::None,
        body: b"",
        keep_alive: true,
    },
    Accept {
        name: "transfer coding name is case-insensitive, empty list elements ignored",
        input: b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: , Chunked ,\r\n\r\n1\r\nx\r\n0\r\n\r\n",
        method: "POST",
        target: "/",
        version: Version::Http11,
        framing: BodyFraming::Chunked,
        body: b"x",
        keep_alive: true,
    },
    Accept {
        name: "Content-Length: 0 means no body",
        input: b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n",
        method: "POST",
        target: "/",
        version: Version::Http11,
        framing: BodyFraming::None,
        body: b"",
        keep_alive: true,
    },
    Accept {
        name: "OWS around values, tabs, obs-text",
        input: b"GET / HTTP/1.1\r\nHost: \t a \t\r\nX-Text:caf\xc3\xa9 \x80\xff\r\nX-Empty:\r\n\r\n",
        method: "GET",
        target: "/",
        version: Version::Http11,
        framing: BodyFraming::None,
        body: b"",
        keep_alive: true,
    },
    Accept {
        // E-16: a one-byte method is a token.
        name: "one-byte extension method",
        input: b"X / HTTP/1.1\r\nHost: a\r\n\r\n",
        method: "X",
        target: "/",
        version: Version::Http11,
        framing: BodyFraming::None,
        body: b"",
        keep_alive: true,
    },
    Accept {
        // E-37: the scheme is the application's decision, not the parser's.
        name: "absolute-form with a non-http scheme",
        input: b"GET ftp://h/ HTTP/1.1\r\nHost: h\r\n\r\n",
        method: "GET",
        target: "ftp://h/",
        version: Version::Http11,
        framing: BodyFraming::None,
        body: b"",
        keep_alive: true,
    },
];

#[test]
fn test_rfc_accept_cases_parse_whole_and_bytewise() {
    for case in ACCEPT {
        let whole = drive_server(&[case.input], Limits::new());
        let bytes: Vec<&[u8]> = case.input.chunks(1).collect();
        let bytewise = drive_server(&bytes, Limits::new());
        assert_eq!(whole, bytewise, "{}: split changed the result", case.name);
        match &whole[0] {
            Ev::Head {
                method,
                target,
                version,
                framing,
                keep_alive,
                ..
            } => {
                assert_eq!(method, case.method, "{}", case.name);
                assert_eq!(target, case.target, "{}", case.name);
                assert_eq!(*version, case.version, "{}", case.name);
                assert_eq!(*framing, case.framing, "{}", case.name);
                assert_eq!(*keep_alive, case.keep_alive, "{}", case.name);
            }
            other => panic!("{}: expected a request, got {other:?}", case.name),
        }
        let body: Vec<u8> = whole
            .iter()
            .filter_map(|e| match e {
                Ev::Body(b) => Some(b.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(body, case.body, "{}", case.name);
        assert!(whole.contains(&Ev::End), "{}: no end", case.name);
    }
}

#[test]
fn test_header_values_are_trimmed_and_kept_as_bytes() {
    let input =
        b"GET / HTTP/1.1\r\nHost: \t a \t\r\nX-Text:caf\xc3\xa9 \x80\xff\r\nX-Empty:\r\n\r\n";
    let events = drive_server(&[input], Limits::new());
    let Ev::Head { headers, .. } = &events[0] else {
        panic!("expected a request");
    };
    assert_eq!(
        headers,
        &[
            ("Host".to_string(), b"a".to_vec()),
            ("X-Text".to_string(), b"caf\xc3\xa9 \x80\xff".to_vec()),
            ("X-Empty".to_string(), Vec::new()),
        ]
    );
}

const REJECT: &[(&str, &[u8], HttpError)] = &[
    (
        "HTTP/1.1 without Host",
        b"GET / HTTP/1.1\r\n\r\n",
        HttpError::MissingHost,
    ),
    (
        "two Host fields",
        b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
        HttpError::InvalidHost,
    ),
    (
        "Host with a space",
        b"GET / HTTP/1.1\r\nHost: a b\r\n\r\n",
        HttpError::InvalidHost,
    ),
    (
        "Host with a path",
        b"GET / HTTP/1.1\r\nHost: a/b\r\n\r\n",
        HttpError::InvalidHost,
    ),
    (
        "double space before target",
        b"GET  / HTTP/1.1\r\nHost: a\r\n\r\n",
        HttpError::InvalidTarget,
    ),
    (
        "space inside target",
        b"GET /a b HTTP/1.1\r\nHost: a\r\n\r\n",
        HttpError::InvalidTarget,
    ),
    (
        "trailing space after version",
        b"GET / HTTP/1.1 \r\nHost: a\r\n\r\n",
        HttpError::InvalidVersion,
    ),
    (
        "tab as separator",
        b"GET\t/ HTTP/1.1\r\nHost: a\r\n\r\n",
        HttpError::InvalidStartLine,
    ),
    (
        "asterisk with an extension method",
        b"M-SEARCH * HTTP/1.1\r\nHost: a\r\n\r\n",
        HttpError::InvalidTarget,
    ),
    (
        "HTTP/0.9 request line",
        b"GET /\r\n\r\n",
        HttpError::InvalidStartLine,
    ),
    (
        "HTTP/2.0",
        b"GET / HTTP/2.0\r\nHost: a\r\n\r\n",
        HttpError::UnsupportedVersion,
    ),
    (
        "lowercase protocol name",
        b"GET / http/1.1\r\nHost: a\r\n\r\n",
        HttpError::InvalidVersion,
    ),
    (
        "two-digit minor",
        b"GET / HTTP/1.10\r\nHost: a\r\n\r\n",
        HttpError::InvalidVersion,
    ),
    (
        "non-token method",
        b"G(T / HTTP/1.1\r\nHost: a\r\n\r\n",
        HttpError::InvalidMethod,
    ),
    (
        "asterisk outside OPTIONS",
        b"GET * HTTP/1.1\r\nHost: a\r\n\r\n",
        HttpError::InvalidTarget,
    ),
    (
        "fragment in target",
        b"GET /a#b HTTP/1.1\r\nHost: a\r\n\r\n",
        HttpError::InvalidTarget,
    ),
    (
        "bad percent-encoding",
        b"GET /%zz HTTP/1.1\r\nHost: a\r\n\r\n",
        HttpError::InvalidTarget,
    ),
    (
        "non-ASCII target",
        b"GET /\xc3\xa9 HTTP/1.1\r\nHost: a\r\n\r\n",
        HttpError::InvalidTarget,
    ),
    (
        "CONNECT with origin-form",
        b"CONNECT / HTTP/1.1\r\nHost: a\r\n\r\n",
        HttpError::InvalidTarget,
    ),
    (
        "CONNECT without port",
        b"CONNECT example.com HTTP/1.1\r\nHost: a\r\n\r\n",
        HttpError::InvalidTarget,
    ),
    (
        "RFC 9112 5.2 obs-fold",
        b"GET / HTTP/1.1\r\nHost: a\r\nX: 1\r\n 2\r\n\r\n",
        HttpError::ObsFold,
    ),
    (
        "whitespace before first field",
        b"GET / HTTP/1.1\r\n Host: a\r\n\r\n",
        HttpError::ObsFold,
    ),
    (
        "RFC 9112 5.1 space before colon",
        b"GET / HTTP/1.1\r\nHost : a\r\n\r\n",
        HttpError::WhitespaceBeforeColon,
    ),
    (
        "tab before colon",
        b"GET / HTTP/1.1\r\nHost\t: a\r\n\r\n",
        HttpError::WhitespaceBeforeColon,
    ),
    (
        "space inside field name",
        b"GET / HTTP/1.1\r\nHo st: a\r\n\r\n",
        HttpError::InvalidHeaderName,
    ),
    (
        "field line without colon",
        b"GET / HTTP/1.1\r\nHost a\r\n\r\n",
        HttpError::InvalidHeaderName,
    ),
    (
        "empty field name",
        b"GET / HTTP/1.1\r\n: a\r\nHost: a\r\n\r\n",
        HttpError::InvalidHeaderName,
    ),
    (
        "obs-text in field name",
        b"GET / HTTP/1.1\r\nH\xe9: a\r\nHost: a\r\n\r\n",
        HttpError::InvalidHeaderName,
    ),
    (
        "NUL in field value",
        b"GET / HTTP/1.1\r\nHost: a\r\nX: a\x00b\r\n\r\n",
        HttpError::InvalidHeaderValue,
    ),
    (
        "DEL in field value",
        b"GET / HTTP/1.1\r\nHost: a\r\nX: a\x7fb\r\n\r\n",
        HttpError::InvalidHeaderValue,
    ),
    (
        "vertical tab in field value",
        b"GET / HTTP/1.1\r\nHost: a\r\nX: \x0ba\r\n\r\n",
        HttpError::InvalidHeaderValue,
    ),
    (
        "bare LF ends the request line",
        b"GET / HTTP/1.1\nHost: a\r\n\r\n",
        HttpError::BareLf,
    ),
    (
        "bare LF ends a field",
        b"GET / HTTP/1.1\r\nHost: a\n\r\n",
        HttpError::BareLf,
    ),
    (
        "bare LF ends the head",
        b"GET / HTTP/1.1\r\nHost: a\r\n\n",
        HttpError::BareLf,
    ),
    (
        "bare CR in a field value",
        b"GET / HTTP/1.1\r\nHost: a\r\nX: 1\r2\r\n\r\n",
        HttpError::BareCr,
    ),
    (
        "bare CR in the request line",
        b"GET /\rx HTTP/1.1\r\nHost: a\r\n\r\n",
        HttpError::BareCr,
    ),
    (
        "negative Content-Length",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n",
        HttpError::InvalidContentLength,
    ),
    (
        "signed Content-Length",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +1\r\n\r\n",
        HttpError::InvalidContentLength,
    ),
    (
        "Content-Length list",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1, 1\r\n\r\nx",
        HttpError::InvalidContentLength,
    ),
    (
        "Content-Length with inner space",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1 1\r\n\r\n",
        HttpError::InvalidContentLength,
    ),
    (
        "empty Content-Length",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length:\r\n\r\n",
        HttpError::InvalidContentLength,
    ),
    (
        "Content-Length overflow",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 18446744073709551616\r\n\r\n",
        HttpError::InvalidContentLength,
    ),
    (
        "duplicate Content-Length",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
        HttpError::DuplicateContentLength,
    ),
    (
        "Content-Length and Transfer-Encoding",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
        HttpError::ConflictingFraming,
    ),
    (
        "chunked not final",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
        HttpError::InvalidTransferEncoding,
    ),
    (
        "only gzip",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n",
        HttpError::InvalidTransferEncoding,
    ),
    (
        "chunked twice",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, chunked\r\n\r\n",
        HttpError::InvalidTransferEncoding,
    ),
    (
        "chunked with parameters",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked;q=1\r\n\r\n",
        HttpError::InvalidTransferEncoding,
    ),
    (
        "empty Transfer-Encoding",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding:\r\n\r\n",
        HttpError::InvalidTransferEncoding,
    ),
    (
        "gzip then chunked",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        HttpError::UnsupportedTransferEncoding,
    ),
    (
        "RFC 9112 6.1 TE in HTTP/1.0",
        b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n",
        HttpError::TransferEncodingInHttp10,
    ),
    (
        "chunk size with 0x prefix",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0x5\r\n",
        HttpError::InvalidChunkSize,
    ),
    (
        "chunk size with leading space",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n 5\r\n",
        HttpError::InvalidChunkSize,
    ),
    (
        "empty chunk size",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n\r\n",
        HttpError::InvalidChunkSize,
    ),
    (
        "chunk size overflow",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n10000000000000000\r\n",
        HttpError::InvalidChunkSize,
    ),
    (
        "chunk size with trailing space",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5 \r\n",
        HttpError::InvalidChunkExtension,
    ),
    (
        "chunk extension without name",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5;\r\n",
        HttpError::InvalidChunkExtension,
    ),
    (
        "chunk data without CRLF",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabc\r\n",
        HttpError::InvalidChunkTerminator,
    ),
    (
        "chunk data ended by LF",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\n0\r\n\r\n",
        HttpError::InvalidChunkTerminator,
    ),
    (
        "chunk-size line ended by LF",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n2\nab\r\n",
        HttpError::BareLf,
    ),
    (
        "obs-fold in trailer",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nT: 1\r\n 2\r\n\r\n",
        HttpError::ObsFold,
    ),
    (
        "Content-Length over the body limit",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1048577\r\n\r\n",
        HttpError::BodyTooLarge,
    ),
    (
        "chunk over the body limit",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n100001\r\n",
        HttpError::BodyTooLarge,
    ),
    (
        "body cut short",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nshort",
        HttpError::UnexpectedEof,
    ),
    (
        "head cut short",
        b"GET / HTTP/1.1\r\nHost: a\r\n",
        HttpError::UnexpectedEof,
    ),
    (
        // E-18, T-42: prior-knowledge HTTP/2 to an HTTP/1.1-only listener,
        // recognised before version parsing from 0.5 (505 either way).
        "HTTP/2 connection preface",
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        HttpError::Http2Preface,
    ),
    (
        // The preface's first 18 bytes alone are an HTTP/1.1-shaped head
        // with version 2.0; without the rest it is that, not the preface.
        "HTTP/2.0 request line without the rest of the preface",
        b"PRI * HTTP/2.0\r\n\r\n",
        HttpError::UnsupportedVersion,
    ),
];

#[test]
fn test_rfc_reject_cases_produce_exact_errors() {
    for (name, input, expected) in REJECT {
        let whole = drive_server(&[input], Limits::new());
        let bytes: Vec<&[u8]> = input.chunks(1).collect();
        let bytewise = drive_server(&bytes, Limits::new());
        assert_eq!(whole, bytewise, "{name}: split changed the result");
        assert_eq!(whole.last(), Some(&Ev::Err(*expected)), "{name}: {whole:?}");
        assert!(
            expected.status().is_some() || *expected == HttpError::UnexpectedEof,
            "{name}"
        );
    }
}

#[test]
fn test_limit_cases_at_the_boundary() {
    // 100 fields pass, 101 do not (Host counts).
    let mut ok = b"GET / HTTP/1.1\r\nHost: a\r\n".to_vec();
    for i in 0..99 {
        ok.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
    }
    let mut too_many = ok.clone();
    ok.extend_from_slice(b"\r\n");
    too_many.extend_from_slice(b"X-Last: v\r\n\r\n");
    assert!(matches!(
        drive_server(&[&ok], Limits::new())[0],
        Ev::Head { .. }
    ));
    assert_eq!(
        common::server_error(&too_many),
        Some(HttpError::TooManyHeaders)
    );

    // A request line of exactly 8 KiB passes; one byte more does not.
    let fit = 8192 - "GET  HTTP/1.1\r\n".len();
    let line = |n: usize| {
        let mut v = b"GET /".to_vec();
        v.extend(std::iter::repeat_n(b'a', n - 1));
        v.extend_from_slice(b" HTTP/1.1\r\nHost: a\r\n\r\n");
        v
    };
    assert!(matches!(
        drive_server(&[&line(fit)], Limits::new())[0],
        Ev::Head { .. }
    ));
    assert_eq!(
        common::server_error(&line(fit + 1)),
        Some(HttpError::StartLineTooLong)
    );

    // A header section of exactly 16 KiB (fields plus the final CRLF) passes.
    let section = |n: usize| {
        let mut v = b"GET / HTTP/1.1\r\n".to_vec();
        let fixed = "Host: a\r\nX: \r\n\r\n".len();
        v.extend_from_slice(b"Host: a\r\nX: ");
        v.extend(std::iter::repeat_n(b'v', n - fixed));
        v.extend_from_slice(b"\r\n\r\n");
        v
    };
    // The one long line is allowed by a raised field-line budget, so only
    // the section budget is under test here.
    let long_lines = Limits::new().with_max_field_line(16 * 1024);
    assert!(matches!(
        drive_server(&[&section(16 * 1024)], long_lines)[0],
        Ev::Head { .. }
    ));
    let over = drive_server(&[&section(16 * 1024 + 1)], long_lines);
    assert_eq!(over.last(), Some(&Ev::Err(HttpError::HeadersTooLarge)));
    // With the default 8 KiB field-line budget the same line is refused as a
    // line, before the section budget is reached (E-46).
    assert_eq!(
        common::server_error(&section(16 * 1024)),
        Some(HttpError::FieldLineTooLong)
    );

    // Body: exactly the limit passes.
    let limits = Limits::new().with_max_body(5);
    let at = b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n12345";
    assert!(drive_server(&[at], limits).contains(&Ev::Body(b"12345".to_vec())));
    let over = b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\n\r\n123456";
    assert_eq!(
        drive_server(&[over], limits).last(),
        Some(&Ev::Err(HttpError::BodyTooLarge))
    );
}

struct ResponseCase {
    name: &'static str,
    request: fn() -> Request,
    input: &'static [u8],
    expect: Result<(u16, BodyFraming, &'static [u8]), HttpError>,
}

fn get() -> Request {
    Request::get("/").header("host", "a")
}

fn head() -> Request {
    Request::new("HEAD", "/").header("host", "a")
}

const RESPONSES: &[ResponseCase] = &[
    ResponseCase {
        name: "Content-Length",
        request: get,
        input: b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
        expect: Ok((200, BodyFraming::Length(3), b"abc")),
    },
    ResponseCase {
        name: "chunked with trailer",
        request: get,
        input:
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX: 1\r\n\r\n",
        expect: Ok((200, BodyFraming::Chunked, b"abc")),
    },
    ResponseCase {
        name: "RFC 9112 6.3 no framing reads until close",
        request: get,
        input: b"HTTP/1.1 200 OK\r\n\r\nuntil close",
        expect: Ok((200, BodyFraming::UntilClose, b"until close")),
    },
    ResponseCase {
        name: "204 ignores Content-Length",
        request: get,
        input: b"HTTP/1.1 204 No Content\r\nContent-Length: 10\r\n\r\n",
        expect: Ok((204, BodyFraming::None, b"")),
    },
    ResponseCase {
        name: "304 has no body",
        request: get,
        input: b"HTTP/1.1 304 Not Modified\r\nContent-Length: 10\r\n\r\n",
        expect: Ok((304, BodyFraming::None, b"")),
    },
    ResponseCase {
        name: "HEAD response has no body",
        request: head,
        input: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        expect: Ok((200, BodyFraming::None, b"")),
    },
    ResponseCase {
        name: "empty reason phrase",
        request: get,
        input: b"HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n",
        expect: Ok((200, BodyFraming::None, b"")),
    },
    ResponseCase {
        // E-152: senders MUST send the space, but real servers omit it and
        // it cannot change framing, so the client accepts it from 0.3.
        name: "status line without the space after the code",
        request: get,
        input: b"HTTP/1.1 200\r\nContent-Length: 2\r\n\r\nok",
        expect: Ok((200, BodyFraming::Length(2), b"ok")),
    },
    ResponseCase {
        name: "status code of two digits and no reason",
        request: get,
        input: b"HTTP/1.1 20\r\nContent-Length: 0\r\n\r\n",
        expect: Err(HttpError::InvalidStartLine),
    },
    ResponseCase {
        name: "status code glued to the version",
        request: get,
        input: b"HTTP/1.1200 OK\r\nContent-Length: 0\r\n\r\n",
        expect: Err(HttpError::InvalidStartLine),
    },
    ResponseCase {
        name: "four-digit status",
        request: get,
        input: b"HTTP/1.1 2000 OK\r\n\r\n",
        expect: Err(HttpError::InvalidStartLine),
    },
    ResponseCase {
        name: "status above 599",
        request: get,
        input: b"HTTP/1.1 600 Odd\r\n\r\n",
        expect: Err(HttpError::InvalidStatus),
    },
    ResponseCase {
        name: "non-digit status",
        request: get,
        input: b"HTTP/1.1 2x0 OK\r\n\r\n",
        expect: Err(HttpError::InvalidStatus),
    },
    ResponseCase {
        name: "control character in reason",
        request: get,
        input: b"HTTP/1.1 200 O\x01K\r\n\r\n",
        expect: Err(HttpError::InvalidStartLine),
    },
    ResponseCase {
        name: "response smuggling: CL and TE",
        request: get,
        input: b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
        expect: Err(HttpError::ConflictingFraming),
    },
    ResponseCase {
        name: "response obs-fold",
        request: get,
        input: b"HTTP/1.1 200 OK\r\nX: 1\r\n\t2\r\n\r\n",
        expect: Err(HttpError::ObsFold),
    },
    ResponseCase {
        name: "response bare LF",
        request: get,
        input: b"HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n",
        expect: Err(HttpError::BareLf),
    },
    ResponseCase {
        name: "response over the body limit",
        request: get,
        input: b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n",
        expect: Err(HttpError::BodyTooLarge),
    },
];

#[test]
fn test_response_cases() {
    for case in RESPONSES {
        let whole = drive_client(&(case.request)(), &[case.input], Limits::new());
        let bytes: Vec<&[u8]> = case.input.chunks(1).collect();
        let bytewise = drive_client(&(case.request)(), &bytes, Limits::new());
        assert_eq!(whole, bytewise, "{}: split changed the result", case.name);
        match case.expect {
            Ok((status, framing, body)) => {
                let Ev::Status {
                    status: s,
                    framing: f,
                    ..
                } = &whole[0]
                else {
                    panic!("{}: {whole:?}", case.name);
                };
                assert_eq!((*s, *f), (status, framing), "{}", case.name);
                let got: Vec<u8> = whole
                    .iter()
                    .filter_map(|e| match e {
                        Ev::Body(b) => Some(b.clone()),
                        _ => None,
                    })
                    .flatten()
                    .collect();
                assert_eq!(got, body, "{}", case.name);
                assert!(whole.contains(&Ev::End), "{}", case.name);
            }
            Err(e) => assert_eq!(whole.last(), Some(&Ev::Err(e)), "{}: {whole:?}", case.name),
        }
    }
}

// ---------------------------------------------------------------------------
// 0.3 edge-case rows (specification section 12.3)
// ---------------------------------------------------------------------------

/// The first request head of `input`, fed whole, checked by `f`.
fn with_head(input: &[u8], limits: Limits, f: impl FnOnce(&http_net::RequestHead<'_>)) {
    let mut conn = ServerConn::with_limits(limits);
    let _ = conn.feed(input);
    match conn.poll() {
        Ok(ServerEvent::Request(r)) => f(&r),
        other => panic!(
            "expected a request for {:?}, got {other:?}",
            String::from_utf8_lossy(input)
        ),
    }
}

#[test]
fn test_method_of_eight_kib_is_start_line_too_long() {
    // E-17
    let mut input = vec![b'M'; 8 * 1024];
    input.extend_from_slice(b" / HTTP/1.1\r\nHost: a\r\n\r\n");
    assert_eq!(
        common::server_error(&input),
        Some(HttpError::StartLineTooLong)
    );
}

#[test]
fn test_empty_query_is_some_empty() {
    // E-28
    with_head(b"GET /a? HTTP/1.1\r\nHost: a\r\n\r\n", Limits::new(), |r| {
        assert_eq!(r.path(), "/a");
        assert_eq!(r.query(), Some(""));
    });
    with_head(
        b"GET /a?b HTTP/1.1\r\nHost: a\r\n\r\n",
        Limits::new(),
        |r| {
            assert_eq!(r.query(), Some("b"));
        },
    );
}

#[test]
fn test_target_form_reports_all_four_forms() {
    // E-37 and the four forms of RFC 9112 section 3.2.
    let cases: &[(&[u8], TargetForm, &str, &str)] = &[
        (
            b"GET /p?q HTTP/1.1\r\nHost: h\r\n\r\n",
            TargetForm::Origin,
            "h",
            "/p",
        ),
        (
            b"GET ftp://h/ HTTP/1.1\r\nHost: other\r\n\r\n",
            TargetForm::Absolute,
            "h",
            "/",
        ),
        (
            b"GET http://h:8080 HTTP/1.1\r\nHost: other\r\n\r\n",
            TargetForm::Absolute,
            "h:8080",
            "/",
        ),
        (
            b"CONNECT h:443 HTTP/1.1\r\nHost: h:443\r\n\r\n",
            TargetForm::Authority,
            "h:443",
            "h:443",
        ),
        (
            b"OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n",
            TargetForm::Asterisk,
            "h",
            "*",
        ),
    ];
    for (input, form, host, path) in cases {
        with_head(input, Limits::new(), |r| {
            assert_eq!(
                r.target_form(),
                *form,
                "{:?}",
                String::from_utf8_lossy(input)
            );
            assert_eq!(r.host(), Some(*host));
            assert_eq!(r.path(), *path);
        });
    }
}

#[test]
fn test_target_of_exactly_the_remaining_budget_is_accepted() {
    // E-40: "GET " + target + " HTTP/1.1\r\n" fills the start-line budget.
    let limits = Limits::new().with_max_start_line(64);
    let line = |target_len: usize| {
        let mut v = b"GET /".to_vec();
        v.extend(std::iter::repeat_n(b'a', target_len - 1));
        v.extend_from_slice(b" HTTP/1.1\r\nHost: a\r\n\r\n");
        v
    };
    let fit = 64 - "GET  HTTP/1.1\r\n".len();
    with_head(&line(fit), limits, |r| assert_eq!(r.target().len(), fit));
    assert_eq!(
        drive_server(&[&line(fit + 1)], limits).last(),
        Some(&Ev::Err(HttpError::StartLineTooLong))
    );
}

#[test]
fn test_zero_header_budget_accepts_fieldless_http10_only() {
    // E-45
    let limits = Limits::new().with_max_headers(0);
    with_head(b"GET / HTTP/1.0\r\n\r\n", limits, |r| {
        assert_eq!(r.headers().len(), 0);
    });
    assert_eq!(
        drive_server(&[b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"], limits).last(),
        Some(&Ev::Err(HttpError::TooManyHeaders))
    );
}

#[test]
fn test_field_names_with_every_tchar_punctuation_are_accepted() {
    // E-60: the 15 punctuation characters of RFC 9110 section 5.6.2.
    for c in "!#$%&'*+-.^_`|~".chars() {
        let name = format!("X{c}Y");
        let input = format!("GET / HTTP/1.1\r\nHost: a\r\n{name}: v\r\n\r\n");
        with_head(input.as_bytes(), Limits::new(), |r| {
            assert_eq!(r.header(&name), Some(&b"v"[..]), "{name}");
        });
    }
}

#[test]
fn test_duplicate_fields_are_kept_in_order() {
    // E-61
    with_head(
        b"GET / HTTP/1.1\r\nHost: a\r\nAccept: text/html\r\naccept: */*\r\n\r\n",
        Limits::new(),
        |r| {
            assert_eq!(r.header("accept"), Some(&b"text/html"[..]));
            let all: Vec<&[u8]> = r.header_all("ACCEPT").collect();
            assert_eq!(all, [&b"text/html"[..], &b"*/*"[..]]);
            assert_eq!(r.header_all("x-missing").count(), 0);
        },
    );
}

#[test]
fn test_content_length_zero_is_distinct_from_absent() {
    // E-74
    with_head(
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n",
        Limits::new(),
        |r| {
            assert_eq!(r.framing(), BodyFraming::None);
            assert_eq!(r.content_length(), Some(0));
        },
    );
    with_head(b"POST / HTTP/1.1\r\nHost: a\r\n\r\n", Limits::new(), |r| {
        assert_eq!(r.content_length(), None);
    });
    with_head(
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 7\r\n\r\n",
        Limits::new(),
        |r| assert_eq!(r.content_length(), Some(7)),
    );
}

#[test]
fn test_te_request_field_does_not_affect_framing() {
    // E-92: `TE` is not `Transfer-Encoding`.
    with_head(
        b"GET / HTTP/1.1\r\nHost: a\r\nTE: trailers\r\n\r\n",
        Limits::new(),
        |r| assert_eq!(r.framing(), BodyFraming::None),
    );
    let events = drive_server(
        &[b"POST / HTTP/1.1\r\nHost: a\r\nTE: trailers, deflate\r\nContent-Length: 3\r\n\r\nabc"],
        Limits::new(),
    );
    assert!(events.contains(&Ev::Body(b"abc".to_vec())), "{events:?}");
}

#[test]
fn test_ten_thousand_one_byte_chunks_decode_correctly() {
    // E-113
    let mut input = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    let mut expected = Vec::new();
    for i in 0..10_000u32 {
        let b = b'a' + (i % 26) as u8;
        input.extend_from_slice(b"1\r\n");
        input.push(b);
        input.extend_from_slice(b"\r\n");
        expected.push(b);
    }
    input.extend_from_slice(b"0\r\n\r\n");
    let whole = drive_server(&[&input], Limits::new());
    assert!(whole.contains(&Ev::Body(expected)), "body differs");
    assert!(whole.contains(&Ev::End));
    // Odd-sized reads split chunk lines everywhere.
    let pieces: Vec<&[u8]> = input.chunks(7).collect();
    assert_eq!(drive_server(&pieces, Limits::new()), whole);
}

#[test]
fn test_client_half_close_after_complete_request_still_gets_response() {
    // E-123: the client shut down its sending side after the request.
    let mut conn = ServerConn::new();
    let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    conn.feed_eof();
    assert!(matches!(conn.poll(), Ok(ServerEvent::Request(_))));
    assert!(matches!(conn.poll(), Ok(ServerEvent::RequestEnd)));
    let mut out = Vec::new();
    conn.respond(&Response::text(200, "still here"), &mut out)
        .unwrap();
    assert!(out.ends_with(b"still here"));
    assert!(matches!(conn.poll(), Ok(ServerEvent::Closed)));
}

#[test]
fn test_two_set_cookie_fields_are_never_joined() {
    // E-162
    let mut conn = ClientConn::new();
    conn.send_request(&get(), &mut Vec::new()).unwrap();
    let _ = conn.feed(
        b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1; Path=/\r\nset-cookie: b=2, c=3\r\nContent-Length: 0\r\n\r\n",
    );
    let ClientEvent::Response(resp) = conn.poll().unwrap() else {
        panic!("expected a response");
    };
    let all: Vec<&[u8]> = resp.header_all("set-cookie").collect();
    assert_eq!(all, [&b"a=1; Path=/"[..], &b"b=2, c=3"[..]]);
    assert_eq!(resp.content_length(), Some(0));
}

#[test]
fn test_unregistered_status_keeps_the_space_before_an_empty_reason() {
    // E-176: RFC 9112 section 4, `status-code SP [ reason-phrase ]`.
    let mut conn = ServerConn::new();
    let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    while !matches!(conn.poll(), Ok(ServerEvent::RequestEnd)) {}
    let mut out = Vec::new();
    conn.respond(&Response::new(299), &mut out).unwrap();
    assert!(
        out.starts_with(b"HTTP/1.1 299 \r\n"),
        "{:?}",
        String::from_utf8_lossy(&out)
    );
}
