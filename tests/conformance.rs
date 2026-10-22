//! RFC 9112 / RFC 9110 conformance table.
//!
//! Each row is one MUST or SHOULD statement relevant to this layer
//! (paraphrased, with its section), and a check that runs it against
//! `ServerConn` or `ClientConn`. Where http-net deliberately goes further
//! than the RFC allows it to (a MAY it declines, a lenient option it does
//! not take), the row says so and checks the stricter behaviour; the full
//! list of such choices is in the strictness table of the plan.
//!
//! One test runs every row and reports each failing row by section.

mod common;

use common::{Ev, drive_client, drive_server, server_error};
use http_net::{
    BodyFraming, ClientConn, ClientEvent, HttpError, Limits, Request, Response, ServerConn,
    ServerEvent, Version,
};

struct Row {
    section: &'static str,
    statement: &'static str,
    check: fn() -> Result<(), String>,
}

fn expect_error(input: &[u8], want: HttpError) -> Result<(), String> {
    match server_error(input) {
        Some(e) if e == want => Ok(()),
        other => Err(format!("expected {want:?}, got {other:?}")),
    }
}

fn expect_error_status(input: &[u8], want: u16) -> Result<(), String> {
    match server_error(input) {
        Some(e) if e.status() == Some(want) => Ok(()),
        other => Err(format!("expected an error answered {want}, got {other:?}")),
    }
}

fn serve(input: &[u8]) -> Vec<Ev> {
    drive_server(&[input], Limits::new())
}

fn heads(events: &[Ev]) -> Vec<&Ev> {
    events
        .iter()
        .filter(|e| matches!(e, Ev::Head { .. }))
        .collect()
}

/// Feeds `input` and runs `f` on the first request head.
fn with_head(
    input: &[u8],
    f: impl FnOnce(&http_net::RequestHead<'_>) -> Result<(), String>,
) -> Result<(), String> {
    let mut conn = ServerConn::new();
    let _ = conn.feed(input);
    match conn.poll() {
        Ok(ServerEvent::Request(r)) => f(&r),
        other => Err(format!("expected a request head, got {other:?}")),
    }
}

/// Feeds `input`, reads the whole request, and answers it with `response`.
/// Returns the bytes written and whether the connection then closed.
fn answer(input: &[u8], response: &Response) -> Result<(Vec<u8>, bool), String> {
    let mut conn = ServerConn::new();
    let _ = conn.feed(input);
    loop {
        match conn.poll() {
            Ok(ServerEvent::RequestEnd) => break,
            Ok(ServerEvent::Request(_) | ServerEvent::Body(_)) => {}
            other => return Err(format!("no complete request: {other:?}")),
        }
    }
    let mut out = Vec::new();
    conn.respond(response, &mut out)
        .map_err(|e| format!("respond: {e:?}"))?;
    let closed = matches!(conn.poll(), Ok(ServerEvent::Closed));
    Ok((out, closed))
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

fn client(request: &Request, response: &[u8]) -> Vec<Ev> {
    drive_client(request, &[response], Limits::new())
}

fn get() -> Request {
    Request::get("/").header("host", "a")
}

fn ensure(ok: bool, what: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(what.to_string()) }
}

const ROWS: &[Row] = &[
    // ---- RFC 9112 section 2: message format --------------------------------
    Row {
        section: "RFC 9112 2.2",
        statement: "a recipient MAY recognize a single LF as a line terminator (http-net declines: a bare LF is refused so every hop agrees on line ends)",
        check: || expect_error(b"GET / HTTP/1.1\nHost: a\r\n\r\n", HttpError::BareLf),
    },
    Row {
        section: "RFC 9112 2.2",
        statement: "a bare CR in a protocol element MUST be treated as invalid or replaced by SP (http-net: invalid)",
        check: || expect_error(b"GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n", HttpError::BareCr),
    },
    Row {
        section: "RFC 9112 2.2",
        statement: "a server SHOULD ignore at least one empty line received before the request-line",
        check: || {
            ensure(
                heads(&serve(b"\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n")).len() == 1,
                "leading empty lines not ignored",
            )
        },
    },
    Row {
        section: "RFC 9112 2.2",
        statement: "whitespace between the start-line and the first field: the recipient MUST reject the message or consume the line without processing it (http-net: rejects)",
        check: || expect_error(b"GET / HTTP/1.1\r\n Host: a\r\n\r\n", HttpError::ObsFold),
    },
    Row {
        section: "RFC 9112 2.3",
        statement: "HTTP-version is case-sensitive (HTTP-name is %s\"HTTP\")",
        check: || {
            expect_error(
                b"GET / http/1.1\r\nHost: a\r\n\r\n",
                HttpError::InvalidVersion,
            )
        },
    },
    // ---- RFC 9112 section 3: request line, target, Host -------------------
    Row {
        section: "RFC 9112 3",
        statement: "a request-line that is not method SP request-target SP HTTP-version SHOULD be answered 400",
        check: || expect_error_status(b"GET  / HTTP/1.1\r\nHost: a\r\n\r\n", 400),
    },
    Row {
        section: "RFC 9112 3.2",
        statement: "a server MUST respond 400 to an HTTP/1.1 request that lacks a Host field",
        check: || {
            expect_error(b"GET / HTTP/1.1\r\n\r\n", HttpError::MissingHost)
                .and_then(|()| expect_error_status(b"GET / HTTP/1.1\r\n\r\n", 400))
        },
    },
    Row {
        section: "RFC 9112 3.2",
        statement: "a server MUST respond 400 to a request with more than one Host field",
        check: || {
            expect_error(
                b"GET / HTTP/1.1\r\nHost: a\r\nhost: a\r\n\r\n",
                HttpError::InvalidHost,
            )
        },
    },
    Row {
        section: "RFC 9112 3.2",
        statement: "a server MUST respond 400 to a request whose Host field value is invalid",
        check: || {
            expect_error(
                b"GET / HTTP/1.1\r\nHost: a/b\r\n\r\n",
                HttpError::InvalidHost,
            )
        },
    },
    Row {
        section: "RFC 9112 3.2 (0.3)",
        statement: "Host is uri-host [\":\" port]; an empty host before a port (\":80\") is invalid",
        check: || {
            expect_error(
                b"GET / HTTP/1.1\r\nHost: :80\r\n\r\n",
                HttpError::InvalidHost,
            )
        },
    },
    Row {
        section: "RFC 9112 3.2 (0.3)",
        statement: "a reg-name's pct-encoded triple is \"%\" HEXDIG HEXDIG; a bad escape in Host is invalid",
        check: || {
            expect_error(
                b"GET / HTTP/1.1\r\nHost: a%zz\r\n\r\n",
                HttpError::InvalidHost,
            )
        },
    },
    Row {
        section: "RFC 9112 3.2.2",
        statement: "for an absolute-form target, a server MUST ignore Host and use the target's authority",
        check: || {
            with_head(
                b"GET http://a.test/x HTTP/1.1\r\nHost: b.test\r\n\r\n",
                |r| {
                    ensure(
                        r.host() == Some("a.test") && r.path() == "/x",
                        "authority not used",
                    )
                },
            )
        },
    },
    Row {
        section: "RFC 9112 3.2.3",
        statement: "the authority-form is only used for CONNECT requests",
        check: || {
            expect_error(
                b"GET example.com:443 HTTP/1.1\r\nHost: a\r\n\r\n",
                HttpError::InvalidTarget,
            )
        },
    },
    Row {
        section: "RFC 9112 3.2.4",
        statement: "the asterisk-form is only used for a server-wide OPTIONS request",
        check: || {
            expect_error(
                b"GET * HTTP/1.1\r\nHost: a\r\n\r\n",
                HttpError::InvalidTarget,
            )
            .and_then(|()| {
                ensure(
                    heads(&serve(b"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n")).len() == 1,
                    "OPTIONS * refused",
                )
            })
        },
    },
    Row {
        section: "RFC 9110 4.2.4",
        statement: "userinfo in an http(s) URI is invalid; a recipient SHOULD treat its presence as an error",
        check: || {
            expect_error(
                b"GET http://u@a/ HTTP/1.1\r\nHost: a\r\n\r\n",
                HttpError::InvalidTarget,
            )
        },
    },
    // ---- RFC 9112 section 4: status line (client) --------------------------
    Row {
        section: "RFC 9112 4",
        statement: "a client SHOULD ignore the reason-phrase content; an empty reason is valid",
        check: || {
            ensure(
                matches!(
                    client(&get(), b"HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n").first(),
                    Some(Ev::Status { status: 200, .. })
                ),
                "empty reason refused",
            )
        },
    },
    Row {
        section: "RFC 9112 4 (0.3)",
        statement: "a status line without the SP after the code is accepted by the client (senders MUST send it; real servers omit it)",
        check: || {
            ensure(
                matches!(
                    client(&get(), b"HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n").first(),
                    Some(Ev::Status { status: 200, .. })
                ),
                "status line without SP refused",
            )
        },
    },
    // ---- RFC 9112 section 5: fields ---------------------------------------
    Row {
        section: "RFC 9112 5.1",
        statement: "a server MUST reject, with 400, a request with whitespace between a field name and the colon",
        check: || {
            expect_error(
                b"GET / HTTP/1.1\r\nHost : a\r\n\r\n",
                HttpError::WhitespaceBeforeColon,
            )
            .and_then(|()| expect_error_status(b"GET / HTTP/1.1\r\nHost : a\r\n\r\n", 400))
        },
    },
    Row {
        section: "RFC 9112 5.2",
        statement: "a server that receives obs-fold MUST reject the message or replace each fold with SP (http-net: rejects)",
        check: || {
            expect_error(
                b"GET / HTTP/1.1\r\nHost: a\r\nX: 1\r\n 2\r\n\r\n",
                HttpError::ObsFold,
            )
        },
    },
    Row {
        section: "RFC 9110 5.5",
        statement: "field values containing CR, LF, or NUL are invalid and MUST be rejected or replaced (http-net: rejects)",
        check: || {
            expect_error(
                b"GET / HTTP/1.1\r\nHost: a\r\nX: a\x00b\r\n\r\n",
                HttpError::InvalidHeaderValue,
            )
        },
    },
    Row {
        section: "RFC 9110 5.5",
        statement: "leading and trailing whitespace of a field value is not part of the value",
        check: || {
            with_head(b"GET / HTTP/1.1\r\nHost: a\r\nX: \t v w \t\r\n\r\n", |r| {
                ensure(r.header("x") == Some(&b"v w"[..]), "OWS kept in value")
            })
        },
    },
    Row {
        section: "RFC 9110 5.6.2",
        statement: "field names are tokens",
        check: || {
            expect_error(
                b"GET / HTTP/1.1\r\nHost: a\r\nX(Y): 1\r\n\r\n",
                HttpError::InvalidHeaderName,
            )
        },
    },
    // ---- RFC 9112 section 6: framing --------------------------------------
    Row {
        section: "RFC 9112 6.1",
        statement: "Content-Length together with Transfer-Encoding: a server MAY reject it as a smuggling attempt, and MUST close the connection after responding (http-net: rejects)",
        check: || {
            expect_error(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n", HttpError::ConflictingFraming)
        },
    },
    Row {
        section: "RFC 9112 6.1",
        statement: "Transfer-Encoding in an HTTP/1.0 message makes the framing faulty",
        check: || {
            expect_error(
                b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                HttpError::TransferEncodingInHttp10,
            )
        },
    },
    Row {
        section: "RFC 9112 6.1",
        statement: "a sender MUST NOT apply chunked more than once (http-net refuses a message that does)",
        check: || {
            expect_error(
                b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, chunked\r\n\r\n",
                HttpError::InvalidTransferEncoding,
            )
        },
    },
    Row {
        section: "RFC 9112 6.3 (4)",
        statement: "a request whose Transfer-Encoding does not end in chunked MUST be answered 400 and the connection closed",
        check: || {
            expect_error(
                b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, identity\r\n\r\n",
                HttpError::InvalidTransferEncoding,
            )
            .and_then(|()| {
                expect_error_status(
                    b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: identity\r\n\r\n",
                    400,
                )
            })
        },
    },
    Row {
        section: "RFC 9112 6.3 (5)",
        statement: "an invalid Content-Length in a request is an unrecoverable error answered 400",
        check: || {
            expect_error(
                b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +3\r\n\r\nabc",
                HttpError::InvalidContentLength,
            )
            .and_then(|()| {
                expect_error_status(
                    b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0x3\r\n\r\nabc",
                    400,
                )
            })
        },
    },
    Row {
        section: "RFC 9112 6.3 (6)",
        statement: "a valid Content-Length gives the body length; the next request starts right after it",
        check: || {
            let ev = serve(b"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabcGET /b HTTP/1.1\r\nHost: a\r\n\r\n");
            ensure(
                heads(&ev).len() == 2 && ev.contains(&Ev::Body(b"abc".to_vec())),
                "body or pipelined request mis-framed",
            )
        },
    },
    Row {
        section: "RFC 9112 6.3 (7)",
        statement: "a request with neither Content-Length nor Transfer-Encoding has no body",
        check: || {
            with_head(b"GET / HTTP/1.1\r\nHost: a\r\n\r\nGET", |r| {
                ensure(r.framing() == BodyFraming::None, "body expected")
            })
        },
    },
    Row {
        section: "RFC 9112 6.3 (1)",
        statement: "a response to HEAD has no body, whatever its fields say",
        check: || {
            let ev = client(
                &Request::new("HEAD", "/").header("host", "a"),
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n",
            );
            ensure(
                matches!(
                    ev.first(),
                    Some(Ev::Status {
                        framing: BodyFraming::None,
                        ..
                    })
                ) && ev.get(1) == Some(&Ev::End),
                "HEAD response read a body",
            )
        },
    },
    Row {
        section: "RFC 9112 6.3 (1)",
        statement: "1xx, 204, and 304 responses have no body",
        check: || {
            for resp in [
                &b"HTTP/1.1 204 No Content\r\nContent-Length: 3\r\n\r\n"[..],
                b"HTTP/1.1 304 Not Modified\r\nContent-Length: 3\r\n\r\n",
            ] {
                let ev = client(&get(), resp);
                if !matches!(
                    ev.first(),
                    Some(Ev::Status {
                        framing: BodyFraming::None,
                        ..
                    })
                ) {
                    return Err(format!("bodiless status read a body: {ev:?}"));
                }
            }
            let ev = client(
                &get(),
                b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            );
            ensure(
                matches!(ev.first(), Some(Ev::Status { status: 200, .. })),
                "interim response mis-framed",
            )
        },
    },
    Row {
        section: "RFC 9112 6.3 (2)",
        statement: "a 2xx response to CONNECT switches to a tunnel; Content-Length and Transfer-Encoding are ignored",
        check: || {
            let ev = client(
                &Request::new("CONNECT", "a:443").header("host", "a:443"),
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nTLS",
            );
            ensure(
                ev.last() == Some(&Ev::Upgraded(b"TLS".to_vec())),
                "CONNECT 2xx did not tunnel",
            )
        },
    },
    Row {
        section: "RFC 9112 6.3 (8)",
        statement: "a response with neither Content-Length nor Transfer-Encoding runs until the connection closes",
        check: || {
            let ev = client(&get(), b"HTTP/1.1 200 OK\r\n\r\nall of it");
            ensure(
                ev.contains(&Ev::Body(b"all of it".to_vec())) && ev.last() == Some(&Ev::Closed),
                "until-close body mishandled",
            )
        },
    },
    Row {
        section: "RFC 9110 8.6",
        statement: "a server MUST NOT send Content-Length in a 1xx or 204 response",
        check: || {
            answer(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", &Response::new(204)).and_then(
                |(out, _)| ensure(!contains(&out, b"content-length"), "content-length on 204"),
            )
        },
    },
    Row {
        section: "RFC 9110 8.6",
        statement: "a server MUST NOT send Content-Length in a 2xx response to CONNECT",
        check: || {
            answer(
                b"CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\n",
                &Response::new(200),
            )
            .and_then(|(out, _)| {
                ensure(
                    !contains(&out, b"content-length") && !contains(&out, b"transfer-encoding"),
                    "framing field on CONNECT 2xx",
                )
            })
        },
    },
    Row {
        section: "RFC 9110 9.3.2",
        statement: "the server SHOULD send the same fields for HEAD as for GET, but no content",
        check: || {
            answer(
                b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n",
                &Response::text(200, "hello"),
            )
            .and_then(|(out, _)| {
                ensure(
                    contains(&out, b"content-length: 5") && out.ends_with(b"\r\n\r\n"),
                    "HEAD answer wrong",
                )
            })
        },
    },
    // ---- RFC 9112 section 7: chunked coding -------------------------------
    Row {
        section: "RFC 9112 7.1",
        statement: "a recipient MUST be able to parse and decode the chunked transfer coding, including the trailer section",
        check: || {
            let ev = serve(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-T: 1\r\n\r\n");
            ensure(
                ev.contains(&Ev::Body(b"Wikipedia".to_vec())),
                "chunked body not decoded",
            )
        },
    },
    Row {
        section: "RFC 9112 7.1.1",
        statement: "chunk-ext = *( BWS \";\" BWS name [ BWS \"=\" BWS value ] ); anything else is malformed",
        check: || {
            expect_error(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n4;\r\nWiki\r\n0\r\n\r\n", HttpError::InvalidChunkExtension)
        },
    },
    Row {
        section: "RFC 9110 6.5",
        statement: "trailer fields are not part of the header section; framing fields in a trailer cannot change how the message is framed",
        check: || {
            let ev = serve(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\nContent-Length: 50\r\n\r\nGET /next HTTP/1.1\r\nHost: a\r\n\r\n");
            ensure(heads(&ev).len() == 2, "trailer changed framing")
        },
    },
    // ---- RFC 9112 section 9: connection management ------------------------
    Row {
        section: "RFC 9112 9.3",
        statement: "HTTP/1.1 connections persist by default; \"close\" in Connection ends them after the response",
        check: || {
            answer(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", &Response::new(204))
                .and_then(|(_, closed)| ensure(!closed, "HTTP/1.1 closed by default"))?;
            answer(
                b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
                &Response::new(204),
            )
            .and_then(|(out, closed)| {
                ensure(
                    closed && contains(&out, b"connection: close"),
                    "close not honoured",
                )
            })
        },
    },
    Row {
        section: "RFC 9112 9.3",
        statement: "an HTTP/1.0 connection persists only when the client sent keep-alive",
        check: || {
            answer(b"GET / HTTP/1.0\r\n\r\n", &Response::new(204))
                .and_then(|(_, closed)| ensure(closed, "HTTP/1.0 kept alive without asking"))?;
            answer(
                b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
                &Response::new(204),
            )
            .and_then(|(out, closed)| {
                ensure(
                    !closed && contains(&out, b"connection: keep-alive"),
                    "keep-alive not honoured",
                )
            })
        },
    },
    Row {
        section: "RFC 9112 9.3",
        statement: "a server that responds before reading the entire request body must close the connection (it cannot reuse it)",
        check: || {
            let mut conn = ServerConn::new();
            let _ = conn.feed(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nab");
            let _ = conn.poll();
            let mut out = Vec::new();
            conn.respond(&Response::new(413), &mut out)
                .map_err(|e| format!("{e:?}"))?;
            ensure(
                contains(&out, b"connection: close")
                    && matches!(conn.poll(), Ok(ServerEvent::Closed)),
                "kept alive with unread body",
            )
        },
    },
    Row {
        section: "RFC 9112 9.3.2",
        statement: "a server MUST send responses to pipelined requests in the order the requests were received",
        check: || {
            let mut conn = ServerConn::new();
            let _ =
                conn.feed(b"GET /a HTTP/1.1\r\nHost: a\r\n\r\nGET /b HTTP/1.1\r\nHost: a\r\n\r\n");
            let mut seen = Vec::new();
            loop {
                match conn.poll() {
                    Ok(ServerEvent::Request(r)) => seen.push(r.target().to_string()),
                    Ok(ServerEvent::RequestEnd) => {
                        // The second request is not parsed before the first is answered.
                        if !matches!(conn.poll(), Ok(ServerEvent::AwaitingResponse)) {
                            return Err("next request parsed before the response".into());
                        }
                        conn.respond(&Response::new(204), &mut Vec::new())
                            .map_err(|e| format!("{e:?}"))?;
                    }
                    Ok(ServerEvent::NeedInput) => break,
                    other => return Err(format!("{other:?}")),
                }
            }
            ensure(seen == ["/a", "/b"], "pipelined order lost")
        },
    },
    Row {
        section: "RFC 9112 9.6",
        statement: "after a parse error the connection cannot be resynchronised; nothing after the bad message is parsed",
        check: || {
            let ev = serve(b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: a\r\n\r\n");
            ensure(
                heads(&ev).is_empty() && matches!(ev.last(), Some(Ev::Err(_))),
                "parsed past an error",
            )
        },
    },
    // ---- RFC 9110: semantics this layer enforces --------------------------
    Row {
        section: "RFC 9110 2.5",
        statement: "a recipient MUST process HTTP/1.x with a higher minor version as the highest it implements",
        check: || {
            with_head(b"GET / HTTP/1.4\r\nHost: a\r\n\r\n", |r| {
                ensure(
                    r.version() == Version::Http11,
                    "HTTP/1.4 not processed as 1.1",
                )
            })
        },
    },
    Row {
        section: "RFC 9110 15.6.6",
        statement: "a server that does not support the major version answers 505",
        check: || expect_error_status(b"GET / HTTP/2.0\r\nHost: a\r\n\r\n", 505),
    },
    Row {
        section: "RFC 9110 10.1.1",
        statement: "a server receiving 100-continue in an HTTP/1.1 request with content sends 100 or a final status before waiting for the content",
        check: || {
            let mut conn = ServerConn::new();
            let _ = conn.feed(
                b"PUT /f HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n",
            );
            let expects =
                matches!(conn.poll(), Ok(ServerEvent::Request(r)) if r.expects_continue());
            let mut out = Vec::new();
            ensure(
                expects
                    && conn.send_continue(&mut out).is_ok()
                    && out == b"HTTP/1.1 100 Continue\r\n\r\n",
                "100-continue not handled",
            )
        },
    },
    Row {
        section: "RFC 9110 10.1.1",
        statement: "a server MUST ignore a 100-continue expectation received in an HTTP/1.0 request",
        check: || {
            with_head(
                b"PUT /f HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n",
                |r| ensure(!r.expects_continue(), "HTTP/1.0 expectation honoured"),
            )
        },
    },
    Row {
        section: "RFC 9110 15.2",
        statement: "a server MUST NOT send a 1xx response to an HTTP/1.0 client",
        check: || {
            let mut conn = ServerConn::new();
            let _ = conn.feed(b"PUT /f HTTP/1.0\r\nContent-Length: 2\r\n\r\n");
            let _ = conn.poll();
            ensure(
                conn.send_continue(&mut Vec::new()).is_err(),
                "100 Continue sent to HTTP/1.0",
            )
        },
    },
    Row {
        section: "RFC 9110 7.8",
        statement: "a server MUST ignore an Upgrade field received in an HTTP/1.0 request",
        check: || {
            with_head(
                b"GET / HTTP/1.0\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
                |r| ensure(!r.is_upgrade(), "HTTP/1.0 upgrade honoured"),
            )
        },
    },
    Row {
        section: "RFC 9110 7.8",
        statement: "a 101 response MUST carry an Upgrade field naming the protocol switched to",
        check: || {
            answer(
                b"GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
                &Response::switching_protocols("websocket"),
            )
            .and_then(|(out, _)| {
                ensure(
                    contains(&out, b"upgrade: websocket") && contains(&out, b"connection: upgrade"),
                    "101 without Upgrade",
                )
            })
        },
    },
    Row {
        section: "RFC 9110 7.8 (0.3)",
        statement: "a server MUST NOT switch to a protocol that was not indicated by the client",
        check: || {
            let mut conn = ServerConn::new();
            let _ = conn.feed(
                b"GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
            );
            while !matches!(conn.poll(), Ok(ServerEvent::RequestEnd)) {}
            match conn.respond(&Response::switching_protocols("ftp"), &mut Vec::new()) {
                Err(HttpError::UpgradeNotOffered) => Ok(()),
                other => Err(format!("expected UpgradeNotOffered, got {other:?}")),
            }
        },
    },
    Row {
        section: "RFC 9113 3.1 (0.3)",
        statement: "the h2c upgrade token is deprecated: a request offering only h2c is served as HTTP/1.1",
        check: || {
            with_head(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAoAAA\r\n\r\n", |r| ensure(!r.is_upgrade(), "h2c treated as an upgrade offer"))
        },
    },
    Row {
        section: "RFC 9110 7.8",
        statement: "a client switches protocols only on a 101 to a request that asked for it",
        check: || {
            let ev = client(
                &get(),
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: x\r\n\r\n",
            );
            ensure(
                ev.last() == Some(&Ev::Err(HttpError::UnexpectedUpgrade)),
                "unrequested 101 accepted",
            )
        },
    },
    Row {
        section: "RFC 9110 5.5, RFC 9112 11.1",
        statement: "a sender MUST NOT generate CR, LF, or NUL in a field value (response splitting)",
        check: || {
            let mut conn = ClientConn::new();
            let r = Request::get("/")
                .header("host", "a")
                .header("x", "a\r\nInjected: 1");
            ensure(
                conn.send_request(&r, &mut Vec::new()) == Err(HttpError::BareCr),
                "CR LF accepted in an outgoing value",
            )
        },
    },
    Row {
        section: "RFC 9112 6.1",
        statement: "the connection owns the framing fields of what it sends; a caller cannot add a conflicting Content-Length or Transfer-Encoding",
        check: || {
            let mut conn = ClientConn::new();
            let r = Request::post("/")
                .header("host", "a")
                .header("transfer-encoding", "chunked")
                .body(&b"x"[..]);
            let refused = conn.send_request(&r, &mut Vec::new()) == Err(HttpError::ReservedHeader);
            let idle = matches!(conn.poll(), Ok(ClientEvent::Idle));
            ensure(refused && idle, "caller-set framing field accepted")
        },
    },
    Row {
        section: "RFC 9110 15.2 (0.4)",
        statement: "a server must not send a 1xx response to an HTTP/1.0 client",
        check: || {
            let mut conn = ServerConn::new();
            let _ = conn.feed(b"GET / HTTP/1.0\r\n\r\n");
            while !matches!(conn.poll(), Ok(ServerEvent::RequestEnd)) {}
            let mut out = Vec::new();
            let hints = conn.send_informational(&Response::new(103), &mut out);
            let cont = conn.send_continue(&mut out);
            ensure(
                hints == Err(HttpError::InterimNotAllowed)
                    && cont == Err(HttpError::InterimNotAllowed)
                    && out.is_empty(),
                "1xx written to an HTTP/1.0 client",
            )
        },
    },
    Row {
        section: "RFC 9110 15.2 (0.4)",
        statement: "interim responses precede the final response, any number of them, and a client that did not ask for them skips them",
        check: || {
            let mut conn = ServerConn::new();
            let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
            while !matches!(conn.poll(), Ok(ServerEvent::RequestEnd)) {}
            let mut out = Vec::new();
            conn.send_informational(&Response::new(103), &mut out)
                .map_err(|e| format!("{e:?}"))?;
            conn.send_informational(&Response::new(102), &mut out)
                .map_err(|e| format!("{e:?}"))?;
            conn.respond(&Response::new(204), &mut out)
                .map_err(|e| format!("{e:?}"))?;
            let late = conn.send_informational(&Response::new(103), &mut Vec::new());
            let events = client(&get(), &out);
            ensure(
                late == Err(HttpError::InterimNotAllowed)
                    && matches!(events.first(), Some(Ev::Status { status: 204, .. })),
                "interim after the final response, or not skipped",
            )
        },
    },
    Row {
        section: "RFC 9110 10.1.1 (0.4)",
        statement: "a client that sends 100-continue waits for 100 or a final status before the body; a final status means the body is not sent",
        check: || {
            let mut conn = ClientConn::new();
            let mut out = Vec::new();
            let r = Request::put("/")
                .header("host", "a")
                .content_length(3)
                .expect_continue();
            conn.send_request(&r, &mut out)
                .map_err(|e| format!("{e:?}"))?;
            let waiting = conn.is_waiting_for_continue();
            let _ = conn.feed(b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n");
            let final_first = matches!(conn.poll(), Ok(ClientEvent::Response(_)));
            let refused = conn.send_body(b"abc", &mut out).is_err();
            ensure(
                waiting && final_first && refused,
                "body sent after a final status",
            )
        },
    },
    Row {
        section: "RFC 9110 10.1.1 (0.4)",
        statement: "a server may answer an unknown expectation with 417; the expectation is reported, never acted on, and never changes framing",
        check: || {
            with_head(
                b"POST / HTTP/1.1\r\nHost: a\r\nExpect: x-unknown\r\nContent-Length: 2\r\n\r\nhi",
                |r| {
                    ensure(
                        r.has_unknown_expectation()
                            && !r.expects_continue()
                            && r.content_length() == Some(2),
                        "unknown expectation not reported, or it changed framing",
                    )
                },
            )
        },
    },
    Row {
        section: "RFC 9110 6.5.1 (0.4)",
        statement: "a sender must not generate trailer fields that frame, route, authenticate, modify, or describe the message",
        check: || {
            let mut conn = ServerConn::new();
            let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
            while !matches!(conn.poll(), Ok(ServerEvent::RequestEnd)) {}
            let mut out = Vec::new();
            conn.respond(&Response::new(200).chunked(), &mut out)
                .map_err(|e| format!("{e:?}"))?;
            let refused = [
                "content-length",
                "host",
                "authorization",
                "set-cookie",
                "content-type",
            ]
            .iter()
            .all(|n| {
                conn.end_body_with_trailers(&[(n, b"v")], &mut out)
                    == Err(HttpError::TrailerNotAllowed)
            });
            ensure(refused, "a forbidden trailer field was sent")
        },
    },
    Row {
        section: "RFC 9110 6.5 (0.4)",
        statement: "trailer fields may be discarded and never change how the message was framed",
        check: || {
            let input = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nContent-Length: 99\r\n\r\nGET /next HTTP/1.1\r\nHost: a\r\n\r\n";
            let events = serve(input);
            ensure(
                heads(&events).len() == 2 && events.contains(&Ev::Body(b"hi".to_vec())),
                "a trailer changed framing",
            )
        },
    },
    Row {
        section: "RFC 9110 7.6.1 (0.5)",
        statement: "a proxy MUST remove the hop-by-hop fields, including every field the Connection field lists, before forwarding",
        check: || {
            let mut conn = ServerConn::new();
            let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: up\r\nConnection: X-A\r\nX-A: 1\r\nKeep-Alive: 5\r\nTE: trailers\r\nAccept: */*\r\n\r\n");
            let Ok(ServerEvent::Request(head)) = conn.poll() else {
                return Err("no request".into());
            };
            let mut out = Vec::new();
            ClientConn::new()
                .send_request(&Request::forward_from(&head), &mut out)
                .map_err(|e| format!("{e:?}"))?;
            ensure(
                out == b"GET / HTTP/1.1\r\nHost: up\r\nAccept: */*\r\n\r\n",
                "a hop-by-hop field was forwarded",
            )
        },
    },
    Row {
        section: "RFC 9112 5.2 (0.5)",
        statement: "a user agent that receives obs-fold in a response MUST replace each fold with one or more SP before interpreting the value (opt-in here; refused by default)",
        check: || {
            let folded = b"HTTP/1.1 200 OK\r\nX: a\r\n b\r\nContent-Length: 0\r\n\r\n";
            let mut conn = ClientConn::new();
            conn.set_leniency(http_net::ClientLeniency::new().with_obs_fold_in_responses(true));
            conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())
                .map_err(|e| format!("{e:?}"))?;
            let _ = conn.feed(folded);
            match conn.poll() {
                Ok(ClientEvent::Response(r)) => ensure(
                    r.header("x") == Some(&b"a   b"[..]),
                    "the fold was not replaced with SP",
                ),
                other => Err(format!("{other:?}")),
            }
        },
    },
    Row {
        section: "RFC 9113 3.4 (0.5)",
        statement: "a connection that starts with the HTTP/2 preface is prior-knowledge HTTP/2, not an HTTP/1.1 request",
        check: || expect_error(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", HttpError::Http2Preface),
    },
];

#[test]
fn test_conformance_table_every_row_holds() {
    let failures: Vec<String> = ROWS
        .iter()
        .filter_map(|row| {
            (row.check)()
                .err()
                .map(|why| format!("{}: {}\n    -> {why}", row.section, row.statement))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} conformance rows failed:\n{}",
        failures.len(),
        ROWS.len(),
        failures.join("\n")
    );
}

#[test]
fn test_conformance_table_is_not_trivial() {
    assert!(ROWS.len() >= 25, "only {} rows", ROWS.len());
    for row in ROWS {
        assert!(row.section.starts_with("RFC "), "{}", row.section);
        assert!(!row.statement.is_empty());
    }
}
