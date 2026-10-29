//! Hop-by-hop fields: the fields a proxy must not forward (RFC 9110
//! section 7.6.1). [`Request::forward_from`](crate::Request::forward_from)
//! uses the same rule.

use crate::head::ListElements;

/// The fields that are hop-by-hop whatever `Connection` lists: they describe
/// this one connection (RFC 9110 section 7.6.1 names `Connection`,
/// `Proxy-Connection`, `Keep-Alive`, `TE`, `Transfer-Encoding`, `Upgrade`;
/// `Trailer` announces trailers of a body that is re-framed per hop).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "transfer-encoding",
    "upgrade",
    "trailer",
];

/// Whether a field named `name` is hop-by-hop: one of `connection`,
/// `keep-alive`, `proxy-connection`, `te`, `transfer-encoding`, `upgrade`,
/// `trailer`, or any name the message's `Connection` field lists (RFC 9110
/// section 7.6.1). A proxy removes these before forwarding a message.
/// Names compare ASCII case-insensitively. For a request, pass
/// [`RequestHead::connection_options`](crate::RequestHead::connection_options)
/// as `connection_options`; for a response, pass
/// [`ResponseHead::header_list("connection")`](crate::ResponseHead::header_list)
/// (a `ResponseHead` has no `connection_options`).
///
/// # Examples
///
/// ```
/// use http_net::{ServerConn, ServerEvent, is_hop_by_hop};
///
/// let mut conn = ServerConn::new();
/// let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: X-Trace\r\nX-Trace: 1\r\nAccept: */*\r\n\r\n");
/// let ServerEvent::Request(req) = conn.poll().unwrap() else { panic!() };
/// assert!(is_hop_by_hop("Keep-Alive", req.connection_options()));
/// assert!(is_hop_by_hop("x-trace", req.connection_options()));
/// assert!(!is_hop_by_hop("accept", req.connection_options()));
/// ```
#[must_use]
pub fn is_hop_by_hop(name: &str, mut connection_options: ListElements<'_, '_>) -> bool {
    HOP_BY_HOP.iter().any(|h| h.eq_ignore_ascii_case(name))
        || connection_options.any(|o| o.eq_ignore_ascii_case(name.as_bytes()))
}

#[cfg(test)]
mod tests {
    use crate::{ServerConn, ServerEvent};

    use super::*;

    #[test]
    fn test_is_hop_by_hop_fixed_set_and_connection_options() {
        let mut conn = ServerConn::new();
        let _ = conn.feed(
            b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close, X-A\r\nConnection: x-b\r\n\r\n",
        );
        let Ok(ServerEvent::Request(req)) = conn.poll() else {
            panic!("request");
        };
        for name in HOP_BY_HOP {
            assert!(is_hop_by_hop(name, req.connection_options()), "{name}");
            let upper = name.to_ascii_uppercase();
            assert!(is_hop_by_hop(&upper, req.connection_options()), "{upper}");
        }
        assert!(is_hop_by_hop("X-A", req.connection_options()));
        assert!(is_hop_by_hop("x-b", req.connection_options()));
        // `close` is an option but also names no field anyone sends; it is
        // still treated as listed.
        assert!(is_hop_by_hop("close", req.connection_options()));
        for name in ["host", "accept", "x-c", "content-length", "trailers"] {
            assert!(!is_hop_by_hop(name, req.connection_options()), "{name}");
        }
    }
}
