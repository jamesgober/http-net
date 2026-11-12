//! Hop-by-hop fields: the fields a proxy must not forward (RFC 9110
//! section 7.6.1). [`Request::forward_from`](crate::Request::forward_from)
//! uses the same rule.
//!
//! A head's `Connection` options are read once into a sorted list, so
//! filtering a whole head is linear in its size (plus a sort of the
//! options): checking each field against a fresh `connection_options()`
//! would cost fields times options, which a client controls.

use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::head::{Headers, ListElements, RequestHead, ResponseHead};

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
/// This answers for one name, reading every option. To filter a whole
/// head, use [`RequestHead::end_to_end_headers`] or
/// [`ResponseHead::end_to_end_headers`], which read the options once:
/// calling this for every field costs fields times options.
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

/// ASCII case-insensitive order, for the sorted option list.
fn cmp_ignore_case(a: &[u8], b: &[u8]) -> Ordering {
    a.iter()
        .map(u8::to_ascii_lowercase)
        .cmp(b.iter().map(u8::to_ascii_lowercase))
}

/// The hop-by-hop names of one message: the fixed set and every name its
/// `Connection` fields list, read once, sorted, and deduplicated, so each
/// lookup is a binary search. A head without `Connection` allocates
/// nothing.
pub(crate) struct HopByHop<'a> {
    listed: Vec<&'a [u8]>,
}

impl<'a> HopByHop<'a> {
    pub(crate) fn new(options: ListElements<'a, '_>) -> Self {
        let mut listed: Vec<&'a [u8]> = options.collect();
        listed.sort_unstable_by(|a, b| cmp_ignore_case(a, b));
        listed.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
        Self { listed }
    }

    pub(crate) fn contains(&self, name: &str) -> bool {
        HOP_BY_HOP.iter().any(|h| h.eq_ignore_ascii_case(name))
            || self
                .listed
                .binary_search_by(|o| cmp_ignore_case(o, name.as_bytes()))
                .is_ok()
    }
}

/// The fields of `headers` that `hop` does not name.
fn end_to_end<'a>(
    headers: Headers<'a>,
    hop: HopByHop<'a>,
) -> impl Iterator<Item = (&'a str, &'a [u8])> + use<'a> {
    headers.filter(move |(name, _)| !hop.contains(name))
}

impl<'a> RequestHead<'a> {
    /// The fields a proxy forwards: every field except the hop-by-hop ones
    /// (RFC 9110 section 7.6.1, the rule of [`is_hop_by_hop`]), in order.
    /// The `Connection` options are read once, so this is linear in the
    /// head however many options and fields a client sends.
    ///
    /// Framing (`content-length`), `host`, and `proxy-authorization` are
    /// end-to-end by this rule and are kept; a proxy rebuilds or drops
    /// them, as [`Request::forward_from`](crate::Request::forward_from)
    /// does.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ServerConn, ServerEvent};
    ///
    /// let mut conn = ServerConn::new();
    /// let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: X-Trace\r\nX-Trace: 1\r\nKeep-Alive: 5\r\nAccept: */*\r\n\r\n");
    /// let ServerEvent::Request(req) = conn.poll()? else { panic!() };
    /// let names: Vec<&str> = req.end_to_end_headers().map(|(name, _)| name).collect();
    /// assert_eq!(names, ["Host", "Accept"]);
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    pub fn end_to_end_headers(&self) -> impl Iterator<Item = (&'a str, &'a [u8])> + use<'a> {
        end_to_end(self.headers(), HopByHop::new(self.connection_options()))
    }
}

impl<'a> ResponseHead<'a> {
    /// The fields a proxy forwards: every field except the hop-by-hop ones
    /// (as [`RequestHead::end_to_end_headers`]), in order, linear in the
    /// head. `content-length` is kept; the next hop's framing is the
    /// proxy's to write.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{ClientConn, ClientEvent, Request};
    ///
    /// let mut conn = ClientConn::new();
    /// conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())?;
    /// let _ = conn.feed(b"HTTP/1.1 200 OK\r\nConnection: x-hop\r\nX-Hop: 1\r\nETag: \"7\"\r\nContent-Length: 0\r\n\r\n");
    /// let ClientEvent::Response(resp) = conn.poll()? else { panic!() };
    /// let names: Vec<&str> = resp.end_to_end_headers().map(|(name, _)| name).collect();
    /// assert_eq!(names, ["ETag", "Content-Length"]);
    /// # Ok::<(), http_net::HttpError>(())
    /// ```
    pub fn end_to_end_headers(&self) -> impl Iterator<Item = (&'a str, &'a [u8])> + use<'a> {
        end_to_end(
            self.headers(),
            HopByHop::new(self.header_list("connection")),
        )
    }
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

    /// The sorted set answers exactly as the per-name scan does.
    #[test]
    fn test_hop_by_hop_set_agrees_with_is_hop_by_hop() {
        let mut conn = ServerConn::new();
        let _ = conn.feed(
            b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close, X-A, x-a, Zed\r\nConnection: x-b, , \"q\"\r\n\r\n",
        );
        let Ok(ServerEvent::Request(req)) = conn.poll() else {
            panic!("request");
        };
        let set = HopByHop::new(req.connection_options());
        for name in [
            "connection",
            "TE",
            "x-a",
            "X-A",
            "zed",
            "ZED",
            "x-b",
            "close",
            "host",
            "accept",
            "x",
            "x-a2",
            "",
            "\"q\"",
            "trailer",
            "zee",
        ] {
            assert_eq!(
                set.contains(name),
                is_hop_by_hop(name, req.connection_options()),
                "{name}"
            );
        }
    }
}
