//! Detection of the HTTP/2 connection preface (RFC 9113 section 3.4).

/// The 24 bytes an HTTP/2 client sends first when it knows the server
/// speaks HTTP/2 ("prior knowledge").
pub(crate) const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Whether `input` starts with the HTTP/2 connection preface:
/// `Some(true)` when the first 24 bytes are the preface, `Some(false)` as
/// soon as a byte differs from it, and `None` while `input` is a shorter,
/// so far matching prefix (read more to decide). At most 24 compares.
///
/// [`ServerConn`](crate::ServerConn) checks this at the start of every
/// connection and refuses the preface with
/// [`HttpError::Http2Preface`](crate::HttpError::Http2Preface); a driver
/// that accepts prior-knowledge HTTP/2 (behind a trusted proxy only) checks
/// it first and routes the connection to an HTTP/2 engine.
///
/// # Examples
///
/// ```
/// use http_net::is_h2_preface;
///
/// assert_eq!(is_h2_preface(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00"), Some(true));
/// assert_eq!(is_h2_preface(b"PRI * HTTP/2"), None);
/// assert_eq!(is_h2_preface(b"GET / HTTP/1.1\r\n"), Some(false));
/// assert_eq!(is_h2_preface(b""), None);
/// ```
#[must_use]
pub fn is_h2_preface(input: &[u8]) -> Option<bool> {
    let n = input.len().min(H2_PREFACE.len());
    if input[..n] != H2_PREFACE[..n] {
        return Some(false);
    }
    if n == H2_PREFACE.len() {
        Some(true)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn test_is_h2_preface_every_prefix_length() {
        for len in 0..H2_PREFACE.len() {
            assert_eq!(is_h2_preface(&H2_PREFACE[..len]), None, "{len}");
        }
        assert_eq!(is_h2_preface(H2_PREFACE), Some(true));
        let mut more = H2_PREFACE.to_vec();
        more.extend_from_slice(b"\x00\x00\x12\x04");
        assert_eq!(is_h2_preface(&more), Some(true));
    }

    #[test]
    fn test_is_h2_preface_any_differing_byte_is_false() {
        for at in 0..H2_PREFACE.len() {
            let mut bad: Vec<u8> = H2_PREFACE.to_vec();
            bad[at] ^= 0x20;
            assert_eq!(is_h2_preface(&bad), Some(false), "{at}");
            // Decided as soon as the differing byte is seen.
            assert_eq!(is_h2_preface(&bad[..=at]), Some(false), "{at}");
        }
        assert_eq!(is_h2_preface(b"PRI * HTTP/1.1\r\n\r\n"), Some(false));
    }
}
