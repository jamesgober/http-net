//! The HTTP status code registry: a named constant for every registered
//! code, the canonical reason phrases, and status classes.
//!
//! Status codes are plain `u16` values throughout the crate; these
//! constants give them names. The registry is the IANA HTTP Status Code
//! Registry, with the names RFC 9110 section 15 uses (`413 Content Too
//! Large`, `422 Unprocessable Content`). `306` and `418` are reserved and
//! unused there, so they have no constant and no phrase.
//!
//! # Examples
//!
//! ```
//! use http_net::{Response, reason_phrase, status};
//!
//! let r = Response::new(status::NO_CONTENT);
//! assert_eq!(r.status(), 204);
//! assert_eq!(reason_phrase(status::TOO_EARLY), "Too Early");
//! assert_eq!(status::REQUEST_HEADER_FIELDS_TOO_LARGE, 431);
//! ```

/// One table drives both the constants and `reason_phrase`, so the two can
/// never disagree.
macro_rules! registry {
    ($(($code:literal, $name:ident, $phrase:literal)),* $(,)?) => {
        $(
            #[doc = concat!("`", stringify!($code), " ", $phrase, "`")]
            pub const $name: u16 = $code;
        )*

        /// The canonical reason phrase for a status code: every code in
        /// the IANA HTTP Status Code Registry, with the RFC 9110 names;
        /// `""` for an unassigned code and for the reserved `306` and
        /// `418`.
        ///
        /// When the phrase is empty the serializer still writes the space
        /// after the code (`HTTP/1.1 299 ` CRLF), as RFC 9112 section 4
        /// requires.
        ///
        /// # Examples
        ///
        /// ```
        /// use http_net::reason_phrase;
        ///
        /// assert_eq!(reason_phrase(404), "Not Found");
        /// assert_eq!(reason_phrase(103), "Early Hints");
        /// assert_eq!(reason_phrase(418), "");
        /// assert_eq!(reason_phrase(299), "");
        /// ```
        #[must_use]
        pub const fn reason_phrase(status: u16) -> &'static str {
            match status {
                $($code => $phrase,)*
                _ => "",
            }
        }

        /// The whole status line, `HTTP/1.1 <code> <phrase>` CRLF, for a
        /// registered code, built at compile time so a response head starts
        /// with one copy.
        #[inline]
        pub(crate) const fn status_line(status: u16) -> Option<&'static [u8]> {
            match status {
                $($code => Some(
                    concat!("HTTP/1.1 ", stringify!($code), " ", $phrase, "\r\n").as_bytes()
                ),)*
                _ => None,
            }
        }

        #[cfg(test)]
        const REGISTERED: &[(u16, &str)] = &[$(($code, $phrase)),*];
    };
}

registry! {
    (100, CONTINUE, "Continue"),
    (101, SWITCHING_PROTOCOLS, "Switching Protocols"),
    (102, PROCESSING, "Processing"),
    (103, EARLY_HINTS, "Early Hints"),
    (200, OK, "OK"),
    (201, CREATED, "Created"),
    (202, ACCEPTED, "Accepted"),
    (203, NON_AUTHORITATIVE_INFORMATION, "Non-Authoritative Information"),
    (204, NO_CONTENT, "No Content"),
    (205, RESET_CONTENT, "Reset Content"),
    (206, PARTIAL_CONTENT, "Partial Content"),
    (207, MULTI_STATUS, "Multi-Status"),
    (208, ALREADY_REPORTED, "Already Reported"),
    (226, IM_USED, "IM Used"),
    (300, MULTIPLE_CHOICES, "Multiple Choices"),
    (301, MOVED_PERMANENTLY, "Moved Permanently"),
    (302, FOUND, "Found"),
    (303, SEE_OTHER, "See Other"),
    (304, NOT_MODIFIED, "Not Modified"),
    (305, USE_PROXY, "Use Proxy"),
    (307, TEMPORARY_REDIRECT, "Temporary Redirect"),
    (308, PERMANENT_REDIRECT, "Permanent Redirect"),
    (400, BAD_REQUEST, "Bad Request"),
    (401, UNAUTHORIZED, "Unauthorized"),
    (402, PAYMENT_REQUIRED, "Payment Required"),
    (403, FORBIDDEN, "Forbidden"),
    (404, NOT_FOUND, "Not Found"),
    (405, METHOD_NOT_ALLOWED, "Method Not Allowed"),
    (406, NOT_ACCEPTABLE, "Not Acceptable"),
    (407, PROXY_AUTHENTICATION_REQUIRED, "Proxy Authentication Required"),
    (408, REQUEST_TIMEOUT, "Request Timeout"),
    (409, CONFLICT, "Conflict"),
    (410, GONE, "Gone"),
    (411, LENGTH_REQUIRED, "Length Required"),
    (412, PRECONDITION_FAILED, "Precondition Failed"),
    (413, CONTENT_TOO_LARGE, "Content Too Large"),
    (414, URI_TOO_LONG, "URI Too Long"),
    (415, UNSUPPORTED_MEDIA_TYPE, "Unsupported Media Type"),
    (416, RANGE_NOT_SATISFIABLE, "Range Not Satisfiable"),
    (417, EXPECTATION_FAILED, "Expectation Failed"),
    (421, MISDIRECTED_REQUEST, "Misdirected Request"),
    (422, UNPROCESSABLE_CONTENT, "Unprocessable Content"),
    (423, LOCKED, "Locked"),
    (424, FAILED_DEPENDENCY, "Failed Dependency"),
    (425, TOO_EARLY, "Too Early"),
    (426, UPGRADE_REQUIRED, "Upgrade Required"),
    (428, PRECONDITION_REQUIRED, "Precondition Required"),
    (429, TOO_MANY_REQUESTS, "Too Many Requests"),
    (431, REQUEST_HEADER_FIELDS_TOO_LARGE, "Request Header Fields Too Large"),
    (451, UNAVAILABLE_FOR_LEGAL_REASONS, "Unavailable For Legal Reasons"),
    (500, INTERNAL_SERVER_ERROR, "Internal Server Error"),
    (501, NOT_IMPLEMENTED, "Not Implemented"),
    (502, BAD_GATEWAY, "Bad Gateway"),
    (503, SERVICE_UNAVAILABLE, "Service Unavailable"),
    (504, GATEWAY_TIMEOUT, "Gateway Timeout"),
    (505, HTTP_VERSION_NOT_SUPPORTED, "HTTP Version Not Supported"),
    (506, VARIANT_ALSO_NEGOTIATES, "Variant Also Negotiates"),
    (507, INSUFFICIENT_STORAGE, "Insufficient Storage"),
    (508, LOOP_DETECTED, "Loop Detected"),
    (510, NOT_EXTENDED, "Not Extended"),
    (511, NETWORK_AUTHENTICATION_REQUIRED, "Network Authentication Required"),
}

/// The class of a status code (RFC 9110 section 15).
///
/// # Examples
///
/// ```
/// use http_net::{StatusClass, status_class};
///
/// assert_eq!(status_class(302), Some(StatusClass::Redirection));
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StatusClass {
    /// `1xx`: interim, the request was received and processing continues.
    Informational,
    /// `2xx`: the request was successfully received, understood, and accepted.
    Success,
    /// `3xx`: further action is needed to complete the request.
    Redirection,
    /// `4xx`: the request is wrong or cannot be fulfilled.
    ClientError,
    /// `5xx`: the server failed to fulfil a valid request.
    ServerError,
}

/// The class of `status`, or `None` outside `100..=599`.
///
/// # Examples
///
/// ```
/// use http_net::{StatusClass, status_class};
///
/// assert_eq!(status_class(204), Some(StatusClass::Success));
/// assert_eq!(status_class(503), Some(StatusClass::ServerError));
/// assert_eq!(status_class(99), None);
/// assert_eq!(status_class(600), None);
/// ```
#[must_use]
pub const fn status_class(status: u16) -> Option<StatusClass> {
    Some(match status {
        100..=199 => StatusClass::Informational,
        200..=299 => StatusClass::Success,
        300..=399 => StatusClass::Redirection,
        400..=499 => StatusClass::ClientError,
        500..=599 => StatusClass::ServerError,
        _ => return None,
    })
}

/// Whether a response with `status` to a request with `request` method can
/// carry a body (RFC 9112 section 6.3, rules 1 and 2): false for 1xx, 204,
/// 304, any response to `HEAD`, and a 2xx to `CONNECT` (which turns the
/// connection into a tunnel). For proxies and clients deciding how to read
/// or forward a response.
///
/// # Examples
///
/// ```
/// use http_net::{Method, status_allows_body};
///
/// assert!(status_allows_body(200, Method::Get));
/// assert!(!status_allows_body(200, Method::Head));
/// assert!(!status_allows_body(304, Method::Get));
/// assert!(!status_allows_body(200, Method::Connect));
/// assert!(status_allows_body(407, Method::Connect));
/// ```
#[must_use]
pub const fn status_allows_body(status: u16, request: crate::Method) -> bool {
    !(matches!(request, crate::Method::Head)
        || (status >= 100 && status < 200)
        || status == 204
        || status == 304
        || (matches!(request, crate::Method::Connect) && status >= 200 && status < 300))
}

/// Writes `HTTP/1.1 <code> <phrase>` CRLF: one copy from the compile-time
/// table for a registered code, the parts otherwise (an unregistered code
/// still gets the space after it, RFC 9112 section 4).
#[inline]
pub(crate) fn write_status_line<O: crate::Output + ?Sized>(out: &mut O, status: u16) {
    if let Some(line) = status_line(status) {
        out.put(line);
    } else {
        out.put(b"HTTP/1.1 ");
        crate::scan::push_decimal(out, u64::from(status));
        out.put(b" \r\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_line_table_matches_the_parts_for_every_code() {
        use alloc::{format, vec::Vec};
        for status in 100..=599u16 {
            let mut out = Vec::new();
            write_status_line(&mut out, status);
            let expected = format!("HTTP/1.1 {status} {}\r\n", reason_phrase(status));
            assert_eq!(out, expected.as_bytes(), "status {status}");
            assert_eq!(
                status_line(status).is_some(),
                !reason_phrase(status).is_empty()
            );
        }
    }

    #[test]
    fn test_status_allows_body_follows_rfc_9112_6_3() {
        use crate::Method;
        for status in 100..200 {
            assert!(!status_allows_body(status, Method::Get));
        }
        for m in [Method::Get, Method::Post, Method::Other] {
            assert!(status_allows_body(200, m));
            assert!(!status_allows_body(204, m));
            assert!(!status_allows_body(304, m));
            assert!(status_allows_body(500, m));
        }
        assert!(!status_allows_body(500, Method::Head));
        assert!(!status_allows_body(299, Method::Connect));
        assert!(status_allows_body(300, Method::Connect));
    }

    #[test]
    fn test_reason_phrase_registry_has_every_iana_code() {
        // The 0.3.0 additions, each checked by value.
        let added = [
            (102, "Processing"),
            (103, "Early Hints"),
            (207, "Multi-Status"),
            (208, "Already Reported"),
            (226, "IM Used"),
            (305, "Use Proxy"),
            (402, "Payment Required"),
            (407, "Proxy Authentication Required"),
            (423, "Locked"),
            (424, "Failed Dependency"),
            (425, "Too Early"),
            (451, "Unavailable For Legal Reasons"),
            (506, "Variant Also Negotiates"),
            (507, "Insufficient Storage"),
            (508, "Loop Detected"),
            (510, "Not Extended"),
            (511, "Network Authentication Required"),
        ];
        for (code, phrase) in added {
            assert_eq!(reason_phrase(code), phrase, "{code}");
        }
        assert_eq!(REGISTERED.len(), 61);
        for &(code, phrase) in REGISTERED {
            assert_eq!(reason_phrase(code), phrase);
            assert!(status_class(code).is_some());
        }
    }

    #[test]
    fn test_reason_phrase_unassigned_and_reserved_are_empty() {
        for code in [
            0, 99, 104, 199, 209, 299, 306, 399, 418, 420, 499, 509, 599, 600, 999,
        ] {
            assert_eq!(reason_phrase(code), "", "{code}");
        }
    }

    #[test]
    fn test_status_class_boundaries() {
        assert_eq!(status_class(100), Some(StatusClass::Informational));
        assert_eq!(status_class(199), Some(StatusClass::Informational));
        assert_eq!(status_class(200), Some(StatusClass::Success));
        assert_eq!(status_class(399), Some(StatusClass::Redirection));
        assert_eq!(status_class(400), Some(StatusClass::ClientError));
        assert_eq!(status_class(599), Some(StatusClass::ServerError));
        assert_eq!(status_class(0), None);
    }
}
