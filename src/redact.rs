//! Redaction of credential-carrying field values in `Debug` output.
//!
//! A `{:?}` of a request in a log line must not print a session cookie or a
//! bearer token. Every `Debug` implementation in the crate that shows field
//! values goes through [`FieldValue`], which prints the value of a
//! credential field as its length only. The accessors (`header`, `headers`,
//! `header_value`) still return the real bytes; only formatting is affected,
//! so redaction costs nothing unless `Debug` runs.

use core::fmt;

/// Name parts that mark a field as carrying a credential: the standard
/// fields (`authorization`, `proxy-authorization`, `cookie`, `set-cookie`,
/// RFC 9110 sections 11.6.2 and 11.7.2, RFC 6265) and the usual custom
/// ones (`x-api-key`, `x-auth-token`, `x-csrf-token`, `x-session-id`).
/// Matched ASCII case-insensitively anywhere in the name; redacting a
/// harmless field is cheaper than printing a secret.
const CREDENTIAL_PARTS: &[&[u8]] = &[
    b"auth",
    b"cookie",
    b"token",
    b"secret",
    b"key",
    b"session",
    b"password",
    b"passwd",
    b"csrf",
    b"xsrf",
    b"signature",
    b"credential",
];

/// Whether a field named `name` carries credentials.
pub(crate) fn is_credential(name: &[u8]) -> bool {
    CREDENTIAL_PARTS.iter().any(|part| {
        name.windows(part.len())
            .any(|w| w.eq_ignore_ascii_case(part))
    })
}

/// A request target as `Debug` shows it: the path, and the query as its
/// length only, since a query often carries a token or a signature.
pub(crate) struct Target<'a>(pub(crate) &'a str);

impl fmt::Debug for Target<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.split_once('?') {
            Some((path, query)) => {
                write!(f, "\"{path}?<redacted {} bytes>\"", query.len())
            }
            None => fmt::Debug::fmt(self.0, f),
        }
    }
}

/// A field value as `Debug` shows it: a string when it is UTF-8, bytes
/// otherwise, and `<redacted N bytes>` for a credential field.
pub(crate) struct FieldValue<'a> {
    pub(crate) name: &'a [u8],
    pub(crate) value: &'a [u8],
}

impl fmt::Debug for FieldValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if is_credential(self.name) {
            return write!(f, "<redacted {} bytes>", self.value.len());
        }
        match core::str::from_utf8(self.value) {
            Ok(s) => fmt::Debug::fmt(s, f),
            Err(_) => fmt::Debug::fmt(self.value, f),
        }
    }
}

/// A field name as `Debug` shows it.
pub(crate) struct FieldName<'a>(pub(crate) &'a [u8]);

impl fmt::Debug for FieldName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Names are tokens, so ASCII; anything else prints as bytes.
        match core::str::from_utf8(self.0) {
            Ok(s) => fmt::Debug::fmt(s, f),
            Err(_) => fmt::Debug::fmt(self.0, f),
        }
    }
}

/// Serialized `name: value\r\n` lines (an outgoing message's fields) shown
/// as a list of `(name, value)` pairs with credential values redacted.
pub(crate) struct SerializedFields<'a>(pub(crate) &'a [u8]);

impl fmt::Debug for SerializedFields<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(
                serialized_fields(self.0)
                    .map(|(name, value)| (FieldName(name), FieldValue { name, value })),
            )
            .finish()
    }
}

/// Splits serialized `name: value\r\n` lines into `(name, value)` pairs.
pub(crate) fn serialized_fields(fields: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    fields.split(|&b| b == b'\n').filter_map(|line| {
        let line = line.strip_suffix(b"\r")?;
        let colon = line.iter().position(|&b| b == b':')?;
        Some((&line[..colon], line.get(colon + 2..).unwrap_or(&[])))
    })
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;

    #[test]
    fn test_is_credential_any_case_matches_standard_and_custom_names() {
        for name in [
            &b"Authorization"[..],
            b"PROXY-AUTHORIZATION",
            b"cookie",
            b"Set-Cookie",
            b"X-Api-Key",
            b"x-auth-token",
            b"X-CSRF-Token",
            b"x-session-id",
            b"X-Client-Secret",
            b"x-amz-signature",
            b"www-authenticate",
        ] {
            assert!(is_credential(name), "{name:?}");
        }
        for name in [
            &b"accept"[..],
            b"host",
            b"content-type",
            b"x-request-id",
            b"keep-alive",
            b"",
        ] {
            assert!(!is_credential(name), "{name:?}");
        }
    }

    #[test]
    fn test_target_debug_redacts_the_query_only() {
        assert_eq!(
            format!("{:?}", Target("/cb?access_token=SECRET")),
            "\"/cb?<redacted 19 bytes>\""
        );
        assert_eq!(format!("{:?}", Target("/plain")), "\"/plain\"");
        assert_eq!(format!("{:?}", Target("*")), "\"*\"");
    }

    #[test]
    fn test_field_value_credential_prints_length_only() {
        let v = FieldValue {
            name: b"Cookie",
            value: b"sid=s3cr3t",
        };
        assert_eq!(format!("{v:?}"), "<redacted 10 bytes>");
        let v = FieldValue {
            name: b"accept",
            value: b"text/html",
        };
        assert_eq!(format!("{v:?}"), "\"text/html\"");
        let v = FieldValue {
            name: b"x",
            value: b"\xff",
        };
        assert_eq!(format!("{v:?}"), "[255]");
    }

    #[test]
    fn test_serialized_fields_debug_redacts_and_keeps_order() {
        let shown = format!(
            "{:?}",
            SerializedFields(b"set-cookie: a=1\r\nx-id: 7\r\nauthorization: Basic eDp5\r\n")
        );
        assert_eq!(
            shown,
            "[(\"set-cookie\", <redacted 3 bytes>), (\"x-id\", \"7\"), (\"authorization\", <redacted 10 bytes>)]"
        );
    }
}
