//! Redaction of credential-carrying field values in `Debug` output.
//!
//! A `{:?}` of a request in a log line must not print a session cookie or a
//! bearer token. Every `Debug` implementation in the crate that shows field
//! values goes through [`FieldValue`], which prints the value of a
//! credential field as its length only. The accessors (`header`, `headers`,
//! `header_value`) still return the real bytes; only formatting is affected,
//! so redaction costs nothing unless `Debug` runs.

use core::fmt;

/// Fields whose values carry credentials (RFC 9110 sections 11.6.2 and
/// 11.7.2; RFC 6265 sections 4.1 and 4.2). Matched ASCII case-insensitively.
const CREDENTIAL_FIELDS: &[&[u8]] = &[
    b"authorization",
    b"proxy-authorization",
    b"cookie",
    b"set-cookie",
];

/// Whether a field named `name` carries credentials.
pub(crate) fn is_credential(name: &[u8]) -> bool {
    CREDENTIAL_FIELDS
        .iter()
        .any(|c| c.eq_ignore_ascii_case(name))
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
    fn test_is_credential_any_case_matches_the_four_fields() {
        for name in [
            &b"Authorization"[..],
            b"PROXY-AUTHORIZATION",
            b"cookie",
            b"Set-Cookie",
        ] {
            assert!(is_credential(name), "{name:?}");
        }
        for name in [&b"cookies"[..], b"x-authorization", b"", b"set-cookie2"] {
            assert!(!is_credential(name), "{name:?}");
        }
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
