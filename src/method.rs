//! Request methods and sets of them.

use alloc::vec::Vec;

/// The request method.
///
/// Methods are case-sensitive (RFC 9110 section 9.1): `get` is a different,
/// unregistered method and parses as [`Method::Other`]. The exact text is
/// always available from [`RequestHead::method_str`](crate::RequestHead::method_str).
/// A variant is added only when an RFC registers the method.
///
/// # Examples
///
/// ```
/// use http_net::Method;
///
/// assert_eq!(Method::from_bytes(b"GET"), Method::Get);
/// assert_eq!(Method::from_bytes(b"get"), Method::Other);
/// assert_eq!(Method::Post.as_str(), Some("POST"));
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Method {
    /// `GET`
    Get,
    /// `HEAD`: the response carries headers but never a body.
    Head,
    /// `POST`
    Post,
    /// `PUT`
    Put,
    /// `DELETE`
    Delete,
    /// `CONNECT`: the target is in authority form; a 2xx response turns the
    /// connection into a tunnel.
    Connect,
    /// `OPTIONS`: the only method that may use the `*` target.
    Options,
    /// `TRACE`
    Trace,
    /// `PATCH`
    Patch,
    /// Any other token.
    Other,
}

/// Every variant in [`Method::index`] order.
const ALL: [Method; 10] = [
    Method::Get,
    Method::Head,
    Method::Post,
    Method::Put,
    Method::Delete,
    Method::Connect,
    Method::Options,
    Method::Trace,
    Method::Patch,
    Method::Other,
];

impl Method {
    /// Classifies a method token (case-sensitive).
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Method::from_bytes(b"PATCH"), http_net::Method::Patch);
    /// ```
    #[must_use]
    pub fn from_bytes(token: &[u8]) -> Self {
        match token {
            b"GET" => Self::Get,
            b"HEAD" => Self::Head,
            b"POST" => Self::Post,
            b"PUT" => Self::Put,
            b"DELETE" => Self::Delete,
            b"CONNECT" => Self::Connect,
            b"OPTIONS" => Self::Options,
            b"TRACE" => Self::Trace,
            b"PATCH" => Self::Patch,
            _ => Self::Other,
        }
    }

    /// The method's text, or `None` for [`Method::Other`].
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(http_net::Method::Other.as_str(), None);
    /// ```
    #[must_use]
    pub const fn as_str(&self) -> Option<&'static str> {
        Some(match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Connect => "CONNECT",
            Self::Options => "OPTIONS",
            Self::Trace => "TRACE",
            Self::Patch => "PATCH",
            Self::Other => return None,
        })
    }

    /// Whether the method is safe (RFC 9110 section 9.2.1): `GET`, `HEAD`,
    /// `OPTIONS`, `TRACE`. [`Method::Other`] is not; decide from the text.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::Method;
    ///
    /// assert!(Method::Head.is_safe());
    /// assert!(!Method::Put.is_safe());
    /// ```
    #[must_use]
    pub const fn is_safe(&self) -> bool {
        matches!(self, Self::Get | Self::Head | Self::Options | Self::Trace)
    }

    /// Whether the method is idempotent (RFC 9110 section 9.2.2): the safe
    /// methods plus `PUT` and `DELETE`.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::Method;
    ///
    /// assert!(Method::Delete.is_idempotent());
    /// assert!(!Method::Post.is_idempotent());
    /// ```
    #[must_use]
    pub const fn is_idempotent(&self) -> bool {
        self.is_safe() || matches!(self, Self::Put | Self::Delete)
    }

    /// A dense index, `0..=9` in declaration order (`Other` is 9), for bit
    /// sets and lookup tables.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::Method;
    ///
    /// assert_eq!(Method::Get.index(), 0);
    /// assert_eq!(Method::Other.index(), 9);
    /// ```
    #[must_use]
    pub const fn index(&self) -> u8 {
        match self {
            Self::Get => 0,
            Self::Head => 1,
            Self::Post => 2,
            Self::Put => 3,
            Self::Delete => 4,
            Self::Connect => 5,
            Self::Options => 6,
            Self::Trace => 7,
            Self::Patch => 8,
            Self::Other => 9,
        }
    }
}

/// A set of methods: one bit per [`Method`], so a membership check is one
/// AND. For routers and for the `Allow` field of a `405` response.
///
/// [`Method::Other`] cannot be represented precisely: `contains(Method::Other)`
/// means "some extension method is allowed", and
/// [`write_allow`](Self::write_allow) leaves it out.
///
/// # Examples
///
/// ```
/// use http_net::{Method, MethodSet};
///
/// const READ: MethodSet = MethodSet::of(&[Method::Get, Method::Head]);
/// let allowed = READ.with(Method::Post);
/// assert!(allowed.contains(Method::Post));
/// assert!(!allowed.contains(Method::Delete));
///
/// let mut allow = Vec::new();
/// allowed.write_allow(&mut allow);
/// assert_eq!(allow, b"GET, HEAD, POST");
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct MethodSet {
    bits: u16,
}

impl MethodSet {
    /// The empty set.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(http_net::MethodSet::EMPTY.is_empty());
    /// ```
    pub const EMPTY: Self = Self { bits: 0 };

    /// The set of `methods`.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{Method, MethodSet};
    ///
    /// let set = MethodSet::of(&[Method::Put, Method::Delete, Method::Put]);
    /// assert_eq!(set.iter().count(), 2);
    /// ```
    #[must_use]
    pub const fn of(methods: &[Method]) -> Self {
        let mut set = Self::EMPTY;
        let mut i = 0;
        while i < methods.len() {
            set = set.with(methods[i]);
            i += 1;
        }
        set
    }

    /// This set with `method` added.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{Method, MethodSet};
    ///
    /// assert!(MethodSet::EMPTY.with(Method::Get).contains(Method::Get));
    /// ```
    #[must_use]
    pub const fn with(self, method: Method) -> Self {
        Self {
            bits: self.bits | (1 << method.index()),
        }
    }

    /// Whether `method` is in the set.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{Method, MethodSet};
    ///
    /// assert!(!MethodSet::EMPTY.contains(Method::Get));
    /// ```
    #[must_use]
    pub const fn contains(&self, method: Method) -> bool {
        self.bits & (1 << method.index()) != 0
    }

    /// The methods in either set.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{Method, MethodSet};
    ///
    /// let both = MethodSet::of(&[Method::Get]).union(MethodSet::of(&[Method::Post]));
    /// assert!(both.contains(Method::Get) && both.contains(Method::Post));
    /// ```
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// Whether the set is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{Method, MethodSet};
    ///
    /// assert!(!MethodSet::of(&[Method::Get]).is_empty());
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bits == 0
    }

    /// The members in [`Method::index`] order.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{Method, MethodSet};
    ///
    /// let set = MethodSet::of(&[Method::Post, Method::Get]);
    /// assert_eq!(set.iter().collect::<Vec<_>>(), [Method::Get, Method::Post]);
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = Method> + use<> {
        let set = *self;
        ALL.into_iter().filter(move |m| set.contains(*m))
    }

    /// Appends the registered members to `out` as an `Allow` field value,
    /// in [`Method::index`] order, separated by `", "`. `Other` is left out
    /// (it has no name to write).
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::{Method, MethodSet};
    ///
    /// let mut out = Vec::new();
    /// MethodSet::of(&[Method::Options, Method::Get, Method::Other]).write_allow(&mut out);
    /// assert_eq!(out, b"GET, OPTIONS");
    /// ```
    pub fn write_allow(&self, out: &mut Vec<u8>) {
        let mut first = true;
        for name in self.iter().filter_map(|m| m.as_str()) {
            if !first {
                out.extend_from_slice(b", ");
            }
            first = false;
            out.extend_from_slice(name.as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_properties_match_rfc_9110() {
        let safe = [Method::Get, Method::Head, Method::Options, Method::Trace];
        let idempotent = [
            Method::Get,
            Method::Head,
            Method::Options,
            Method::Trace,
            Method::Put,
            Method::Delete,
        ];
        for m in ALL {
            assert_eq!(m.is_safe(), safe.contains(&m), "{m:?}");
            assert_eq!(m.is_idempotent(), idempotent.contains(&m), "{m:?}");
        }
    }

    #[test]
    fn test_method_index_dense_round_trips() {
        for (i, m) in ALL.iter().enumerate() {
            assert_eq!(usize::from(m.index()), i);
            if let Some(text) = m.as_str() {
                assert_eq!(Method::from_bytes(text.as_bytes()), *m);
            }
        }
    }

    #[test]
    fn test_method_set_operations_cover_every_method() {
        let all = MethodSet::of(&ALL);
        assert_eq!(all.iter().count(), 10);
        for m in ALL {
            assert!(all.contains(m));
            assert!(!MethodSet::EMPTY.contains(m));
            assert_eq!(MethodSet::EMPTY.with(m).iter().collect::<Vec<_>>(), [m]);
        }
        assert!(MethodSet::default().is_empty());
        let mut out = Vec::new();
        all.write_allow(&mut out);
        assert_eq!(
            out,
            b"GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH"
        );
        let mut out = Vec::new();
        MethodSet::of(&[Method::Other]).write_allow(&mut out);
        assert!(out.is_empty());
    }
}
