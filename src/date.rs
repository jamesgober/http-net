//! The `Date` field: IMF-fixdate formatting and a per-second cache.
//!
//! The core has no clock (it is sans-IO and `no_std`): the caller supplies
//! the time as Unix seconds. The blocking adapter wraps the system clock in
//! `blocking::now_date`. The formatting grammar is RFC 9110 section 5.6.7;
//! it moves to `parse-net` once http-net depends on it, and the cache stays
//! here.

use core::fmt;

/// The last second IMF-fixdate can show: 9999-12-31T23:59:59Z.
const MAX_SECONDS: u64 = 253_402_300_799;

/// A formatted `Date` value: an IMF-fixdate such as
/// `Sun, 06 Nov 1994 08:49:37 GMT` (always 29 bytes).
///
/// # Examples
///
/// ```
/// use http_net::HttpDate;
///
/// let d = HttpDate::from_unix_seconds(784_111_777);
/// assert_eq!(d.as_str(), "Sun, 06 Nov 1994 08:49:37 GMT");
/// assert_eq!(d.as_bytes().len(), 29);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HttpDate([u8; 29]);

impl HttpDate {
    /// Formats `secs` seconds after the Unix epoch. Times after the year
    /// 9999 are shown as its last second, the latest the format can hold.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_net::HttpDate;
    ///
    /// assert_eq!(HttpDate::from_unix_seconds(0).as_str(), "Thu, 01 Jan 1970 00:00:00 GMT");
    /// assert_eq!(HttpDate::from_unix_seconds(u64::MAX).as_str(), "Fri, 31 Dec 9999 23:59:59 GMT");
    /// ```
    #[must_use]
    pub const fn from_unix_seconds(secs: u64) -> Self {
        const WEEKDAYS: [&[u8; 3]; 7] = [b"Thu", b"Fri", b"Sat", b"Sun", b"Mon", b"Tue", b"Wed"];
        const MONTHS: [&[u8; 3]; 12] = [
            b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
            b"Dec",
        ];
        let secs = if secs > MAX_SECONDS {
            MAX_SECONDS
        } else {
            secs
        };
        let days = secs / 86_400;
        let rem = secs % 86_400;
        let (year, month, day) = civil_from_days(days);
        let mut out = *b"Thu, 01 Jan 1970 00:00:00 GMT";
        copy3(&mut out, 0, WEEKDAYS[(days % 7) as usize]);
        two_digits(&mut out, 5, day);
        copy3(&mut out, 8, MONTHS[(month - 1) as usize]);
        two_digits(&mut out, 12, year / 100);
        two_digits(&mut out, 14, year % 100);
        two_digits(&mut out, 17, rem / 3600);
        two_digits(&mut out, 20, rem % 3600 / 60);
        two_digits(&mut out, 23, rem % 60);
        Self(out)
    }

    /// The 29 bytes of the value.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(http_net::HttpDate::from_unix_seconds(0).as_bytes().ends_with(b" GMT"));
    /// ```
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 29] {
        &self.0
    }

    /// The value as text.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(http_net::HttpDate::from_unix_seconds(0).as_str().starts_with("Thu, "));
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Built only from ASCII digits, names, and separators.
        core::str::from_utf8(&self.0).unwrap_or("")
    }
}

impl fmt::Debug for HttpDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("HttpDate").field(&self.as_str()).finish()
    }
}

impl fmt::Display for HttpDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A `Date` value reformatted at most once per second.
///
/// A server writes `date` on every response; formatting it once per second
/// instead of once per response saves the calendar arithmetic on all but the
/// first response of each second. Keep one per thread or per connection
/// driver: it is plain data, not shared state.
///
/// # Examples
///
/// ```
/// use http_net::DateCache;
///
/// let mut cache = DateCache::new();
/// assert_eq!(cache.update(784_111_777).as_str(), "Sun, 06 Nov 1994 08:49:37 GMT");
/// // Same second: the stored value, no formatting.
/// assert_eq!(cache.update(784_111_777).as_str(), "Sun, 06 Nov 1994 08:49:37 GMT");
/// assert_eq!(cache.update(784_111_778).as_str(), "Sun, 06 Nov 1994 08:49:38 GMT");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DateCache {
    /// The second `date` shows; `None` before the first update.
    second: Option<u64>,
    date: HttpDate,
}

impl Default for DateCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DateCache {
    /// An empty cache; [`current`](Self::current) shows the epoch until the
    /// first [`update`](Self::update).
    ///
    /// # Examples
    ///
    /// ```
    /// let cache = http_net::DateCache::new();
    /// assert_eq!(cache.current().as_str(), "Thu, 01 Jan 1970 00:00:00 GMT");
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            second: None,
            date: HttpDate::from_unix_seconds(0),
        }
    }

    /// The value for `unix_seconds`, reformatted only when the second
    /// differs from the last update.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut cache = http_net::DateCache::new();
    /// assert!(cache.update(1_000_000_000).as_str().contains("2001"));
    /// ```
    pub fn update(&mut self, unix_seconds: u64) -> &HttpDate {
        if self.second != Some(unix_seconds) {
            self.date = HttpDate::from_unix_seconds(unix_seconds);
            self.second = Some(unix_seconds);
        }
        &self.date
    }

    /// The value from the last update.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut cache = http_net::DateCache::new();
    /// let _ = cache.update(86_400);
    /// assert_eq!(cache.current().as_str(), "Fri, 02 Jan 1970 00:00:00 GMT");
    /// ```
    #[must_use]
    pub const fn current(&self) -> &HttpDate {
        &self.date
    }
}

const fn copy3(dst: &mut [u8; 29], at: usize, src: &[u8; 3]) {
    dst[at] = src[0];
    dst[at + 1] = src[1];
    dst[at + 2] = src[2];
}

const fn two_digits(dst: &mut [u8; 29], at: usize, v: u64) {
    dst[at] = b'0' + (v / 10 % 10) as u8;
    dst[at + 1] = b'0' + (v % 10) as u8;
}

/// Days since 1970-01-01 to (year, month 1..=12, day 1..=31), after Howard
/// Hinnant's `civil_from_days`, for dates on or after the epoch.
const fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + (month <= 2) as u64;
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_date_known_values() {
        for (secs, text) in [
            (0, "Thu, 01 Jan 1970 00:00:00 GMT"),
            (784_111_777, "Sun, 06 Nov 1994 08:49:37 GMT"),
            (951_782_400, "Tue, 29 Feb 2000 00:00:00 GMT"),
            (1_791_072_000, "Sun, 04 Oct 2026 00:00:00 GMT"),
            (4_107_542_400, "Mon, 01 Mar 2100 00:00:00 GMT"),
            (MAX_SECONDS, "Fri, 31 Dec 9999 23:59:59 GMT"),
            (MAX_SECONDS + 1, "Fri, 31 Dec 9999 23:59:59 GMT"),
        ] {
            assert_eq!(HttpDate::from_unix_seconds(secs).as_str(), text, "{secs}");
        }
    }

    /// The calendar matches a day-by-day walk from the epoch, so no month or
    /// leap-year boundary between 1970 and 2400 is off by one.
    #[test]
    fn test_civil_from_days_matches_a_day_by_day_walk() {
        let (mut y, mut m, mut d) = (1970u64, 1u64, 1u64);
        for days in 0..157_000u64 {
            assert_eq!(civil_from_days(days), (y, m, d), "day {days}");
            let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
            let len = match m {
                2 if leap => 29,
                2 => 28,
                4 | 6 | 9 | 11 => 30,
                _ => 31,
            };
            d += 1;
            if d > len {
                d = 1;
                m += 1;
                if m > 12 {
                    m = 1;
                    y += 1;
                }
            }
        }
    }

    #[test]
    fn test_date_cache_reformats_only_on_a_new_second() {
        let mut cache = DateCache::new();
        let a = *cache.update(10);
        assert_eq!(cache.second, Some(10));
        assert_eq!(*cache.update(10), a);
        let b = *cache.update(11);
        assert_ne!(a, b);
        // Going back in time is a new second too.
        assert_eq!(*cache.update(10), a);
        assert_eq!(cache.current(), &a);
    }
}
