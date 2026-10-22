//! The bounded input buffer shared by the server and client connections.
//!
//! Layout: `data[pin_start..pin_end]` is the pinned head of the message in
//! progress (kept so the caller can still read it while the body streams),
//! `data[pos..filled]` is unread input, `data[filled..]` is spare space, and
//! everything else (earlier messages, consumed body bytes) is reclaimable.
//! Compaction moves the pinned head to the front and the unread input right
//! after it. It only runs when the spare space is exhausted, and the bytes it
//! moves are bounded by the head budget plus one partial line (the parsers
//! consume every complete data run before asking for input), which keeps
//! total copying linear in the input.

use alloc::vec::Vec;

/// Smallest allocation, so tiny connections do not reallocate repeatedly.
const MIN_ALLOC: usize = 4096;

pub(crate) struct Buffer {
    data: Vec<u8>,
    filled: usize,
    pos: usize,
    pin: Option<(usize, usize)>,
    cap: usize,
    eof: bool,
    /// Zero bytes that are no longer needed: a finished message, the stale
    /// copies compaction leaves behind, and everything on reset, release,
    /// and drop.
    wipe: bool,
}

impl Drop for Buffer {
    fn drop(&mut self) {
        if self.wipe {
            zero(&mut self.data);
        }
    }
}

/// Overwrites `bytes` with zeros in a way the optimizer keeps: the slice is
/// passed to `black_box` afterwards, so the stores cannot be removed as dead.
fn zero(bytes: &mut [u8]) {
    bytes.fill(0);
    let _ = core::hint::black_box(bytes);
}

impl Buffer {
    pub(crate) const fn new(cap: usize) -> Self {
        Self {
            data: Vec::new(),
            filled: 0,
            pos: 0,
            pin: None,
            cap,
            eof: false,
            wipe: false,
        }
    }

    /// A buffer that adopts `storage` (its contents are ignored); its
    /// capacity is used up to `cap`.
    pub(crate) fn with_storage(mut storage: Vec<u8>, cap: usize) -> Self {
        storage.clear();
        let usable = storage.capacity().min(cap);
        storage.resize(usable, 0);
        Self {
            data: storage,
            ..Self::new(cap)
        }
    }

    /// Gives the storage back (wiped first when wiping is on), leaving this
    /// buffer empty.
    pub(crate) fn take_storage(&mut self) -> Vec<u8> {
        if self.wipe {
            zero(&mut self.data);
        }
        self.filled = 0;
        self.pos = 0;
        self.pin = None;
        core::mem::take(&mut self.data)
    }

    /// Back to the initial state for a new peer, keeping the allocation
    /// (wiped first when wiping is on).
    pub(crate) fn reset(&mut self) {
        if self.wipe {
            zero(&mut self.data);
        }
        self.filled = 0;
        self.pos = 0;
        self.pin = None;
        self.eof = false;
    }

    /// Frees the allocation when nothing is buffered or pinned; returns
    /// whether memory was released.
    pub(crate) fn shrink(&mut self) -> bool {
        let pinned = self.pin.is_some_and(|(start, end)| end > start);
        if self.pos != self.filled || pinned || self.data.capacity() == 0 {
            return false;
        }
        drop(self.take_storage());
        true
    }

    pub(crate) fn set_wipe(&mut self, wipe: bool) {
        self.wipe = wipe;
    }

    /// Zeroes the bytes of a finished message, from its pinned start to the
    /// read cursor (head, body, and framing), when wiping is on.
    pub(crate) fn wipe_consumed(&mut self) {
        if self.wipe {
            let start = self.pin().min(self.pos);
            let end = self.pos;
            if let Some(region) = self.data.get_mut(start..end) {
                zero(region);
            }
        }
    }

    /// Unread input.
    #[inline]
    pub(crate) fn unread(&self) -> &[u8] {
        self.data.get(self.pos..self.filled).unwrap_or(&[])
    }

    /// Absolute offset of the read cursor.
    #[inline]
    pub(crate) const fn pos(&self) -> usize {
        self.pos
    }

    /// Bytes from absolute `start` to the end of input.
    #[inline]
    pub(crate) fn from(&self, start: usize) -> &[u8] {
        self.data.get(start..self.filled).unwrap_or(&[])
    }

    /// Bytes in the absolute range `start..end`.
    #[inline]
    pub(crate) fn range(&self, start: usize, end: usize) -> &[u8] {
        self.data.get(start..end).unwrap_or(&[])
    }

    /// Marks `n` unread bytes as consumed.
    #[inline]
    pub(crate) fn consume(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.filled);
    }

    /// Pins the bytes from the read cursor on (the start of a message head).
    #[inline]
    pub(crate) fn pin_at_pos(&mut self) {
        self.pin = Some((self.pos, self.pos));
    }

    /// Ends the pinned region at the read cursor (after the head is consumed).
    #[inline]
    pub(crate) fn extend_pin_to_pos(&mut self) {
        if let Some((start, _)) = self.pin {
            self.pin = Some((start, self.pos));
        }
    }

    /// Releases the pin: the previous message's head may be reclaimed.
    #[inline]
    pub(crate) fn unpin(&mut self) {
        self.pin = None;
    }

    /// Absolute offset of the pinned message start.
    #[inline]
    pub(crate) fn pin(&self) -> usize {
        self.pin.map_or(self.pos, |(start, _)| start)
    }

    /// Bytes compaction would free.
    fn reclaimable(&self) -> usize {
        match self.pin {
            Some((start, end)) => start + (self.pos - end),
            None => self.pos,
        }
    }

    #[inline]
    pub(crate) const fn is_eof(&self) -> bool {
        self.eof
    }

    #[inline]
    pub(crate) fn set_eof(&mut self) {
        self.eof = true;
    }

    /// Writable space after the input, made as large as the capacity allows.
    /// Empty only when the buffer is full of bytes it must keep; the parsers
    /// guarantee that never happens while they are waiting for input.
    pub(crate) fn spare(&mut self) -> &mut [u8] {
        if self.filled == self.data.len() {
            let reclaimable = self.reclaimable();
            let len = self.data.len();
            if reclaimable > 0 && (len == self.cap || reclaimable >= len / 2) {
                self.compact();
            } else if len < self.cap {
                let grown = len.saturating_mul(2).max(MIN_ALLOC).min(self.cap);
                self.data.resize(grown, 0);
            } else if reclaimable > 0 {
                self.compact();
            }
        }
        let filled = self.filled;
        self.data.get_mut(filled..).unwrap_or(&mut [])
    }

    /// Records that `n` bytes were written into [`spare`](Self::spare).
    #[inline]
    pub(crate) fn commit(&mut self, n: usize) {
        self.filled = (self.filled + n).min(self.data.len());
    }

    /// Copies as much of `bytes` as fits; returns how many were taken.
    pub(crate) fn feed(&mut self, mut bytes: &[u8]) -> usize {
        let mut taken = 0;
        while !bytes.is_empty() {
            let spare = self.spare();
            if spare.is_empty() {
                break;
            }
            let n = spare.len().min(bytes.len());
            spare[..n].copy_from_slice(&bytes[..n]);
            self.commit(n);
            taken += n;
            bytes = &bytes[n..];
        }
        taken
    }

    fn compact(&mut self) {
        let kept = match self.pin {
            Some((start, end)) => {
                self.data.copy_within(start..end, 0);
                self.pin = Some((0, end - start));
                end - start
            }
            None => 0,
        };
        let live = self.filled - self.pos;
        self.data.copy_within(self.pos..self.filled, kept);
        let old_filled = self.filled;
        self.pos = kept;
        self.filled = kept + live;
        if self.wipe {
            // Everything before the new end was overwritten by the moved
            // bytes; what lies between the new and the old end is a stale
            // copy (consumed body, the head's old place, the unread bytes'
            // old place).
            if let Some(stale) = self.data.get_mut(self.filled..old_filled) {
                zero(stale);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_never_exceeds_cap() {
        let mut b = Buffer::new(10_000);
        let big = alloc::vec![7u8; 50_000];
        assert_eq!(b.feed(&big), 10_000);
        assert!(b.spare().is_empty());
        assert_eq!(b.unread().len(), 10_000);
    }

    #[test]
    fn test_buffer_compaction_keeps_pinned_head() {
        let mut b = Buffer::new(8192);
        assert_eq!(b.feed(b"HEAD"), 4);
        b.pin_at_pos();
        b.consume(4);
        b.extend_pin_to_pos();
        let fill = alloc::vec![1u8; 8188];
        assert_eq!(b.feed(&fill), 8188);
        b.consume(8188);
        // Full: the next spare() must compact everything but the pin.
        assert_eq!(b.spare().len(), 8188);
        assert_eq!(b.pos(), 4);
        assert_eq!(b.range(b.pin(), b.pin() + 4), b"HEAD");
        assert_eq!(b.pin(), 0);
        b.unpin();
        assert_eq!(b.pin(), b.pos());
    }

    #[test]
    fn test_buffer_eof_flag() {
        let mut b = Buffer::new(64);
        assert!(!b.is_eof());
        b.set_eof();
        assert!(b.is_eof());
    }
}
