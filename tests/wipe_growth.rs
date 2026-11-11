//! With wiping on, no heap block the connections free still holds a
//! request's or a response's bytes, including the block left behind when
//! the input buffer grows (fixed in 0.10: growth reallocated and freed the
//! old block unwiped). The allocator below inspects every block as it is
//! freed; `realloc` is left at its default (allocate, copy, free), so a
//! block a reallocation moves is freed through `dealloc` and inspected too.
//!
//! The tests share the allocator, so they run one at a time (a lock) and
//! each counts only its own marker. The allocator itself takes no lock: the
//! marker is published through atomics, so no freed block goes unchecked.

#![allow(unsafe_code)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::{
        Mutex,
        atomic::{AtomicPtr, AtomicUsize, Ordering},
    },
};

use http_net::{ClientConn, ClientEvent, Request, Response, ServerConn, ServerEvent};

/// The armed marker: its bytes and length; a length of 0 is disarmed.
static MARKER_PTR: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static MARKER_LEN: AtomicUsize = AtomicUsize::new(0);
static LEAKED: AtomicUsize = AtomicUsize::new(0);
static SERIAL: Mutex<()> = Mutex::new(());

struct Inspecting;

// SAFETY: every call forwards to `System` with the same arguments; the
// inspection only reads a block that is still allocated.
unsafe impl GlobalAlloc for Inspecting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as the caller promised for this layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let len = MARKER_LEN.load(Ordering::Acquire);
        if len > 0 && layout.size() >= len {
            // SAFETY: the marker is a `'static` slice of `len` bytes, published
            // before its length; the block is live until `System.dealloc`.
            let marker =
                unsafe { std::slice::from_raw_parts(MARKER_PTR.load(Ordering::Acquire), len) };
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if block.windows(len).any(|w| w == marker) {
                let _ = LEAKED.fetch_add(1, Ordering::Relaxed);
            }
        }
        // SAFETY: as the caller promised for this block.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Inspecting = Inspecting;

/// Runs `exchange` with `marker` armed and returns how many freed blocks
/// still held it.
fn leaked_blocks(marker: &'static [u8], exchange: impl FnOnce()) -> usize {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    LEAKED.store(0, Ordering::Relaxed);
    MARKER_PTR.store(marker.as_ptr().cast_mut(), Ordering::Release);
    MARKER_LEN.store(marker.len(), Ordering::Release);
    exchange();
    MARKER_LEN.store(0, Ordering::Release);
    LEAKED.load(Ordering::Relaxed)
}

/// A head of about 6 KiB: past the first 4 KiB allocation, so the buffer
/// grows while it is read.
fn big_head(start: &[u8], marker: &[u8]) -> Vec<u8> {
    let mut head = start.to_vec();
    head.extend_from_slice(marker);
    head.extend_from_slice(b"\r\n");
    for i in 0..60 {
        head.extend_from_slice(format!("x-pad-{i:02}: {}\r\n", "p".repeat(90)).as_bytes());
    }
    head
}

fn serve(wire: &[u8], wipe: bool) {
    let mut conn = ServerConn::new();
    conn.set_wipe(wipe);
    let mut out = Vec::new();
    for piece in wire.chunks(1000) {
        assert_eq!(conn.feed(piece), piece.len());
        loop {
            match conn.poll().unwrap() {
                ServerEvent::NeedInput => break,
                ServerEvent::RequestEnd => conn.respond(&Response::new(204), &mut out).unwrap(),
                _ => {}
            }
        }
    }
}

#[test]
fn test_server_wipe_leaves_no_credential_in_freed_blocks_after_growth() {
    const MARKER: &[u8] = b"Zm9vOnNlcnZlci1tYXJrZXI";
    let mut wire = big_head(
        b"GET / HTTP/1.1\r\nHost: a\r\nAuthorization: Basic ",
        MARKER,
    );
    wire.extend_from_slice(b"\r\n");
    assert!(wire.len() > 6000 && wire.len() < 8 * 1024, "{}", wire.len());
    assert_eq!(leaked_blocks(MARKER, || serve(&wire, true)), 0);
    // Control: without wiping the probe does see the freed copy, so the
    // test can tell the difference.
    assert!(leaked_blocks(MARKER, || serve(&wire, false)) > 0);
}

fn fetch(wire: &[u8], wipe: bool) {
    let mut conn = ClientConn::new();
    conn.set_wipe(wipe);
    conn.send_request(&Request::get("/").header("host", "a"), &mut Vec::new())
        .unwrap();
    for piece in wire.chunks(1000) {
        assert_eq!(conn.feed(piece), piece.len());
        loop {
            match conn.poll().unwrap() {
                ClientEvent::NeedInput | ClientEvent::Idle => break,
                _ => {}
            }
        }
    }
}

#[test]
fn test_client_wipe_leaves_no_cookie_in_freed_blocks_after_growth() {
    const MARKER: &[u8] = b"c2Vzc2lvbi1jbGllbnQtbWFya2Vy";
    let mut wire = big_head(b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=", MARKER);
    wire.extend_from_slice(b"Content-Length: 0\r\n\r\n");
    assert_eq!(leaked_blocks(MARKER, || fetch(&wire, true)), 0);
    assert!(leaked_blocks(MARKER, || fetch(&wire, false)) > 0);
}
