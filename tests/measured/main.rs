//! The module's timing program (`doc/governance/rust-style.md` section
//! 5c): Xmip's TLS held to a time. A plain `cargo test` leaves it out; the
//! landing runs it after every other test of the module, alone, one test at
//! a time (`cargo test --test measured --all-features -- --test-threads=1`),
//! so what is measured is Xmip's work and not its neighbors':
//!
//! - a side of a split connection writes at once while the other side
//!   waits reading on the same connection.
//! - proving a browser's key adds under a millisecond to its handshake,
//!   and the node's check of the transcript takes under one
//!   (`possession`).

mod possession;

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use xmip_core_library_tls::fixture::pair;

#[test]
fn a_write_is_not_held_up_by_a_read_waiting_on_the_same_connection() {
    let ((mut near_reading, mut near_writing), (mut far_reading, mut far_writing)) = pair();

    // The near side waits to read on its own thread, holding nothing.
    let waiting = std::thread::spawn(move || {
        let mut heard = [0u8; 5];
        near_reading.read_exact(&mut heard).expect("heard");
        heard
    });
    std::thread::sleep(Duration::from_millis(20));
    // Meanwhile it writes, and is not held up by its own waiting read.
    let started = Instant::now();
    near_writing.write_all(b"wants").expect("written");
    near_writing.flush().expect("flushed");
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "{:?}",
        started.elapsed()
    );

    let mut asked = [0u8; 5];
    far_reading.read_exact(&mut asked).expect("asked");
    far_writing.write_all(b"event").expect("answered");
    assert_eq!(&waiting.join().expect("near reader"), b"event");
}
