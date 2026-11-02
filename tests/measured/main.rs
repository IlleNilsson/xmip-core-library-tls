//! The module's timing program (`doc/governance/rust-style.md` section
//! 5c): Xmip's TLS held to a time. A plain `cargo test` leaves it out; the
//! landing runs it after every other test of the module, alone, one test at
//! a time (`cargo test --test measured --all-features -- --test-threads=1`),
//! so what is measured is Xmip's work and not its neighbors':
//!
//! - a side of a split connection writes at once while the other side
//!   waits reading on the same connection.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use xmip_core_library_tls::duplex::{Reading, Writing, split};
use xmip_core_library_tls::{client_with, configure, server, server_config};

/// One side of a split connection.
type Sides<C> = (Reading<C>, Writing<C>);

/// A client and a server, split, over loopback, Nagle's algorithm off as
/// every connection Xmip makes and accepts has it.
fn pair() -> (
    Sides<rustls::ClientConnection>,
    Sides<rustls::ServerConnection>,
) {
    let signed =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("a certificate");
    let config = server_config(
        signed.cert.pem().as_bytes(),
        signed.key_pair.serialize_pem().as_bytes(),
    )
    .expect("server config");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(signed.cert.der().clone()).expect("trusted");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bound");
    let address = listener.local_addr().expect("address");

    let near = std::thread::spawn(move || {
        let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(5)).expect("connected");
        tcp.set_nodelay(true).expect("no delay");
        let stream = client_with("localhost", tcp, Arc::new(configure(roots))).expect("tls");
        let split = split(stream).expect("split");
        (split.reading, split.writing)
    });
    // bounded: the near end connects on loopback on the thread above, or fails
    let (tcp, _) = listener.accept().expect("accepted");
    tcp.set_nodelay(true).expect("no delay");
    let far = split(server(tcp, Arc::new(config)).expect("tls")).expect("split");
    (near.join().expect("client"), (far.reading, far.writing))
}

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
