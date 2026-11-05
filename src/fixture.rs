//! The connection this crate's tests and its timing program both stand up,
//! written once (`test-support`; `doc/governance/rust-style.md` section
//! 5c): never a production build.

use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use crate::duplex::{Reading, Writing, split};
use crate::{client_with, configure, server, server_config};

/// One side of a split connection.
pub type Sides<C> = (Reading<C>, Writing<C>);

/// How long the near end waits for loopback to take its connection.
const CONNECTING: Duration = Duration::from_secs(5);

/// A loopback connection's two ends, near and far, made and accepted on the
/// calling thread before either end's handshake starts, Nagle's algorithm
/// off on both as every connection Xmip makes and accepts has it
/// (`net::connect`, `transport::socket::accept_tcp`).
///
/// Connected first, then accepted: a listener takes a connection into its
/// backlog without waiting for `accept`, so the accept finds it there and
/// returns at once, and a connection the system refuses fails here, in
/// words. Until 2026-11-04 every test connected on a thread of its own and
/// accepted on the test's, and a connect Windows refused — its outgoing
/// ports used up by the machine (Tcpip event 4227) — ended that thread
/// while the test waited in `accept` for a connection that never came, for
/// two hours.
///
/// # Panics
///
/// When the listener cannot be bound, the connection is refused or not
/// taken within five seconds, or Nagle's algorithm cannot be turned off: a
/// test's connection, failing it.
#[must_use]
pub fn connected() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bound");
    let address = listener.local_addr().expect("address");
    let near = TcpStream::connect_timeout(&address, CONNECTING).expect("connected");
    // bounded: the connection above is in the backlog already
    let (far, _) = listener.accept().expect("accepted");
    near.set_nodelay(true).expect("no delay");
    far.set_nodelay(true).expect("no delay");
    (near, far)
}

/// A client and a server, split, over loopback ([`connected`]): with
/// Nagle's algorithm on, a record written after the server's tickets
/// waited for the client's delayed acknowledgement, forty milliseconds on
/// Linux, past the test's ten (2026-10-21).
///
/// # Panics
///
/// When the certificate, the loopback connection or either handshake
/// fails: a test's connection, failing it.
#[must_use]
pub fn pair() -> (
    Sides<rustls::ClientConnection>,
    Sides<rustls::ServerConnection>,
) {
    let signed =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("a certificate");
    let config = server_config(
        signed.cert.pem().as_bytes(),
        signed.signing_key.serialize_pem().as_bytes(),
    )
    .expect("server config");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(signed.cert.der().clone()).expect("trusted");
    let (near, far) = connected();

    let near = std::thread::spawn(move || {
        let stream = client_with("localhost", near, Arc::new(configure(roots))).expect("tls");
        let split = split(stream).expect("split");
        (split.reading, split.writing)
    });
    let far = split(server(far, Arc::new(config)).expect("tls")).expect("split");
    (near.join().expect("client"), (far.reading, far.writing))
}
