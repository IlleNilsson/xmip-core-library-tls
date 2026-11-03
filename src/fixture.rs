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

/// A client and a server, split, over loopback, Nagle's algorithm off as
/// every connection Xmip makes and accepts has it (`net::connect`,
/// `transport::socket::accept_tcp`): with it on, a record written after
/// the server's tickets waited for the client's delayed acknowledgement,
/// forty milliseconds on Linux, past the test's ten (2026-10-21).
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
