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
//! - a full handshake, as every configuration of the library makes, costs
//!   under a millisecond more than one resumed by rustls's defaults
//!   (`resumption`).

mod possession;
mod resumption;

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use rcgen::{CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use xmip_core_library_tls::Identity;
use xmip_core_library_tls::fixture::pair;

/// What one test authority issued, PEM: its own certificate, and a
/// server's for `localhost` and a client's, each a certificate and its key.
struct Issued {
    authority: String,
    server: (String, String),
    client: (String, String),
}

impl Issued {
    fn new() -> Self {
        let authority_key = KeyPair::generate().expect("a key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let authority = CertifiedIssuer::self_signed(params, authority_key).expect("an authority");
        let issue = |purpose: ExtendedKeyUsagePurpose, name: &str| {
            let key = KeyPair::generate().expect("a key");
            let mut params = CertificateParams::new(vec![name.to_string()]).expect("params");
            params.extended_key_usages = vec![purpose];
            let issued = params.signed_by(&key, &authority).expect("issued");
            (issued.pem(), key.serialize_pem())
        };
        Self {
            server: issue(ExtendedKeyUsagePurpose::ServerAuth, "localhost"),
            client: issue(ExtendedKeyUsagePurpose::ClientAuth, "alice"),
            authority: authority.pem(),
        }
    }

    /// The identity of `(certificate, key)`, trusting the authority.
    fn identity(&self, (certificate, key): &(String, String)) -> Identity {
        Identity::from_pem(
            certificate.as_bytes(),
            key.as_bytes(),
            self.authority.as_bytes(),
        )
        .expect("an identity")
    }
}

fn median(mut times: Vec<Duration>) -> Duration {
    times.sort();
    times[times.len() / 2]
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
