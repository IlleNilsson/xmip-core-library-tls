//! What proving a browser's possession of its key costs (ADR-0009,
//! amendment 2026-11-02), held to the millisecond rule: a handshake bound
//! and recorded, its transcript recovered, beside the same handshake
//! served plainly; and the node's check of the transcript.

use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use xmip_core_library_tls::fixture::connected;
use xmip_core_library_tls::possession::{binding, handshaken, proved, proving};

use crate::{Issued, median};

const ROUNDS: usize = 31;

/// One browser's handshake against a server that `serve` answers, and how
/// long the server took from the connection to its finished handshake.
fn timed(client: &Arc<rustls::ClientConfig>, serve: &dyn Fn(TcpStream)) -> Duration {
    let (mut near, tcp) = connected();
    let client = Arc::clone(client);
    let browser = std::thread::spawn(move || {
        let name = "localhost".try_into().expect("a name");
        let mut connection = rustls::ClientConnection::new(client, name).expect("a session");
        while connection.is_handshaking() {
            if connection.complete_io(&mut near).is_err() {
                break;
            }
        }
    });
    tcp.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("bounded");
    let began = Instant::now();
    serve(tcp);
    let took = began.elapsed();
    browser.join().expect("the browser");
    took
}

#[test]
fn proving_a_browsers_key_adds_under_a_millisecond_to_its_handshake_and_its_check() {
    let issued = Issued::new();
    let identity = issued.identity(&issued.server);
    let client = Arc::new(issued.identity(&issued.client).client().expect("a client"));
    let plain = Arc::new(identity.server_asking().expect("a server"));
    let bound = Arc::new(proving(&identity).expect("a proving server"));
    let nonces = binding(&[&[1u8; 16][..], &[2u8; 16][..]]);
    let transcript = std::cell::RefCell::new(Vec::new());

    let mut served = Vec::new();
    let mut proving_times = Vec::new();
    for _ in 0..ROUNDS {
        served.push(timed(&client, &|tcp| {
            xmip_core_library_tls::peer::handshaken(tcp, Arc::clone(&plain)).expect("served");
        }));
        proving_times.push(timed(&client, &|tcp| {
            let (_, recorded) = handshaken(tcp, Arc::clone(&bound), nonces).expect("served");
            *transcript.borrow_mut() = recorded.transcript().expect("a transcript");
        }));
    }
    let (plainly, proving_median) = (median(served.clone()), median(proving_times));
    let added = proving_median.saturating_sub(plainly);
    eprintln!("a handshake served plainly {plainly:?}, proving {proving_median:?}");
    assert!(
        added < Duration::from_millis(1),
        "binding and recording added {added:?} to a handshake of {:?}",
        median(served)
    );

    let transcript = transcript.into_inner();
    let checks: Vec<Duration> = (0..ROUNDS)
        .map(|_| {
            let began = Instant::now();
            let proof = proved(&transcript).expect("proved");
            assert_eq!(proof.server_random[..24], nonces);
            began.elapsed()
        })
        .collect();
    let check = median(checks);
    eprintln!("the node's check of a transcript {check:?}");
    assert!(
        check < Duration::from_millis(1),
        "the node's check took {check:?}"
    );
}
