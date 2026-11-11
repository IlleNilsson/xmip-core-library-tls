//! What resuming no session costs (ADR-0033, amendment 2026-11-10), held to
//! the millisecond rule: a full handshake, as every configuration of the
//! library makes, beside one resumed by rustls's defaults, both ends over
//! memory on this thread — mutual TLS, and a server authenticated alone.
//! Over memory no round trip is counted: a TLS 1.3 handshake takes one,
//! full or resumed, and a TLS 1.2 one takes two in full where it took one
//! resumed, which a peer far away pays on top.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::{ClientConfig, Connection, HandshakeKind, ServerConfig};

use crate::{Issued, median};

const ROUNDS: usize = 201;

/// `from`'s bytes to send, read and processed by `to`.
fn moved(from: &mut Connection, to: &mut Connection) {
    let mut wire = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut wire).expect("written");
    }
    let mut unread = wire.as_slice();
    while !unread.is_empty() {
        to.read_tls(&mut unread).expect("read");
        to.process_new_packets().expect("processed");
    }
}

/// One handshake of `client` with `server`, both ends driven on this
/// thread over memory: how long it took from the client's hello to both
/// ends done, and how the client saw it. What the server sends after its
/// handshake — its tickets, where it sends any — reaches the client before
/// the next.
fn shaken(client: &Arc<ClientConfig>, server: &Arc<ServerConfig>) -> (Duration, HandshakeKind) {
    let name = "localhost".try_into().expect("a name");
    let began = Instant::now();
    let mut near = Connection::from(
        rustls::ClientConnection::new(Arc::clone(client), name).expect("a client"),
    );
    let mut far =
        Connection::from(rustls::ServerConnection::new(Arc::clone(server)).expect("a server"));
    for _ in 0..8 {
        if !near.is_handshaking() && !far.is_handshaking() {
            break;
        }
        moved(&mut near, &mut far);
        moved(&mut far, &mut near);
    }
    let took = began.elapsed();
    assert!(!near.is_handshaking() && !far.is_handshaking(), "done");
    moved(&mut far, &mut near);
    (took, near.handshake_kind().expect("a handshake"))
}

/// `server` and `client` given rustls's defaults back: a server's session
/// cache and its tickets, as rustls builds one, and a client's cache.
fn resuming(
    server: &ServerConfig,
    client: &ClientConfig,
) -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let defaults = ServerConfig::builder_with_provider(xmip_core_library_tls::provider())
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .expect("versions")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));
    let mut server = server.clone();
    server.session_storage = defaults.session_storage;
    server.ticketer = defaults.ticketer;
    server.send_tls13_tickets = defaults.send_tls13_tickets;
    let mut client = client.clone();
    client.resumption = rustls::client::Resumption::default();
    (Arc::new(server), Arc::new(client))
}

/// The full handshakes of `client` with `server`, and the resumed ones of
/// the same two given rustls's defaults back, taken in turn so each sees
/// the machine as the other does: each list fastest first.
fn compared(client: &ClientConfig, server: &ServerConfig) -> [Vec<Duration>; 2] {
    let (full_client, full_server) = (Arc::new(client.clone()), Arc::new(server.clone()));
    let (resuming_server, resuming_client) = resuming(server, client);
    shaken(&resuming_client, &resuming_server);
    let (mut full, mut resumed) = (Vec::new(), Vec::new());
    for _ in 0..ROUNDS {
        let (took, kind) = shaken(&full_client, &full_server);
        assert_eq!(kind, HandshakeKind::Full);
        full.push(took);
        let (took, kind) = shaken(&resuming_client, &resuming_server);
        assert_eq!(kind, HandshakeKind::Resumed);
        resumed.push(took);
    }
    full.sort();
    resumed.sort();
    [full, resumed]
}

/// Held by the fastest of each, as the millisecond rule holds a cost
/// beyond load; the medians are said beside it.
#[test]
fn a_full_handshake_costs_under_a_millisecond_more_than_a_resumed_one() {
    let issued = Issued::new();
    let mutual = compared(
        &issued.identity(&issued.client).client().expect("a client"),
        &issued.identity(&issued.server).server().expect("a server"),
    );
    let (certificate, key) = &issued.server;
    let alone = compared(
        &xmip_core_library_tls::trusting(issued.authority.as_bytes()).expect("a client"),
        &xmip_core_library_tls::server_config(certificate.as_bytes(), key.as_bytes())
            .expect("a server"),
    );

    for (what, [full, resumed]) in [("mutual TLS", mutual), ("the server alone", alone)] {
        let added = full[0].saturating_sub(resumed[0]);
        eprintln!(
            "{what}, the fastest of {ROUNDS}: in full {:?}, resumed {:?}, {added:?} more; \
             the median: in full {:?}, resumed {:?}",
            full[0],
            resumed[0],
            median(full.clone()),
            median(resumed.clone()),
        );
        assert!(
            added < Duration::from_millis(1),
            "{what}: a full handshake took {added:?} more than a resumed one"
        );
    }
}
