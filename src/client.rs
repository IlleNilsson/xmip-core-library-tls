//! The near side: a connection this node opens, or upgrades in place.
//!
//! **Loaded once, resumed after.** The operating system's trust store is
//! read the first time a connection needs it, and a configuration over it
//! is built once for each list of protocols offered; every connection
//! after the first shares both. The configuration keeps rustls's session
//! cache, so a second connection to a server resumes the session the first
//! agreed instead of repeating the whole handshake. Until 2026-09-27 every
//! connection read the store and built a configuration of its own, and so
//! resumed nothing.

use std::net::TcpStream;
use std::sync::{Arc, Mutex, PoisonError};

use crate::{Result, TlsError, provider};

/// A client-side TLS connection, ready to read and write.
pub type Guarded = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

/// How many sessions a client configuration remembers for resumption: one
/// per server a node speaks to, with room.
const SESSIONS: usize = 256;

/// Wrap a connection in TLS for one host, against the operating system's
/// trust store.
///
/// The same call serves STARTTLS: a protocol that negotiates in the clear
/// first hands the same socket over once the peer has agreed, and everything
/// after it is guarded.
///
/// # Errors
///
/// Where the trust store is empty or unreadable, the host is not a name TLS
/// can use, or the handshake could not be started.
pub fn client(host: &str, tcp: TcpStream) -> Result<Guarded> {
    client_with(host, tcp, native(&[])?)
}

/// As [`client`], offering `protocols` by ALPN, in order of preference;
/// [`crate::alpn::agreed`] reads which the server selected.
///
/// # Errors
///
/// As [`client`].
pub fn client_offering(host: &str, tcp: TcpStream, protocols: &[&[u8]]) -> Result<Guarded> {
    client_with(host, tcp, native(protocols)?)
}

/// As [`client`], against a trust store the caller holds — a Party's own
/// certificate authority, or a test's. The caller keeps `config` for the
/// next connection, as [`client`] keeps its own, so sessions resume.
///
/// # Errors
///
/// As [`client`], less the trust store.
pub fn client_with(
    host: &str,
    tcp: TcpStream,
    config: Arc<rustls::ClientConfig>,
) -> Result<Guarded> {
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| TlsError::new(format!("a server name tls cannot use: {host}")))?;
    let connection = rustls::ClientConnection::new(config, name)
        .map_err(|failure| TlsError::new(format!("starting the tls session: {failure}")))?;

    Ok(rustls::StreamOwned::new(connection, tcp))
}

/// A client configuration over `roots`, with this node's key exchange and
/// a session cache to resume from.
#[must_use]
pub fn configure(roots: impl Into<Arc<rustls::RootCertStore>>) -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .unwrap_or_else(|_| unreachable!("the default versions are always supported"))
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::in_memory_sessions(SESSIONS);
    config
}

/// What this process has built over the operating system's trust store:
/// the store, once read, and a configuration per list of protocols offered.
struct Native {
    roots: Option<Arc<rustls::RootCertStore>>,
    configs: Vec<(Vec<Vec<u8>>, Arc<rustls::ClientConfig>)>,
}

static NATIVE: Mutex<Native> = Mutex::new(Native {
    roots: None,
    configs: Vec::new(),
});

/// The configuration over the operating system's trust store offering
/// `protocols`: the one built before, or built now and kept. A store that
/// could not be read is read again next time rather than remembered empty.
fn native(protocols: &[&[u8]]) -> Result<Arc<rustls::ClientConfig>> {
    let mut native = NATIVE.lock().unwrap_or_else(PoisonError::into_inner);
    let offered = |kept: &[Vec<u8>]| kept.iter().map(Vec::as_slice).eq(protocols.iter().copied());
    if let Some((_, config)) = native.configs.iter().find(|(kept, _)| offered(kept)) {
        return Ok(Arc::clone(config));
    }
    let roots = match &native.roots {
        Some(roots) => Arc::clone(roots),
        None => Arc::new(native_roots()?),
    };
    native.roots = Some(Arc::clone(&roots));
    let config = Arc::new(crate::alpn::offering(configure(roots), protocols));
    let kept = protocols.iter().map(|protocol| protocol.to_vec()).collect();
    native.configs.push((kept, Arc::clone(&config)));
    Ok(config)
}

/// The operating system trust store, read.
///
/// The native store rather than a bundled root list, because the
/// organizations Xmip is aimed at run internal certificate authorities and
/// expect their own certificates to work without waiting for Xmip to ship a
/// new root bundle.
fn native_roots() -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();

    for certificate in rustls_native_certs::load_native_certs().certs {
        // One unparsable certificate is not a reason to refuse every other
        // certificate in the store.
        let _ = roots.add(certificate);
    }

    if roots.is_empty() {
        return Err(TlsError::new(
            "the operating system trust store held no usable certificates",
        ));
    }

    Ok(roots)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use super::*;
    use crate::server::{server, server_config};

    #[test]
    fn the_trust_store_is_read_once_and_a_configuration_built_once_per_offer() {
        let Ok(plain) = native(&[]) else {
            // A machine without a trust store has nothing to keep; the
            // refusal is the one the store's absence gives.
            let refused = native(&[]).expect_err("no store");
            assert!(refused.message.contains("trust store"), "{refused}");
            return;
        };
        let offering = native(&[b"h2", b"http/1.1"]).expect("offering");
        assert!(Arc::ptr_eq(&plain, &native(&[]).expect("again")));
        assert!(Arc::ptr_eq(
            &offering,
            &native(&[b"h2", b"http/1.1"]).expect("again")
        ));
        assert!(!Arc::ptr_eq(&plain, &offering));
        let native = NATIVE.lock().unwrap_or_else(PoisonError::into_inner);
        assert!(native.configs.len() >= 2);
        let roots: Vec<_> = native.roots.iter().collect();
        assert_eq!(roots.len(), 1, "one store");
    }

    #[test]
    fn a_second_connection_on_a_kept_configuration_resumes_the_first_session() {
        let signed = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("a certificate");
        let served = server_config(
            signed.cert.pem().as_bytes(),
            signed.key_pair.serialize_pem().as_bytes(),
        )
        .expect("server config");
        let served = Arc::new(served);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let far = std::thread::spawn(move || {
            for _ in 0..2 {
                let (tcp, _) = listener.accept().expect("accept");
                let mut guarded = server(tcp, Arc::clone(&served)).expect("server");
                guarded.write_all(b"x").expect("written");
                guarded.flush().expect("flushed");
                let _ = guarded.read(&mut [0u8; 1]);
            }
        });
        let mut roots = rustls::RootCertStore::empty();
        roots.add(signed.cert.der().clone()).expect("trusted");
        let kept = Arc::new(configure(roots));
        let kinds: Vec<_> = (0..2)
            .map(|_| {
                let tcp = TcpStream::connect(address).expect("connect");
                let mut guarded = client_with("localhost", tcp, Arc::clone(&kept)).expect("tls");
                let mut byte = [0u8; 1];
                guarded.read_exact(&mut byte).expect("read");
                guarded.write_all(b"y").expect("written");
                guarded.flush().expect("flushed");
                guarded.conn.handshake_kind()
            })
            .collect();
        far.join().expect("far end");
        assert_eq!(
            kinds,
            [
                Some(rustls::HandshakeKind::Full),
                Some(rustls::HandshakeKind::Resumed)
            ]
        );
    }
}
