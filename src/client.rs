//! The near side: a connection this node opens, or upgrades in place.
//!
//! **Loaded once.** The operating system's trust store is read the first
//! time a connection needs it, and a configuration over it is built once
//! for each list of protocols offered; every connection after the first
//! shares both. Until 2026-09-27 every connection read the store and built
//! a configuration of its own. No configuration resumes a session
//! (`configuration`): every connection checks the server's certificate in
//! a full handshake, but a data connection of one login
//! ([`login_trusting`]), which resumes its control connection's.

use std::net::TcpStream;
use std::sync::{Arc, Mutex, PoisonError};

use crate::{Result, TlsError, configuration};

/// A client-side TLS connection, ready to read and write.
pub type Guarded = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

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
/// next connection, as [`client`] keeps its own, so it is built once.
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

/// Wrap a connection in TLS for one host, against `trust` where the
/// configuration gives a trust store — a Party's own certificate authority,
/// a directory's or an authorization server's — and the operating system's
/// where it gives none: [`client_with`] or [`client`]. The one choice every
/// protocol with an optional trust store makes, made here once.
///
/// # Errors
///
/// As [`client`]; with `trust` given, as [`client_with`].
pub fn client_trusting(
    host: &str,
    tcp: TcpStream,
    trust: Option<&Arc<rustls::ClientConfig>>,
) -> Result<Guarded> {
    client_with(host, tcp, trusted(trust)?)
}

/// A client configuration over `roots`, with this node's key exchange,
/// presenting no certificate and resuming no session.
#[must_use]
pub fn configure(roots: impl Into<Arc<rustls::RootCertStore>>) -> rustls::ClientConfig {
    configuration::client(roots, None)
}

/// A client configuration for one login — a control connection and the
/// data connections opened beside it, as FTPS's (RFC 4217) — trusting as
/// [`client_trusting`] does: `trust` where it is given, the operating
/// system's store where it is not. The login's own connections resume its
/// first session and no other connection does (`configuration`). Built
/// once per login, used for each of its connections, and dropped with it.
///
/// # Errors
///
/// Without `trust`, where the operating system's trust store is empty or
/// unreadable.
pub fn login_trusting(
    trust: Option<&Arc<rustls::ClientConfig>>,
) -> Result<Arc<rustls::ClientConfig>> {
    let trusting = trusted(trust)?;
    Ok(Arc::new(configuration::login(&trusting)))
}

/// `trust` where the configuration gives a trust store, and the operating
/// system's, offering no protocol, where it gives none: the one choice
/// [`client_trusting`] and [`login_trusting`] make.
fn trusted(trust: Option<&Arc<rustls::ClientConfig>>) -> Result<Arc<rustls::ClientConfig>> {
    match trust {
        Some(config) => Ok(Arc::clone(config)),
        None => native(&[]),
    }
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

    use super::*;
    use crate::fixture::{connected, handshakes};
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
    fn a_kept_configuration_resumes_nothing_from_a_server_that_offers_it() {
        let signed = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("a certificate");
        let key =
            crate::pem::private_key(signed.signing_key.serialize_pem().as_bytes()).expect("a key");
        // A server of rustls's defaults: a session cache, and tickets sent.
        let resuming = rustls::ServerConfig::builder_with_provider(crate::provider())
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(vec![signed.cert.der().clone()], key)
            .expect("server config");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(signed.cert.der().clone()).expect("trusted");
        let kept = Arc::new(configure(roots));

        let full = Some(rustls::HandshakeKind::Full);
        assert_eq!(handshakes(&kept, &Arc::new(resuming), 2), [full, full]);
    }

    #[test]
    fn a_given_trust_store_is_trusted_and_without_one_the_systems_is() {
        let signed = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("a certificate");
        let served = Arc::new(
            server_config(
                signed.cert.pem().as_bytes(),
                signed.signing_key.serialize_pem().as_bytes(),
            )
            .expect("server config"),
        );
        let (near, far): (Vec<_>, Vec<_>) = (0..2).map(|_| connected()).unzip();
        let far = std::thread::spawn(move || {
            for tcp in far {
                let mut guarded = server(tcp, Arc::clone(&served)).expect("server");
                if guarded
                    .write_all(b"x")
                    .and_then(|()| guarded.flush())
                    .is_ok()
                {
                    let _ = guarded.read(&mut [0u8; 1]);
                }
            }
        });
        let mut roots = rustls::RootCertStore::empty();
        roots.add(signed.cert.der().clone()).expect("trusted");
        let given = Arc::new(configure(roots));
        let mut near = near.into_iter();
        let mut byte = [0u8; 1];

        let mut trusted =
            client_trusting("localhost", near.next().expect("one"), Some(&given)).expect("tls");
        trusted
            .read_exact(&mut byte)
            .expect("the given store trusts the server");
        trusted.write_all(b"y").expect("written");
        trusted.flush().expect("flushed");
        drop(trusted);
        // The operating system's store does not hold a self-signed
        // certificate made a moment ago: refused at the handshake, or before
        // it on a machine without a store.
        let refused = client_trusting("localhost", near.next().expect("two"), None)
            .map_or(true, |mut system| system.read_exact(&mut byte).is_err());
        far.join().expect("far end");

        assert!(
            refused,
            "the system's store does not trust a self-signed server"
        );
    }
}
