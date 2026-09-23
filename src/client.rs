//! The near side: a connection this node opens, or upgrades in place.

use std::net::TcpStream;
use std::sync::Arc;

use crate::{Result, TlsError, provider};

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
    client_with(host, tcp, Arc::new(configure(native_roots()?)))
}

/// As [`client`], against a trust store the caller holds — a partner's own
/// certificate authority, or a test's.
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

/// A client configuration over `roots`, with this node's key exchange.
#[must_use]
pub fn configure(roots: rustls::RootCertStore) -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .unwrap_or_else(|_| unreachable!("the default versions are always supported"))
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// The operating system trust store.
///
/// The native store rather than a bundled root list, because the
/// organizations Xmip is aimed at run internal certificate authorities and
/// expect their own certificates to work without waiting for Xmip to ship a
/// new root bundle.
///
/// # Errors
///
/// Where the store holds nothing this can read.
pub fn native_roots() -> Result<rustls::RootCertStore> {
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
