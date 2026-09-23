//! The far side: a connection this node answers, presenting its certificate.

use std::net::TcpStream;
use std::sync::Arc;

use crate::{Result, TlsError, provider};

/// A server-side TLS connection, ready to read and write — a Receive
/// Location's guarded channel. ADR-0033.
pub type GuardedServer = rustls::StreamOwned<rustls::ServerConnection, TcpStream>;

/// A server configuration from a certificate chain and its private key, both
/// PEM. This is the Receive side of certificates: the node presents this
/// certificate to callers. Client-certificate verification (mutual-TLS)
/// layers a verifier onto this.
///
/// # Errors
///
/// Where the certificate or key cannot be read, or the pair is not usable.
pub fn server_config(certificate_pem: &[u8], key_pem: &[u8]) -> Result<rustls::ServerConfig> {
    let certificates = rustls_pemfile::certs(&mut &certificate_pem[..])
        .collect::<core::result::Result<Vec<_>, _>>()
        .map_err(|failure| TlsError::new(format!("reading the certificate: {failure}")))?;

    if certificates.is_empty() {
        return Err(TlsError::new("the certificate PEM held no certificate"));
    }

    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|failure| TlsError::new(format!("reading the private key: {failure}")))?
        .ok_or_else(|| TlsError::new("the key PEM held no private key"))?;

    rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .unwrap_or_else(|_| unreachable!("the default versions are always supported"))
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|failure| TlsError::new(format!("loading the certificate and key: {failure}")))
}

/// Answer a TLS connection on an already-accepted socket.
///
/// As on the near side, the same call serves STARTTLS: a server that
/// negotiated in the clear hands the same socket over once it has agreed.
///
/// # Errors
///
/// Where the handshake could not be started.
pub fn server(tcp: TcpStream, config: Arc<rustls::ServerConfig>) -> Result<GuardedServer> {
    let connection = rustls::ServerConnection::new(config)
        .map_err(|failure| TlsError::new(format!("starting the server tls session: {failure}")))?;

    Ok(rustls::StreamOwned::new(connection, tcp))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use super::*;
    use crate::client::{client_with, configure};

    fn self_signed() -> rcgen::CertifiedKey {
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generating a cert")
    }

    /// Hand `ping` over a loopback handshake between this node's server and a
    /// client built from `groups`, and say which group each side agreed.
    fn handshake(
        groups: Option<Vec<&'static dyn rustls::crypto::SupportedKxGroup>>,
    ) -> (rustls::NamedGroup, rustls::NamedGroup) {
        let signed = self_signed();
        let config = Arc::new(
            server_config(
                signed.cert.pem().as_bytes(),
                signed.key_pair.serialize_pem().as_bytes(),
            )
            .expect("server config"),
        );

        let listener = TcpListener::bind("127.0.0.1:0").expect("binding");
        let address = listener.local_addr().expect("address").to_string();
        let trusted = signed.cert.der().clone();

        let caller = std::thread::spawn(move || {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(trusted).expect("trusting the test cert");
            let client = match groups {
                // This node's own client, hybrid first.
                None => configure(roots),
                // A peer that knows only what it is given.
                Some(groups) => {
                    let provider = rustls::crypto::CryptoProvider {
                        kx_groups: groups,
                        ..rustls::crypto::aws_lc_rs::default_provider()
                    };
                    rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                        .expect("versions")
                        .with_root_certificates(roots)
                        .with_no_client_auth()
                }
            };
            let tcp = std::net::TcpStream::connect(&address).expect("connect");
            let mut stream = client_with("localhost", tcp, Arc::new(client)).expect("client");
            stream.write_all(b"ping").expect("write");
            stream.flush().expect("flush");
            let mut back = [0u8; 4];
            stream.read_exact(&mut back).expect("read");
            assert_eq!(&back, b"pong");
            stream
                .conn
                .negotiated_key_exchange_group()
                .expect("a group was agreed")
                .name()
        });

        let (tcp, _) = listener.accept().expect("accept");
        let mut guarded = server(tcp, config).expect("server session");
        let mut received = [0u8; 4];
        guarded.read_exact(&mut received).expect("read ping");
        assert_eq!(&received, b"ping");
        guarded.write_all(b"pong").expect("write pong");
        guarded.flush().expect("flush");
        let agreed = guarded
            .conn
            .negotiated_key_exchange_group()
            .expect("a group was agreed")
            .name();

        (caller.join().expect("client thread"), agreed)
    }

    #[test]
    fn two_nodes_agree_the_hybrid_post_quantum_key_exchange() {
        let hybrid = rustls::NamedGroup::X25519MLKEM768;

        assert_eq!(handshake(None), (hybrid, hybrid));
    }

    #[test]
    fn a_peer_that_knows_only_classical_groups_is_served_with_x25519() {
        let classical = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];

        assert_eq!(
            handshake(Some(classical)),
            (rustls::NamedGroup::X25519, rustls::NamedGroup::X25519)
        );
    }

    #[test]
    fn a_certificate_that_is_not_one_is_refused_by_reason() {
        let signed = self_signed();
        let key = signed.key_pair.serialize_pem();
        let failure = server_config(b"not a cert", key.as_bytes()).expect_err("refused");

        assert!(failure.message.contains("no certificate"), "{failure}");
    }
}
