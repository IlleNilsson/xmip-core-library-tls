//! The far side: a connection this node answers, presenting its certificate.

use std::net::TcpStream;
use std::sync::Arc;

use crate::{Result, TlsError, configuration, pem, provider};

/// A server-side TLS connection, ready to read and write — a Receive
/// Location's guarded channel. ADR-0033.
pub type GuardedServer = rustls::StreamOwned<rustls::ServerConnection, TcpStream>;

/// A server configuration from a certificate chain and its private key, both
/// PEM. This is the Receive side of certificates: the node presents this
/// certificate to callers. Client-certificate verification (mutual-TLS)
/// layers a verifier onto this. No session is resumed
/// (`configuration`).
///
/// # Errors
///
/// Where the certificate or key cannot be read, or the pair is not usable.
pub fn server_config(certificate_pem: &[u8], key_pem: &[u8]) -> Result<rustls::ServerConfig> {
    let provider = provider();
    let presented = pem::certified(certificate_pem, key_pem, &provider)?;
    Ok(configuration::server(
        provider,
        Arc::new(rustls::server::NoClientAuth),
        Arc::new(presented),
    ))
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

    use super::*;
    use crate::client::{client_with, configure};
    use crate::fixture::{connected, handshakes};

    fn self_signed() -> rcgen::CertifiedKey<rcgen::KeyPair> {
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
                signed.signing_key.serialize_pem().as_bytes(),
            )
            .expect("server config"),
        );

        let (calling, tcp) = connected();
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
            let mut stream = client_with("localhost", calling, Arc::new(client)).expect("client");
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
    fn a_client_that_would_resume_is_given_nothing_to_resume_and_shakes_hands_in_full() {
        let signed = self_signed();
        let served = server_config(
            signed.cert.pem().as_bytes(),
            signed.signing_key.serialize_pem().as_bytes(),
        )
        .expect("server config");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(signed.cert.der().clone()).expect("trusted");
        // A client of rustls's defaults: a session cache to resume from.
        let resuming = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .expect("versions")
            .with_root_certificates(roots)
            .with_no_client_auth();

        let full = Some(rustls::HandshakeKind::Full);
        let kinds = handshakes(&Arc::new(resuming), &Arc::new(served), 2);
        assert_eq!(kinds, [full, full]);
    }

    #[test]
    fn a_tls_1_2_client_that_would_resume_by_session_id_is_given_none_and_shakes_hands_in_full() {
        let signed = self_signed();
        let served = server_config(
            signed.cert.pem().as_bytes(),
            signed.signing_key.serialize_pem().as_bytes(),
        )
        .expect("server config");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(signed.cert.der().clone()).expect("trusted");
        // A TLS 1.2 client of rustls's defaults: it resumes by session ID
        // where the server stored one.
        let resuming = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("versions")
            .with_root_certificates(roots)
            .with_no_client_auth();

        let full = Some(rustls::HandshakeKind::Full);
        let kinds = handshakes(&Arc::new(resuming), &Arc::new(served), 2);
        assert_eq!(kinds, [full, full]);
    }

    #[test]
    fn a_certificate_that_is_not_one_is_refused_by_reason() {
        let signed = self_signed();
        let key = signed.signing_key.serialize_pem();
        let failure = server_config(b"not a cert", key.as_bytes()).expect_err("refused");

        assert!(failure.message.contains("no certificate"), "{failure}");
    }
}
