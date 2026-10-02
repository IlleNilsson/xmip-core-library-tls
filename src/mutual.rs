//! Mutual TLS: both ends present a certificate, and each checks the
//! other's against the anchors it was given.
//!
//! Every connection between two of Xmip's own parts is mutual TLS through
//! this library (ADR-0063 clause 1); the first built on it is a node
//! calling Xmip Storage, the nodes declaring the Storage role (ADR-0063,
//! amendment 2026-10-01: *Xmip encrypts to Xmip Node with Role/Type
//! Storage*). The anchors are the ones a node's own provisioning gave it
//! (ADR-0034), never the operating system's trust store: a peer is one of
//! the cluster's own nodes, not anyone a public authority vouches for.

use std::sync::Arc;

use crate::{Result, TlsError, configure, provider};

/// What one end presents and what it trusts: its certificate chain and
/// private key, and the anchors a peer's chain must reach, each PEM.
#[derive(Clone)]
pub struct Identity {
    certificates: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: Arc<rustls::pki_types::PrivateKeyDer<'static>>,
    anchors: Arc<rustls::RootCertStore>,
}

impl Identity {
    /// The identity a chain, its key and the anchors make.
    ///
    /// # Errors
    ///
    /// Where a PEM holds no certificate or no key, or an anchor is not a
    /// certificate a trust store takes.
    pub fn from_pem(certificate_pem: &[u8], key_pem: &[u8], anchors_pem: &[u8]) -> Result<Self> {
        let certificates = certificates(certificate_pem, "the certificate")?;
        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .map_err(|failure| TlsError::new(format!("reading the private key: {failure}")))?
            .ok_or_else(|| TlsError::new("the key PEM held no private key"))?;
        let mut anchors = rustls::RootCertStore::empty();
        for anchor in certificates_of(anchors_pem, "the trust anchors")? {
            anchors
                .add(anchor)
                .map_err(|failure| TlsError::new(format!("a trust anchor: {failure}")))?;
        }
        Ok(Self {
            certificates,
            key: Arc::new(key),
            anchors: Arc::new(anchors),
        })
    }

    /// The server side: presents this identity, and refuses a client that
    /// presents no certificate or one that does not reach the anchors.
    ///
    /// # Errors
    ///
    /// Where the anchors are empty or the certificate and key do not pair.
    pub fn server(&self) -> Result<rustls::ServerConfig> {
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::clone(&self.anchors),
            provider(),
        )
        .build()
        .map_err(|failure| TlsError::new(format!("the client verifier: {failure}")))?;
        rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .unwrap_or_else(|_| unreachable!("the default versions are always supported"))
            .with_client_cert_verifier(verifier)
            .with_single_cert(self.certificates.clone(), self.key.clone_key())
            .map_err(|failure| TlsError::new(format!("loading the certificate and key: {failure}")))
    }

    /// The client side: checks the server against the anchors and presents
    /// this identity when asked, with a session cache to resume from, as
    /// [`configure`] keeps one.
    ///
    /// # Errors
    ///
    /// Where the certificate and key do not pair.
    pub fn client(&self) -> Result<rustls::ClientConfig> {
        let mut config = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .unwrap_or_else(|_| unreachable!("the default versions are always supported"))
            .with_root_certificates(Arc::clone(&self.anchors))
            .with_client_auth_cert(self.certificates.clone(), self.key.clone_key())
            .map_err(|failure| {
                TlsError::new(format!("loading the certificate and key: {failure}"))
            })?;
        config.resumption = configure(rustls::RootCertStore::empty()).resumption;
        Ok(config)
    }
}

fn certificates(pem: &[u8], what: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let found = certificates_of(pem, what)?;
    if found.is_empty() {
        return Err(TlsError::new(format!("{what} held no certificate")));
    }
    Ok(found)
}

fn certificates_of(
    pem: &[u8],
    what: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut &pem[..])
        .collect::<core::result::Result<Vec<_>, _>>()
        .map_err(|failure| TlsError::new(format!("reading {what}: {failure}")))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    use super::*;
    use crate::{client_with, server};

    /// An authority, and a leaf it issued for `name`, as PEM.
    struct Issued {
        authority: String,
        certificate: String,
        key: String,
    }

    fn issued(authority: &rcgen::CertifiedKey, name: &str) -> Issued {
        let key = rcgen::KeyPair::generate().expect("a key");
        let params = rcgen::CertificateParams::new(vec![name.to_string()]).expect("params");
        let leaf = params
            .signed_by(&key, &authority.cert, &authority.key_pair)
            .expect("issued");
        Issued {
            authority: authority.cert.pem(),
            certificate: leaf.pem(),
            key: key.serialize_pem(),
        }
    }

    fn authority() -> rcgen::CertifiedKey {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().expect("a key");
        let cert = params.self_signed(&key).expect("signed");
        rcgen::CertifiedKey {
            cert,
            key_pair: key,
        }
    }

    fn identity(issued: &Issued) -> Identity {
        Identity::from_pem(
            issued.certificate.as_bytes(),
            issued.key.as_bytes(),
            issued.authority.as_bytes(),
        )
        .expect("identity")
    }

    /// A ping over a handshake between `near` and a server presenting
    /// `far`: whether it went through.
    fn ping(near: Arc<rustls::ClientConfig>, far: &Identity) -> bool {
        let config = Arc::new(far.server().expect("server config"));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let caller = std::thread::spawn(move || {
            let tcp = TcpStream::connect(address).expect("connect");
            let mut stream = client_with("localhost", tcp, near).expect("client");
            stream.write_all(b"ping").is_ok() && stream.flush().is_ok() && {
                let mut back = [0u8; 4];
                stream.read_exact(&mut back).is_ok()
            }
        });
        let (tcp, _) = listener.accept().expect("accept");
        let mut guarded = server(tcp, config).expect("server");
        let mut received = [0u8; 4];
        if guarded.read_exact(&mut received).is_ok() {
            let _ = guarded.write_all(b"pong");
            let _ = guarded.flush();
        }
        drop(guarded);
        caller.join().expect("caller")
    }

    #[test]
    fn two_nodes_of_one_authority_agree_and_a_stranger_or_no_certificate_is_refused() {
        let ours = authority();
        let near = issued(&ours, "localhost");
        let far = issued(&ours, "localhost");
        assert!(ping(
            Arc::new(identity(&near).client().expect("client")),
            &identity(&far)
        ));

        let theirs = authority();
        let stranger = issued(&theirs, "localhost");
        let foreign = Identity::from_pem(
            stranger.certificate.as_bytes(),
            stranger.key.as_bytes(),
            ours.cert.pem().as_bytes(),
        )
        .expect("identity");
        assert!(!ping(
            Arc::new(foreign.client().expect("client")),
            &identity(&far)
        ));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ours.cert.der().clone()).expect("anchor");
        assert!(!ping(Arc::new(configure(roots)), &identity(&far)));
    }

    #[test]
    fn a_pem_with_no_certificate_or_no_key_is_refused_by_reason() {
        let ours = authority();
        let leaf = issued(&ours, "localhost");
        let refused = Identity::from_pem(b"", leaf.key.as_bytes(), leaf.authority.as_bytes());
        assert!(
            refused
                .err()
                .expect("refused")
                .message
                .contains("no certificate")
        );
        let refused = Identity::from_pem(leaf.certificate.as_bytes(), b"", b"");
        assert!(
            refused
                .err()
                .expect("refused")
                .message
                .contains("no private key")
        );
    }
}
