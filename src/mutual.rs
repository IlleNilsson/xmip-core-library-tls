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

use rustls::sign::{CertifiedKey, SingleCertAndKey};

use crate::signer::{Kept, Sign};
use crate::{Result, TlsError, configure, provider};

/// What one end presents and what it trusts: its certificate chain and the
/// key that signs for it — read from PEM, or kept by its platform's keeper
/// and asked for each signature ([`Sign`]) — and the anchors a peer's chain
/// must reach.
#[derive(Clone)]
pub struct Identity {
    presented: Arc<CertifiedKey>,
    anchors: Arc<rustls::RootCertStore>,
}

impl Identity {
    /// The identity a chain, its key and the anchors make, each PEM.
    ///
    /// # Errors
    ///
    /// Where a PEM holds no certificate or no key, the certificate and key
    /// do not pair, or an anchor is not a certificate a trust store takes.
    pub fn from_pem(certificate_pem: &[u8], key_pem: &[u8], anchors_pem: &[u8]) -> Result<Self> {
        let certificates = certificates(certificate_pem, "the certificate")?;
        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .map_err(|failure| TlsError::new(format!("reading the private key: {failure}")))?
            .ok_or_else(|| TlsError::new("the key PEM held no private key"))?;
        let presented =
            CertifiedKey::from_der(certificates, key, &provider()).map_err(|failure| {
                TlsError::new(format!("loading the certificate and key: {failure}"))
            })?;
        Ok(Self {
            presented: Arc::new(presented),
            anchors: Arc::new(anchors(anchors_pem)?),
        })
    }

    /// The identity a chain, PEM, makes with a key this library cannot
    /// read: `signer` signs every handshake, ECDSA on P-256 with SHA-256
    /// (ADR-0034, amendment 2026-10-15). Whether the chain's leaf is the
    /// keeper's key is the handshake's to find: a peer refuses a signature
    /// its certificate does not verify.
    ///
    /// # Errors
    ///
    /// Where the chain holds no certificate, or an anchor is not a
    /// certificate a trust store takes.
    pub fn from_signer(
        certificate_pem: &[u8],
        signer: Arc<dyn Sign>,
        anchors_pem: &[u8],
    ) -> Result<Self> {
        let certificates = certificates(certificate_pem, "the certificate")?;
        Ok(Self {
            presented: Arc::new(CertifiedKey::new(certificates, Arc::new(Kept(signer)))),
            anchors: Arc::new(anchors(anchors_pem)?),
        })
    }

    /// The server side: presents this identity, and refuses a client that
    /// presents no certificate or one that does not reach the anchors.
    ///
    /// # Errors
    ///
    /// Where the anchors are empty.
    pub fn server(&self) -> Result<rustls::ServerConfig> {
        self.served(false)
    }

    /// The server side a browser reaches (ADR-0009, amendment 2026-10-21):
    /// presents this identity and asks the client for a certificate,
    /// verifying one presented against the anchors and refusing one that
    /// does not reach them; a client that presents none is let through,
    /// and [`crate::Peer::of`] then answers `None` — no one, who only
    /// watches.
    ///
    /// # Errors
    ///
    /// Where the anchors are empty.
    pub fn server_asking(&self) -> Result<rustls::ServerConfig> {
        self.served(true)
    }

    /// A server presenting this identity, verifying a client's certificate
    /// against the anchors; `asking`, a client may present none.
    fn served(&self, asking: bool) -> Result<rustls::ServerConfig> {
        self.served_by(asking, provider())
    }

    /// The same, built from `provider`: the general one, or the proving
    /// one of `possession`.
    pub(crate) fn served_by(
        &self,
        asking: bool,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<rustls::ServerConfig> {
        let builder = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::clone(&self.anchors),
            Arc::clone(&provider),
        );
        let builder = if asking {
            builder.allow_unauthenticated()
        } else {
            builder
        };
        let verifier = builder
            .build()
            .map_err(|failure| TlsError::new(format!("the client verifier: {failure}")))?;
        Ok(rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .unwrap_or_else(|_| unreachable!("the default versions are always supported"))
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(Arc::clone(
                &self.presented,
            )))))
    }

    /// The client side: checks the server against the anchors and presents
    /// this identity when asked, with a session cache to resume from, as
    /// [`configure`] keeps one.
    ///
    /// # Errors
    ///
    /// None today; a `Result` beside [`Identity::server`]'s.
    pub fn client(&self) -> Result<rustls::ClientConfig> {
        let mut config = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .unwrap_or_else(|_| unreachable!("the default versions are always supported"))
            .with_root_certificates(Arc::clone(&self.anchors))
            .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(Arc::clone(
                &self.presented,
            ))));
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

/// A client that trusts only the certificates `anchors_pem` holds — a
/// cluster's own authority, an ACME server it runs — never the operating
/// system's trust store; it presents no certificate of its own.
///
/// # Errors
///
/// Where the PEM holds no certificate, or one a trust store does not take.
pub fn trusting(anchors_pem: &[u8]) -> Result<rustls::ClientConfig> {
    let roots = anchors(anchors_pem)?;
    if roots.is_empty() {
        return Err(TlsError::new("the trust anchors held no certificate"));
    }
    Ok(configure(roots))
}

/// The trust store the certificates `pem` holds make.
fn anchors(pem: &[u8]) -> Result<rustls::RootCertStore> {
    let mut anchors = rustls::RootCertStore::empty();
    for anchor in certificates_of(pem, "the trust anchors")? {
        anchors
            .add(anchor)
            .map_err(|failure| TlsError::new(format!("a trust anchor: {failure}")))?;
    }
    Ok(anchors)
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

    fn issued(authority: &rcgen::CertifiedIssuer<'_, rcgen::KeyPair>, name: &str) -> Issued {
        let key = rcgen::KeyPair::generate().expect("a key");
        let params = rcgen::CertificateParams::new(vec![name.to_string()]).expect("params");
        let leaf = params.signed_by(&key, authority).expect("issued");
        Issued {
            authority: authority.pem(),
            certificate: leaf.pem(),
            key: key.serialize_pem(),
        }
    }

    fn authority() -> rcgen::CertifiedIssuer<'static, rcgen::KeyPair> {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().expect("a key");
        rcgen::CertifiedIssuer::self_signed(params, key).expect("signed")
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
            ours.pem().as_bytes(),
        )
        .expect("identity");
        assert!(!ping(
            Arc::new(foreign.client().expect("client")),
            &identity(&far)
        ));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ours.der().clone()).expect("anchor");
        assert!(!ping(Arc::new(configure(roots)), &identity(&far)));
    }

    /// A keeper: signs with a key this library is never handed, or refuses.
    struct Keeper(Option<Arc<dyn rustls::sign::SigningKey>>);

    impl crate::Sign for Keeper {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
            let key = self
                .0
                .as_ref()
                .ok_or_else(|| TlsError::new("the user said no"))?;
            let signer = key
                .choose_scheme(&[rustls::SignatureScheme::ECDSA_NISTP256_SHA256])
                .expect("P-256");
            signer
                .sign(message)
                .map_err(|failure| TlsError::new(failure.to_string()))
        }
    }

    fn kept(issued: &Issued, keeper: Keeper) -> Identity {
        Identity::from_signer(
            issued.certificate.as_bytes(),
            Arc::new(keeper),
            issued.authority.as_bytes(),
        )
        .expect("identity")
    }

    #[test]
    fn a_key_its_keeper_holds_signs_the_handshake_and_a_keeper_that_refuses_is_refused() {
        let ours = authority();
        let near = issued(&ours, "localhost");
        let far = issued(&ours, "localhost");
        let der = rustls_pemfile::private_key(&mut near.key.as_bytes())
            .expect("pem")
            .expect("a key");
        let key = rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&der).expect("ECDSA");

        let client = kept(&near, Keeper(Some(Arc::clone(&key)))).client();
        assert!(ping(Arc::new(client.expect("client")), &identity(&far)));
        let refusing = kept(&near, Keeper(None)).client().expect("client");
        assert!(!ping(Arc::new(refusing), &identity(&far)));

        // The other way about: a server whose key is kept answers too.
        let server = kept(&far, Keeper(Some(key)));
        assert!(!ping(
            Arc::new(identity(&near).client().expect("client")),
            &server
        ));
        let held = issued(&ours, "localhost");
        let der = rustls_pemfile::private_key(&mut held.key.as_bytes())
            .expect("pem")
            .expect("a key");
        let own = rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&der).expect("ECDSA");
        let server = kept(&held, Keeper(Some(own)));
        assert!(ping(
            Arc::new(identity(&near).client().expect("client")),
            &server
        ));

        let refused = Identity::from_signer(b"", Arc::new(Keeper(None)), b"").err();
        assert!(refused.expect("refused").message.contains("no certificate"));
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

    #[test]
    fn a_client_trusts_only_the_anchors_it_is_given_and_none_is_refused() {
        let ours = authority();
        assert!(trusting(ours.pem().as_bytes()).is_ok());
        let refused = trusting(b"").expect_err("refused");
        assert!(refused.message.contains("no certificate"), "{refused}");
    }
}
