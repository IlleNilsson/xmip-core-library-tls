//! The certificate a client presented, as the server that terminated its
//! TLS reads it once the handshake has finished.
//!
//! What a transport writes on an arrival under `context::property`'s
//! `tls.peer.*` names (ADR-0019, amendment 2026-09-24), and what the first
//! gate reads back: the subject is the claim, the issuer and the
//! fingerprint ride beside it. Read here once, for every transport that
//! terminates TLS. The chain itself is not reported: a handshake that
//! verified the client has walked it already, and `mutual-tls` records that
//! rather than walking it again (ADR-0033, amendment 2026-09-18).

use std::net::TcpStream;
use std::sync::Arc;

use crate::name::Name;
use crate::{GuardedServer, Result, TlsError, server};

/// Answer a TLS connection on an accepted socket and finish its handshake
/// before a byte of content is read, saying who the client is: a server
/// whose configuration verifies clients has refused one whose chain does
/// not reach its anchors by the time this returns.
///
/// # Errors
///
/// Where the handshake fails — the client presented no certificate a
/// verifying server takes, or one that does not reach its anchors, or
/// stopped — or the socket's own wait ran out.
pub fn answered(
    tcp: TcpStream,
    config: Arc<rustls::ServerConfig>,
) -> Result<(GuardedServer, Option<Peer>)> {
    let guarded = handshaken(tcp, config).map_err(TlsError::from)?;
    let peer = Peer::of(&guarded.conn)?;
    Ok((guarded, peer))
}

/// Why a server's handshake did not finish, in two kinds: a host that
/// tells its audit of a certificate refused tells nothing of a client that
/// merely hung up.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Unanswered {
    /// The client's certificate was refused: one that does not reach the
    /// anchors, or none where the server requires one.
    Refused(TlsError),
    /// Anything else: the client stopped or spoke no TLS, the socket's wait
    /// ran out, or the session could not start.
    Failed(TlsError),
}

impl From<Unanswered> for TlsError {
    fn from(unanswered: Unanswered) -> Self {
        match unanswered {
            Unanswered::Refused(said) | Unanswered::Failed(said) => said,
        }
    }
}

/// Answer a TLS connection on an accepted socket and finish its handshake,
/// as [`answered`] does, saying of one that did not finish whether the
/// client's certificate was refused ([`Unanswered`]). Who the client is
/// the caller reads from the session ([`Peer::of`]).
///
/// # Errors
///
/// Where the handshake did not finish, by kind.
pub fn handshaken(
    tcp: TcpStream,
    config: Arc<rustls::ServerConfig>,
) -> core::result::Result<GuardedServer, Unanswered> {
    let mut guarded = server(tcp, config).map_err(Unanswered::Failed)?;
    completed(&mut guarded.conn, &mut guarded.sock)?;
    Ok(guarded)
}

/// `connection`'s handshake, driven over `io` until it has finished, saying
/// of one that did not whether the client's certificate was refused: the
/// one loop every server's handshake here runs, over its socket or over a
/// recording of it (`possession`).
///
/// # Errors
///
/// Where the handshake did not finish, by kind.
pub(crate) fn completed(
    connection: &mut rustls::ServerConnection,
    io: &mut (impl std::io::Read + std::io::Write),
) -> core::result::Result<(), Unanswered> {
    while connection.is_handshaking() {
        if let Err(failure) = connection.complete_io(io) {
            let said = TlsError::new(format!("the TLS handshake: {failure}"));
            let refused = matches!(
                failure
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
                Some(rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented)
            );
            return Err(if refused {
                Unanswered::Refused(said)
            } else {
                Unanswered::Failed(said)
            });
        }
    }
    Ok(())
}

/// What a client's certificate says of it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Peer {
    /// The leaf's subject, as [`Name`] writes it.
    pub subject: String,
    /// The leaf's issuer, as [`Name`] writes it.
    pub issuer: String,
    /// The leaf's SHA-256 fingerprint ([`fingerprint`]).
    pub fingerprint: String,
}

impl Peer {
    /// The client of `connection`, where it presented a certificate: read
    /// once the handshake has finished, so a server configured to verify
    /// clients has verified it by now. `None` where it presented none.
    ///
    /// # Errors
    ///
    /// The handshake has not finished, or the leaf is not X.509.
    pub fn of(connection: &rustls::ServerConnection) -> Result<Option<Self>> {
        if connection.is_handshaking() {
            return Err(TlsError::new(
                "the peer is read once the handshake has finished",
            ));
        }
        let Some(leaf) = connection.peer_certificates().and_then(<[_]>::first) else {
            return Ok(None);
        };
        Ok(Some(Self {
            subject: Name::subject_of(leaf)?.to_string(),
            issuer: Name::issuer_of(leaf)?.to_string(),
            fingerprint: fingerprint(leaf),
        }))
    }
}

/// The leaf the client of `connection` presented, DER, once its handshake
/// has finished: what a host hands a surface that reads the certificate
/// itself — a web host's `ConnectionInfo.ClientCertificate`. `None` where
/// it presented none, or the handshake has not finished.
#[must_use]
pub fn presented(connection: &rustls::ServerConnection) -> Option<Vec<u8>> {
    if connection.is_handshaking() {
        return None;
    }
    connection
        .peer_certificates()
        .and_then(<[_]>::first)
        .map(|leaf| leaf.as_ref().to_vec())
}

/// A certificate's SHA-256 fingerprint, `SHA256:` then lowercase hex: the
/// way a transport reports it beside the subject and a gate checks it.
#[must_use]
pub fn fingerprint(certificate: &[u8]) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, certificate);
    format!("SHA256:{}", codec::hex::encode(digest.as_ref()))
}

/// Whether the certificate `der` authenticates a server: its extended key
/// usage names `serverAuth`. A node's certificate does, between nodes both
/// ways; a person's authenticates a client alone (ADR-0034), so a plane
/// that serves Xmip's own parts tells the two apart by it. False for a
/// certificate that is not X.509 or names no extended key usage.
#[must_use]
pub fn authenticates_servers(der: &[u8]) -> bool {
    use x509_parser::prelude::{FromDer, X509Certificate};
    X509Certificate::from_der(der)
        .ok()
        .and_then(|(_, parsed)| {
            parsed
                .extended_key_usage()
                .ok()
                .flatten()
                .map(|eku| eku.value.server_auth)
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;
    use crate::fixture::connected;
    use crate::{Identity, client_with};

    #[test]
    fn a_nodes_certificate_authenticates_servers_and_a_persons_does_not() {
        let key = rcgen::KeyPair::generate().expect("a key");
        let mut node = rcgen::CertificateParams::new(vec!["n.example".to_string()]).expect("p");
        node.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let node = node.self_signed(&key).expect("signed");
        assert!(authenticates_servers(node.der()));
        let mut person = rcgen::CertificateParams::new(Vec::<String>::new()).expect("p");
        person.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let person = person.self_signed(&key).expect("signed");
        assert!(!authenticates_servers(person.der()));
        assert!(!authenticates_servers(b"not a certificate"));
    }

    /// An authority, as PEM with its signing half.
    fn authority() -> rcgen::CertifiedIssuer<'static, rcgen::KeyPair> {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Party CA");
        let key = rcgen::KeyPair::generate().expect("a key");
        rcgen::CertifiedIssuer::self_signed(params, key).expect("signed")
    }

    /// An identity `CN=<name>` the authority issued, trusting it.
    fn identity(by: &rcgen::CertifiedIssuer<'_, rcgen::KeyPair>, name: &str) -> Identity {
        let key = rcgen::KeyPair::generate().expect("a key");
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let leaf = params.signed_by(&key, by).expect("issued");
        Identity::from_pem(
            leaf.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
            by.pem().as_bytes(),
        )
        .expect("an identity")
    }

    /// `client` connects to a server presenting `server` and sends a word;
    /// what the server answered of it, and the word where it got one.
    fn answer(
        client: Arc<rustls::ClientConfig>,
        server: &Identity,
    ) -> Result<(Option<Peer>, Vec<u8>)> {
        answer_by(client, server.server().expect("a server"))
            .map(|(peer, _, read)| (peer, read))
            .map_err(TlsError::from)
    }

    /// What a server answered of its client, the leaf it presented, and the
    /// word it sent.
    type Heard = (Option<Peer>, Option<Vec<u8>>, Vec<u8>);

    /// As [`answer`], by a server configured `config`: what it heard, or
    /// why not by kind.
    fn answer_by(
        client: Arc<rustls::ClientConfig>,
        config: rustls::ServerConfig,
    ) -> core::result::Result<Heard, Unanswered> {
        let config = Arc::new(config);
        let (calling, tcp) = connected();
        let caller = std::thread::spawn(move || {
            let mut stream = client_with("localhost", calling, client).expect("client");
            let _ = stream.write_all(b"order");
            // Ended as TLS ends a Stream, and read to the server's close:
            // a socket closed with the server's session tickets unread is
            // reset, and on Windows a reset loses what was not yet read.
            stream.conn.send_close_notify();
            let _ = stream.flush();
            let _ = stream.read_to_end(&mut Vec::new());
        });
        let answered = handshaken(tcp, config).and_then(|mut guarded| {
            let peer = Peer::of(&guarded.conn).map_err(Unanswered::Failed)?;
            let leaf = presented(&guarded.conn);
            let mut read = Vec::new();
            let _ = guarded.read_to_end(&mut read);
            Ok((peer, leaf, read))
        });
        caller.join().expect("the caller");
        answered
    }

    #[test]
    fn a_client_the_anchors_take_is_answered_and_named_before_its_content_is_read() {
        let ours = authority();
        let server = identity(&ours, "localhost");
        let client = identity(&ours, "party-x.example")
            .client()
            .expect("a client");

        let (peer, read) = answer(Arc::new(client), &server).expect("answered");
        let peer = peer.expect("a client certificate");

        assert_eq!(peer.subject, "CN=party-x.example");
        assert_eq!(peer.issuer, "CN=Party CA");
        assert!(peer.fingerprint.starts_with("SHA256:"), "{peer:?}");
        assert_eq!(read, b"order");
    }

    #[test]
    fn a_client_another_authority_issued_is_refused_in_the_handshake() {
        let ours = authority();
        let server = identity(&ours, "localhost");
        let stranger = stranger(&ours);
        let refused = answer(Arc::new(stranger.client().expect("a client")), &server)
            .expect_err("a stranger");
        assert!(refused.message.contains("handshake"), "{refused}");

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ours.der().clone()).expect("an anchor");
        let presents_nothing = crate::configure(roots);
        let refused = answer(Arc::new(presents_nothing), &server).expect_err("no certificate");
        assert!(refused.message.contains("handshake"), "{refused}");
    }

    #[test]
    fn a_server_asking_names_its_anchors_client_lets_one_without_through_refuses_a_stranger() {
        let ours = authority();
        let server = identity(&ours, "localhost");
        let asking = || server.server_asking().expect("a server");
        let client = identity(&ours, "party-x.example")
            .client()
            .expect("a client");

        let (peer, leaf, read) = answer_by(Arc::new(client), asking()).expect("answered");
        let leaf = leaf.expect("the leaf it presented");
        assert_eq!(peer.expect("named").fingerprint, fingerprint(&leaf));
        assert_eq!(read, b"order");

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ours.der().clone()).expect("an anchor");
        let watcher = Arc::new(crate::configure(roots));
        let (peer, leaf, read) = answer_by(watcher, asking()).expect("let through");
        assert_eq!((peer, leaf), (None, None));
        assert_eq!(read, b"order");

        let stranger = stranger(&ours).client().expect("a client");
        let refused = answer_by(Arc::new(stranger), asking()).expect_err("a stranger");
        assert!(matches!(refused, Unanswered::Refused(_)), "{refused:?}");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ours.der().clone()).expect("an anchor");
        let watcher = Arc::new(crate::configure(roots));
        let required = answer_by(watcher, server.server().expect("a server"))
            .expect_err("no certificate where one is required");
        assert!(matches!(required, Unanswered::Refused(_)), "{required:?}");
    }

    /// An identity another authority issued, trusting `ours`, so that only
    /// the server can refuse it.
    fn stranger(ours: &rcgen::CertifiedIssuer<'_, rcgen::KeyPair>) -> Identity {
        let theirs = authority();
        let key = rcgen::KeyPair::generate().expect("a key");
        let leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("params")
            .signed_by(&key, &theirs)
            .expect("issued");
        Identity::from_pem(
            leaf.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
            ours.pem().as_bytes(),
        )
        .expect("an identity")
    }

    #[test]
    fn a_fingerprint_is_the_sha256_of_the_leaf_in_lowercase_hex() {
        assert_eq!(
            fingerprint(b"abc"),
            "SHA256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
