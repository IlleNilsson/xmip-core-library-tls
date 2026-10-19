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
    let mut guarded = server(tcp, config)?;
    while guarded.conn.is_handshaking() {
        guarded
            .conn
            .complete_io(&mut guarded.sock)
            .map_err(|failure| TlsError::new(format!("the TLS handshake: {failure}")))?;
    }
    let peer = Peer::of(&guarded.conn)?;
    Ok((guarded, peer))
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

/// A certificate's SHA-256 fingerprint, `SHA256:` then lowercase hex: the
/// way a transport reports it beside the subject and a gate checks it.
#[must_use]
pub fn fingerprint(certificate: &[u8]) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, certificate);
    format!("SHA256:{}", codec::hex::encode(digest.as_ref()))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use super::*;
    use crate::{Identity, client_with};

    /// An authority, as PEM with its signing half.
    fn authority() -> (rcgen::Certificate, rcgen::KeyPair) {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Party CA");
        let key = rcgen::KeyPair::generate().expect("a key");
        (params.self_signed(&key).expect("signed"), key)
    }

    /// An identity `CN=<name>` the authority issued, trusting it.
    fn identity(by: &(rcgen::Certificate, rcgen::KeyPair), name: &str) -> Identity {
        let key = rcgen::KeyPair::generate().expect("a key");
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let leaf = params.signed_by(&key, &by.0, &by.1).expect("issued");
        Identity::from_pem(
            leaf.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
            by.0.pem().as_bytes(),
        )
        .expect("an identity")
    }

    /// `client` connects to a server presenting `server` and sends a word;
    /// what the server answered of it, and the word where it got one.
    fn answer(
        client: Arc<rustls::ClientConfig>,
        server: &Identity,
    ) -> Result<(Option<Peer>, Vec<u8>)> {
        let config = Arc::new(server.server().expect("a server"));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let caller = std::thread::spawn(move || {
            let tcp = std::net::TcpStream::connect(address).expect("connect");
            let mut stream = client_with("localhost", tcp, client).expect("client");
            let _ = stream.write_all(b"order");
            // Ended as TLS ends a Stream, and read to the server's close:
            // a socket closed with the server's session tickets unread is
            // reset, and on Windows a reset loses what was not yet read.
            stream.conn.send_close_notify();
            let _ = stream.flush();
            let _ = stream.read_to_end(&mut Vec::new());
        });
        let (tcp, _) = listener.accept().expect("accept");
        let answered = answered(tcp, config).map(|(mut guarded, peer)| {
            let mut read = Vec::new();
            let _ = guarded.read_to_end(&mut read);
            (peer, read)
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
        // Theirs, trusting ours so that only the server can refuse.
        let theirs = authority();
        let key = rcgen::KeyPair::generate().expect("a key");
        let leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("params")
            .signed_by(&key, &theirs.0, &theirs.1)
            .expect("issued");
        let stranger = Identity::from_pem(
            leaf.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
            ours.0.pem().as_bytes(),
        )
        .expect("an identity");
        let refused = answer(Arc::new(stranger.client().expect("a client")), &server)
            .expect_err("a stranger");
        assert!(refused.message.contains("handshake"), "{refused}");

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ours.0.der().clone()).expect("an anchor");
        let presents_nothing = crate::configure(roots);
        let refused = answer(Arc::new(presents_nothing), &server).expect_err("no certificate");
        assert!(refused.message.contains("handshake"), "{refused}");
    }

    #[test]
    fn a_fingerprint_is_the_leafs_sha256_in_lowercase_hex() {
        assert_eq!(
            fingerprint(b"abc"),
            "SHA256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
