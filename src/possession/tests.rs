//! The possession proof made and checked over loopback: a browser's
//! handshake over TLS 1.3, over 1.3 retried, and over 1.2, each recorded
//! with the random bound and its transcript proved — the `ServerHello`'s
//! random holding the binding, which pins the order in which rustls 0.23.46
//! draws its randoms — a transcript that is not the handshake's, or a
//! handshake with no certificate, proving nothing, and a handshake that
//! panics leaving its thread disarmed.

use std::sync::Arc;
use std::time::Duration;

use rcgen::{CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use super::{binding, handshaken, proved, proving};
use crate::fixture::connected;
use crate::{Identity, Result};

/// A test authority, the server's identity under it, and a client's
/// certificate and key under it.
struct Parties {
    server: Identity,
    server_leaf: Vec<u8>,
    server_chain: String,
    authority: CertificateDer<'static>,
    authority_pem: String,
    client: (CertificateDer<'static>, Vec<u8>),
}

fn parties() -> Parties {
    let authority_key = KeyPair::generate().expect("a key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let authority = CertifiedIssuer::self_signed(params, authority_key).expect("an authority");
    let issue = |purpose: ExtendedKeyUsagePurpose, name: &str| {
        let key = KeyPair::generate().expect("a key");
        let mut params = CertificateParams::new(vec![name.to_string()]).expect("params");
        params.extended_key_usages = vec![purpose];
        let issued = params.signed_by(&key, &authority).expect("issued");
        (issued, key)
    };
    let (server, server_key) = issue(ExtendedKeyUsagePurpose::ServerAuth, "localhost");
    let (client, client_key) = issue(ExtendedKeyUsagePurpose::ClientAuth, "alice");
    let identity = Identity::from_pem(
        server.pem().as_bytes(),
        server_key.serialize_pem().as_bytes(),
        authority.pem().as_bytes(),
    )
    .expect("the server's identity");
    Parties {
        server: identity,
        server_leaf: server.der().to_vec(),
        server_chain: server.pem(),
        authority: authority.der().clone(),
        authority_pem: authority.pem(),
        client: (client.der().clone(), client_key.serialize_der()),
    }
}

/// A browser's handshake at the given versions and key exchange groups,
/// presenting the client certificate or none, against a proving server
/// whose random is bound to `bound`: the transcript the server recovered.
fn handshake(
    parties: &Parties,
    versions: &[&'static rustls::SupportedProtocolVersion],
    groups: &[&'static dyn rustls::crypto::SupportedKxGroup],
    presenting: bool,
    bound: [u8; super::BINDING],
) -> Result<Vec<u8>> {
    let config = Arc::new(proving(&parties.server).expect("proving"));
    let provider = Arc::new(rustls::crypto::CryptoProvider {
        kx_groups: groups.to_vec(),
        ..(*crate::provider()).clone()
    });
    let mut roots = rustls::RootCertStore::empty();
    roots.add(parties.authority.clone()).expect("trusted");
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .expect("versions")
        .with_root_certificates(roots);
    let client = if presenting {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(parties.client.1.clone()));
        builder
            .with_client_auth_cert(vec![parties.client.0.clone()], key)
            .expect("a client certificate")
    } else {
        builder.with_no_client_auth()
    };
    let (mut near, tcp) = connected();
    let browser = std::thread::spawn(move || {
        near.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("bounded");
        let name = "localhost".try_into().expect("a name");
        let mut connection =
            rustls::ClientConnection::new(Arc::new(client), name).expect("a session");
        while connection.is_handshaking() {
            if connection.complete_io(&mut near).is_err() {
                break;
            }
        }
    });
    tcp.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("bounded");
    let (_, recorded) = handshaken(tcp, config, bound).expect("handshaken");
    let transcript = recorded.transcript();
    browser.join().expect("the browser");
    transcript
}

const TLS13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
const TLS12: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];

#[test]
fn every_version_binds_the_random_and_the_browsers_key_is_proven_to_hold_it() {
    use rustls::crypto::aws_lc_rs::kx_group::{MLKEM768, X25519, X25519MLKEM768};
    let parties = parties();
    let bound = binding(&[b"node one's nonce", b"node two's nonce"]);
    // TLS 1.3; TLS 1.3 retried, the browser's first key share one the
    // server does not take; TLS 1.2.
    let cases: [(
        &[&rustls::SupportedProtocolVersion],
        &[&dyn rustls::crypto::SupportedKxGroup],
        bool,
    ); 3] = [
        (TLS13, &[X25519MLKEM768, X25519], true),
        (TLS13, &[MLKEM768, X25519], true),
        (TLS12, &[X25519], false),
    ];
    for (versions, groups, tls13) in cases {
        let transcript = handshake(&parties, versions, groups, true, bound).expect("a transcript");
        let proof = proved(&transcript).expect("proved");
        assert_eq!(
            proof.server_random[..super::BINDING],
            bound,
            "rustls's draw order holds"
        );
        assert_eq!(proof.tls13, tls13);
        assert_eq!(proof.client_chain[0], parties.client.0.to_vec());
        assert_eq!(proof.server_leaf, parties.server_leaf);

        // One byte of the `ClientHello` changed proves nothing.
        let mut tampered = transcript.clone();
        tampered[12] ^= 1;
        assert!(proved(&tampered).is_err());
    }
}

/// A keeper that panics when the handshake asks it to sign.
struct Panicking;

impl crate::Sign for Panicking {
    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>> {
        panic!("a keeper that panics in the middle of a handshake");
    }
}

#[test]
fn a_panic_inside_a_recorded_handshake_leaves_the_thread_disarmed() {
    use rustls::crypto::aws_lc_rs::kx_group::X25519;
    let mut parties = parties();
    parties.server = Identity::from_signer(
        parties.server_chain.as_bytes(),
        Arc::new(Panicking),
        parties.authority_pem.as_bytes(),
    )
    .expect("a server whose keeper panics");
    let bound = binding(&[b"a nonce"]);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        handshake(&parties, TLS13, &[X25519], true, bound)
    }));
    assert!(unwound.is_err(), "the keeper panicked inside the handshake");
    assert!(!super::recorded::armed(), "disarmed and its secrets taken");
    let mut random = [0u8; 32];
    super::bound::provider()
        .secure_random
        .fill(&mut random)
        .expect("drawn");
    assert_ne!(
        random[..super::BINDING],
        bound,
        "a draw after is the system's"
    );
}

#[test]
fn a_browser_that_presents_no_certificate_proves_nothing() {
    use rustls::crypto::aws_lc_rs::kx_group::X25519;
    let parties = parties();
    let refused =
        handshake(&parties, TLS13, &[X25519], false, [7; super::BINDING]).expect_err("no proof");
    assert!(
        refused.message.contains("no client certificate"),
        "{refused}"
    );
}
