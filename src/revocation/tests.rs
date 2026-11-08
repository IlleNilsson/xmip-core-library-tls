//! Revocation attacked over loopback: a revoked client refused and its
//! neighbor let through, an expired list refusing every client unless
//! accepted, a list written anew read at the next handshake, and a list
//! gone refusing rather than letting anyone through.

use std::assert_matches;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer,
    ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, RevokedCertParams,
    SerialNumber, date_time_ymd,
};

use super::Revocation;
use crate::fixture::connected;
use crate::peer::{Unanswered, handshaken};
use crate::{Identity, client_with};

type Authority = CertifiedIssuer<'static, KeyPair>;

fn authority() -> Authority {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    CertifiedIssuer::self_signed(params, KeyPair::generate().expect("a key")).expect("signed")
}

/// A leaf of `authority`, serial `serial`, for `purpose`: its PEM and key.
fn leaf(authority: &Authority, serial: u64, purpose: ExtendedKeyUsagePurpose) -> (String, String) {
    let key = KeyPair::generate().expect("a key");
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    params.serial_number = Some(SerialNumber::from(serial));
    params.extended_key_usages = vec![purpose];
    let issued = params.signed_by(&key, authority).expect("issued");
    (issued.pem(), key.serialize_pem())
}

/// A list `authority` signs revoking `serials`, valid from `from` to
/// `until` (years), PEM.
fn list(authority: &Authority, serials: &[u64], from: i32, until: i32) -> String {
    let revoked_certs = serials
        .iter()
        .map(|serial| RevokedCertParams {
            serial_number: SerialNumber::from(*serial),
            revocation_time: date_time_ymd(from, 1, 1),
            reason_code: None,
            invalidity_date: None,
        })
        .collect();
    let params = CertificateRevocationListParams {
        this_update: date_time_ymd(from, 1, 1),
        next_update: date_time_ymd(until, 1, 1),
        crl_number: SerialNumber::from(1),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    };
    params
        .signed_by(&**authority)
        .expect("a list")
        .pem()
        .expect("PEM")
}

/// A server of `authority` refusing by `revocation`.
fn server(authority: &Authority, revocation: Revocation) -> Arc<rustls::ServerConfig> {
    let (certificate, key) = leaf(authority, 1, ExtendedKeyUsagePurpose::ServerAuth);
    let identity = Identity::from_pem(
        certificate.as_bytes(),
        key.as_bytes(),
        authority.pem().as_bytes(),
    )
    .expect("identity")
    .revoking(Arc::new(revocation));
    Arc::new(identity.server().expect("a server"))
}

/// The handshake a client of `authority`, serial `serial`, makes with
/// `server`: answered, or why not.
fn answer(
    authority: &Authority,
    serial: u64,
    server: &Arc<rustls::ServerConfig>,
) -> Result<(), Unanswered> {
    let (certificate, key) = leaf(authority, serial, ExtendedKeyUsagePurpose::ClientAuth);
    let client = Identity::from_pem(
        certificate.as_bytes(),
        key.as_bytes(),
        authority.pem().as_bytes(),
    )
    .expect("identity")
    .client()
    .expect("a client");
    let (near, far) = connected();
    near.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("bounded");
    far.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("bounded");
    let calling = std::thread::spawn(move || {
        let mut stream = client_with("localhost", near, Arc::new(client)).expect("a client");
        let _ = stream.write_all(b"order");
        // Ended as TLS ends a stream and read to the server's close, as
        // `peer`'s tests do: Windows loses what a reset socket left unread.
        stream.conn.send_close_notify();
        let _ = stream.flush();
        let _ = stream.read_to_end(&mut Vec::new());
    });
    let answered = handshaken(far, Arc::clone(server)).map(|mut guarded| {
        let _ = guarded.read_to_end(&mut Vec::new());
    });
    calling.join().expect("the client");
    answered
}

#[test]
fn a_revoked_client_is_refused_and_its_neighbor_is_not() {
    let ours = authority();
    let held = Revocation::from_lists(list(&ours, &[7], 2000, 2100).as_bytes()).expect("lists");
    let server = server(&ours, held);
    let refused = answer(&ours, 7, &server).expect_err("revoked");
    assert_matches!(refused, Unanswered::Refused(_), "{refused:?}");
    answer(&ours, 8, &server).expect("not revoked");
}

#[test]
fn an_expired_list_refuses_every_client_unless_configuration_accepts_it() {
    let ours = authority();
    let expired = list(&ours, &[], 2000, 2001);
    let server_refusing = server(
        &ours,
        Revocation::from_lists(expired.as_bytes()).expect("lists"),
    );
    let refused = answer(&ours, 8, &server_refusing).expect_err("expired");
    assert_matches!(refused, Unanswered::Refused(_), "{refused:?}");
    let refused = format!("{refused:?}");
    assert!(refused.contains("xpired"), "{refused}");

    let accepting = Revocation::from_lists(expired.as_bytes())
        .expect("lists")
        .accepting_expired();
    answer(&ours, 8, &server(&ours, accepting)).expect("accepted, as configured");
}

/// A file of its own under the system's temporary folder, removed when
/// dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let folder =
            std::env::temp_dir().join(format!("xmip-tls-revocation-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&folder).expect("a folder");
        Self(folder.join("authority.crl"))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Some(folder) = self.0.parent() {
            let _ = std::fs::remove_dir_all(folder);
        }
    }
}

#[test]
fn a_list_written_anew_is_read_at_the_next_handshake_and_one_gone_refuses() {
    let ours = authority();
    let scratch = Scratch::new("anew");
    std::fs::write(&scratch.0, list(&ours, &[], 2000, 2100)).expect("written");
    let server = server(&ours, Revocation::from_file(&scratch.0).expect("lists"));
    answer(&ours, 9, &server).expect("not revoked yet");

    std::fs::write(&scratch.0, list(&ours, &[9], 2000, 2100)).expect("written anew");
    let refused = answer(&ours, 9, &server).expect_err("revoked since");
    assert_matches!(refused, Unanswered::Refused(_), "{refused:?}");

    std::fs::remove_file(&scratch.0).expect("removed");
    answer(&ours, 10, &server).expect_err("no list, no one");
}

#[test]
fn bytes_that_hold_no_list_are_refused_by_reason() {
    let refused = Revocation::from_lists(b"").expect_err("nothing");
    assert!(refused.message.contains("no list"), "{refused}");
    let refused =
        Revocation::from_lists(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
            .expect_err("no list block");
    assert!(refused.message.contains("no X509 CRL"), "{refused}");
    let gone = std::env::temp_dir().join("xmip-tls-revocation-never-written.crl");
    assert!(Revocation::from_file(gone).is_err());
}
