//! Certificates and a private key read from PEM: what the near and the far
//! side present, and the anchors a peer's chain must reach. The armor is
//! the estate's one PEM reader, `codec::pem`; until 2026-11-13 it was
//! rustls-pki-types' `PemObject`, and until 2026-11-07 `rustls-pemfile`.

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use rustls::sign::CertifiedKey;

use crate::{Result, TlsError};

/// The labels a private key is written under: PKCS #8, PKCS #1, SEC 1.
const KEY_LABELS: [&str; 3] = ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"];

/// The chain an end presents, `certificate_pem`, and the key `key_pem`
/// that signs for it, loaded by `provider` and checked to pair where the
/// key says enough to tell.
///
/// # Errors
///
/// Where the PEM holds no certificate or no key, or the two do not pair.
pub(crate) fn certified(
    certificate_pem: &[u8],
    key_pem: &[u8],
    provider: &CryptoProvider,
) -> Result<CertifiedKey> {
    let chain = chain(certificate_pem, "the certificate")?;
    let key = private_key(key_pem)?;
    CertifiedKey::from_der(chain, key, provider)
        .map_err(|failure| TlsError::new(format!("loading the certificate and key: {failure}")))
}

/// The chain `pem` holds, the leaf first, `what` naming it: one
/// certificate at least.
///
/// # Errors
///
/// Where it holds none, or a block that is not PEM.
pub(crate) fn chain(pem: &[u8], what: &str) -> Result<Vec<CertificateDer<'static>>> {
    let found = certificates(pem, what)?;
    if found.is_empty() {
        return Err(TlsError::new(format!("{what} held no certificate")));
    }
    Ok(found)
}

/// Every certificate `pem` holds, `what` naming it where a block does not
/// read; none where it holds none.
///
/// # Errors
///
/// A `CERTIFICATE` block that is not PEM, or text that is not text.
pub(crate) fn certificates(pem: &[u8], what: &str) -> Result<Vec<CertificateDer<'static>>> {
    let blocks = codec::pem::decode("CERTIFICATE", text(pem, what)?)
        .map_err(|failure| TlsError::new(format!("reading {what}: {failure}")))?;
    Ok(blocks.into_iter().map(CertificateDer::from).collect())
}

/// The first private key `pem` holds: PKCS #8, PKCS #1 or SEC 1.
///
/// # Errors
///
/// No private key in it, or a block that is not PEM.
pub(crate) fn private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let found = codec::pem::first_of(&KEY_LABELS, text(pem, "the private key")?)
        .map_err(|failure| TlsError::new(format!("reading the private key: {failure}")))?;
    match found {
        Some(("PRIVATE KEY", der)) => Ok(PrivatePkcs8KeyDer::from(der).into()),
        Some(("RSA PRIVATE KEY", der)) => Ok(PrivatePkcs1KeyDer::from(der).into()),
        Some((_, der)) => Ok(PrivateSec1KeyDer::from(der).into()),
        None => Err(TlsError::new("the key PEM held no private key")),
    }
}

/// `pem` as text, `what` naming it where it is not.
fn text<'a>(pem: &'a [u8], what: &str) -> Result<&'a str> {
    core::str::from_utf8(pem).map_err(|_| TlsError::new(format!("reading {what}: not PEM text")))
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;

    #[test]
    fn a_key_is_read_under_any_of_its_labels_and_none_is_refused_in_words() {
        let signed = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("a certificate");
        let pkcs8 = signed.signing_key.serialize_pem();
        let read = private_key(pkcs8.as_bytes()).expect("a key");
        assert_matches!(read, PrivateKeyDer::Pkcs8(_));
        let der = signed.signing_key.serialize_der();
        let sec1 = codec::pem::encode("EC PRIVATE KEY", &der);
        let read = private_key(sec1.as_bytes()).expect("a key");
        assert_matches!(read, PrivateKeyDer::Sec1(_));
        let refused = private_key(signed.cert.pem().as_bytes()).expect_err("no key");
        assert!(refused.message.contains("no private key"), "{refused}");
        assert_eq!(
            chain(signed.cert.pem().as_bytes(), "x").expect("one").len(),
            1
        );
        assert!(chain(b"", "the anchors").is_err());
    }
}
