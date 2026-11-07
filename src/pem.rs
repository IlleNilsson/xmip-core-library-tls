//! Certificates and a private key read from PEM: what the near and the far
//! side present, and the anchors a peer's chain must reach. Read through
//! rustls-pki-types' `PemObject`, which rustls already brings; until
//! 2026-11-07 through `rustls-pemfile`, archived upstream, and the key
//! read in two places.

use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::{Result, TlsError};

/// Every certificate `pem` holds, `what` naming it where a block does not
/// read; none where it holds none.
///
/// # Errors
///
/// A `CERTIFICATE` block that is not PEM.
pub(crate) fn certificates(pem: &[u8], what: &str) -> Result<Vec<CertificateDer<'static>>> {
    CertificateDer::pem_slice_iter(pem)
        .collect::<core::result::Result<Vec<_>, _>>()
        .map_err(|failure| TlsError::new(format!("reading {what}: {failure}")))
}

/// The first private key `pem` holds: PKCS #8, PKCS #1 or SEC 1.
///
/// # Errors
///
/// No private key in it, or a block that is not PEM.
pub(crate) fn private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_slice(pem).map_err(|failure| match failure {
        pem::Error::NoItemsFound => TlsError::new("the key PEM held no private key"),
        failure => TlsError::new(format!("reading the private key: {failure}")),
    })
}
