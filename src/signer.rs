//! A key this library cannot read: the end's private key is kept by its
//! platform's keeper — the Android Keystore, the iOS keychain's Secure
//! Enclave, Windows CNG and the TPM — and every signature the handshake
//! needs is asked of it (ADR-0034, amendment 2026-10-15). The keeper signs
//! ECDSA on P-256 with SHA-256, the one scheme this offers, since every
//! keeper above holds P-256 and an operator's certificate is for one.

use std::sync::Arc;

use rustls::SignatureScheme;
use rustls::sign::{Signer, SigningKey};

use crate::Result;

/// What signs for an end whose key is kept elsewhere: ECDSA on P-256 over
/// `message`, unhashed — the keeper hashes it with SHA-256 — and the
/// signature DER, `r` and `s` as X.509 carries them.
pub trait Sign: Send + Sync {
    /// The keeper's signature over `message`.
    ///
    /// # Errors
    ///
    /// Where the keeper refused or failed, in its words.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;
}

/// The keeper as rustls asks a key: one scheme, every signature asked of
/// the keeper.
pub(crate) struct Kept(pub(crate) Arc<dyn Sign>);

impl core::fmt::Debug for Kept {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Kept(ECDSA P-256 SHA-256, signed by its keeper)")
    }
}

impl SigningKey for Kept {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| Box::new(Self(Arc::clone(&self.0))) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ECDSA
    }
}

impl Signer for Kept {
    fn sign(&self, message: &[u8]) -> core::result::Result<Vec<u8>, rustls::Error> {
        self.0.sign(message).map_err(|refused| {
            rustls::Error::General(format!("the keeper did not sign: {}", refused.message))
        })
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}
