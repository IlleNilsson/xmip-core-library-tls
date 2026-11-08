//! The revocation lists a mutual-TLS server refuses a client's certificate
//! by (RFC 5280 section 5): the authority's, read from the file it keeps —
//! `provision::register`'s `authority.crl`, DER, switched into place whole —
//! or handed over, PEM or DER. A file is looked at again by every handshake
//! that verifies a client, its metadata alone, and read again only where it
//! changed, so a certificate revoked is refused from the next handshake on;
//! nothing watches it. A list past its nextUpdate refuses every client it
//! would decide, unless [`Revocation::accepting_expired`] says otherwise: a
//! server that cannot know whether a certificate still stands does not
//! guess. A certificate whose issuer published no list held is refused as
//! of unknown status, and every certificate on the path below the anchor is
//! checked.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::SystemTime;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme};

use crate::{Result, TlsError};

/// The lists, the file they came from where one did, and whether a list
/// past its nextUpdate is let decide.
#[derive(Debug)]
pub struct Revocation {
    file: Option<PathBuf>,
    accepting_expired: bool,
    held: RwLock<Held>,
}

/// The lists as last read, what the file looked like then, and how many
/// times they were read: a verifier rebuilds when that count moves.
#[derive(Clone, Debug)]
struct Held {
    lists: Arc<[CertificateRevocationListDer<'static>]>,
    stamp: Option<Stamp>,
    generation: u64,
}

/// A file's modification time and length.
type Stamp = (SystemTime, u64);

impl Revocation {
    /// The lists kept in the file at `path`, read now and again whenever
    /// it changes.
    ///
    /// # Errors
    ///
    /// Where the file cannot be read or holds no list.
    pub fn from_file(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let (lists, stamp) = read(&path)?;
        Ok(Self::holding(Some(path), lists, Some(stamp)))
    }

    /// The lists `bytes` holds: PEM, every `X509 CRL` block, or one list
    /// DER. Changed only by [`Revocation::replace`].
    ///
    /// # Errors
    ///
    /// Where `bytes` holds no list.
    pub fn from_lists(bytes: &[u8]) -> Result<Self> {
        Ok(Self::holding(
            None,
            lists(bytes, "the revocation lists")?,
            None,
        ))
    }

    fn holding(
        file: Option<PathBuf>,
        lists: Vec<CertificateRevocationListDer<'static>>,
        stamp: Option<Stamp>,
    ) -> Self {
        Self {
            file,
            accepting_expired: false,
            held: RwLock::new(Held {
                lists: lists.into(),
                stamp,
                generation: 0,
            }),
        }
    }

    /// Let a list past its nextUpdate decide, as configuration says; a
    /// list that has expired is refused otherwise.
    #[must_use]
    pub const fn accepting_expired(mut self) -> Self {
        self.accepting_expired = true;
        self
    }

    /// Hold the lists `bytes` holds from the next handshake on.
    ///
    /// # Errors
    ///
    /// Where `bytes` holds no list; the lists held stay.
    pub fn replace(&self, bytes: &[u8]) -> Result<()> {
        let lists = lists(bytes, "the revocation lists")?;
        let mut held = self.held.write().unwrap_or_else(PoisonError::into_inner);
        held.lists = lists.into();
        held.generation += 1;
        Ok(())
    }

    /// The lists as they stand, read again where the file changed, and
    /// their generation.
    fn current(&self) -> Result<Held> {
        let held = self
            .held
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(path) = &self.file else {
            return Ok(held);
        };
        let now = stamp(path)?;
        if held.stamp == Some(now) {
            return Ok(held);
        }
        let (lists, stamp) = read(path)?;
        let mut kept = self.held.write().unwrap_or_else(PoisonError::into_inner);
        if kept.stamp != Some(stamp) {
            kept.lists = lists.into();
            kept.stamp = Some(stamp);
            kept.generation += 1;
        }
        Ok(kept.clone())
    }
}

/// The lists the file at `path` holds, and how it looked before it was read:
/// a change while it is read is read again at the next handshake.
fn read(path: &Path) -> Result<(Vec<CertificateRevocationListDer<'static>>, Stamp)> {
    let before = stamp(path)?;
    let bytes = std::fs::read(path).map_err(|failure| {
        TlsError::new(format!(
            "reading the revocation list {}: {failure}",
            path.display()
        ))
    })?;
    Ok((lists(&bytes, &path.display().to_string())?, before))
}

fn stamp(path: &Path) -> Result<Stamp> {
    let found = std::fs::metadata(path).and_then(|meta| Ok((meta.modified()?, meta.len())));
    found.map_err(|failure| {
        TlsError::new(format!("the revocation list {}: {failure}", path.display()))
    })
}

/// Every list `bytes` holds, PEM or one DER; `what` names it in a refusal.
fn lists(bytes: &[u8], what: &str) -> Result<Vec<CertificateRevocationListDer<'static>>> {
    if !bytes.trim_ascii_start().starts_with(b"-----BEGIN") {
        if bytes.is_empty() {
            return Err(TlsError::new(format!("{what} held no list")));
        }
        return Ok(vec![CertificateRevocationListDer::from(bytes.to_vec())]);
    }
    let found = CertificateRevocationListDer::pem_slice_iter(bytes)
        .collect::<core::result::Result<Vec<_>, _>>()
        .map_err(|failure| TlsError::new(format!("reading {what}: {failure}")))?;
    if found.is_empty() {
        return Err(TlsError::new(format!("{what} held no X509 CRL block")));
    }
    Ok(found)
}

/// The client verifier a server of `anchors` builds from `provider`:
/// `asking`, a client may present no certificate; with `revocation`, one
/// presented is refused where a list held revokes it.
///
/// # Errors
///
/// Where the anchors are empty, or a list does not read.
pub(crate) fn verifier(
    anchors: &Arc<RootCertStore>,
    provider: &Arc<CryptoProvider>,
    asking: bool,
    revocation: Option<&Arc<Revocation>>,
) -> Result<Arc<dyn ClientCertVerifier>> {
    let Some(revocation) = revocation else {
        return built(anchors, provider, asking, None);
    };
    let held = revocation.current()?;
    let inner = built(anchors, provider, asking, Some((revocation, &held)))?;
    Ok(Arc::new(Revoking {
        anchors: Arc::clone(anchors),
        provider: Arc::clone(provider),
        asking,
        revocation: Arc::clone(revocation),
        hints: inner.root_hint_subjects().to_vec(),
        built: RwLock::new((held.generation, inner)),
    }))
}

/// The webpki verifier, with the lists where given.
fn built(
    anchors: &Arc<RootCertStore>,
    provider: &Arc<CryptoProvider>,
    asking: bool,
    revoking: Option<(&Revocation, &Held)>,
) -> Result<Arc<dyn ClientCertVerifier>> {
    let mut builder =
        WebPkiClientVerifier::builder_with_provider(Arc::clone(anchors), Arc::clone(provider));
    if let Some((revocation, held)) = revoking {
        builder = builder.with_crls(held.lists.iter().cloned());
        if !revocation.accepting_expired {
            builder = builder.enforce_revocation_expiration();
        }
    }
    if asking {
        builder = builder.allow_unauthenticated();
    }
    builder
        .build()
        .map_err(|failure| TlsError::new(format!("the client verifier: {failure}")))
}

/// A client verifier over lists that may change: rebuilt the first
/// handshake after they did.
struct Revoking {
    anchors: Arc<RootCertStore>,
    provider: Arc<CryptoProvider>,
    asking: bool,
    revocation: Arc<Revocation>,
    hints: Vec<DistinguishedName>,
    built: RwLock<(u64, Arc<dyn ClientCertVerifier>)>,
}

impl fmt::Debug for Revoking {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Revoking")
            .field("asking", &self.asking)
            .field("revocation", &self.revocation)
            .finish_non_exhaustive()
    }
}

impl Revoking {
    /// The verifier as it was last built, whatever the lists did since.
    fn last(&self) -> Arc<dyn ClientCertVerifier> {
        let built = self.built.read().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(&built.1)
    }

    /// The verifier over the lists as they stand, rebuilt where they moved.
    fn current(&self) -> core::result::Result<Arc<dyn ClientCertVerifier>, rustls::Error> {
        let refused = |failure: TlsError| rustls::Error::General(failure.message);
        let held = self.revocation.current().map_err(refused)?;
        {
            let built = self.built.read().unwrap_or_else(PoisonError::into_inner);
            if built.0 == held.generation {
                return Ok(Arc::clone(&built.1));
            }
        }
        let revoking = Some((&*self.revocation, &held));
        let inner = built(&self.anchors, &self.provider, self.asking, revoking).map_err(refused)?;
        let mut built = self.built.write().unwrap_or_else(PoisonError::into_inner);
        *built = (held.generation, Arc::clone(&inner));
        Ok(inner)
    }
}

impl ClientCertVerifier for Revoking {
    fn client_auth_mandatory(&self) -> bool {
        !self.asking
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> core::result::Result<ClientCertVerified, rustls::Error> {
        self.current()?
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.last().verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.last().verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.last().supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests;
