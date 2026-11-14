//! The node's freshness, bound into the `ServerHello`'s random (ADR-0009,
//! amendment 2026-11-02): the host's runtime takes a nonce from every node
//! it relays to before it answers a browser, and the first 24 bytes of the
//! random its server sends are [`binding`] of them. The browser's
//! `CertificateVerify` signs a transcript holding that random, so a node that
//! finds its own nonce bound there knows the browser held its key in a
//! handshake made after the node issued the nonce.
//!
//! rustls draws the random from its provider's random source and offers no
//! other way in, so the provider here is the general one with one change: a
//! source that, on a thread a handshake was armed on ([`Armed`]), writes the
//! binding into every draw of a random's size, 32 bytes, until it is
//! disarmed — the `ServerHello`'s random among them, whichever it is: in
//! rustls 0.23.46, the version `Cargo.toml` pins for this, a retried
//! handshake draws one for the `HelloRetryRequest` and another for the
//! `ServerHello`; TLS 1.2 draws no session ID, as no server of this library
//! stores a session (`configuration`). Every other draw is the operating
//! system's. The last 8 bytes stay random: rustls writes TLS 1.2's
//! downgrade sentinel there (RFC 8446 section 4.1.3). A test of recorded
//! handshakes holds this for 1.3, 1.3 retried and 1.2; where a later
//! rustls draws otherwise, the node finds no binding and refuses relay in
//! words. The arming is a guard dropped on every way out, a panic's unwind
//! included.

use std::cell::Cell;
use std::sync::{Arc, LazyLock};

use rustls::crypto::{CryptoProvider, GetRandomFailed, SecureRandom};

/// How many bytes of the random the binding takes.
pub const BINDING: usize = 24;

thread_local! {
    static ARMED: Cell<Option<[u8; BINDING]>> = const { Cell::new(None) };
}

/// The random source that writes an armed binding into every draw of a
/// random's size.
#[derive(Debug)]
struct Bound;

impl SecureRandom for Bound {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        crate::provider().secure_random.fill(buf)?;
        if buf.len() == 32
            && let Some(binding) = ARMED.get()
        {
            buf[..BINDING].copy_from_slice(&binding);
        }
        Ok(())
    }
}

static BOUND: Bound = Bound;

/// The provider a proving server is built from: the general one, its
/// random source [`Bound`].
pub(crate) fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: LazyLock<Arc<CryptoProvider>> = LazyLock::new(|| {
        Arc::new(CryptoProvider {
            secure_random: &BOUND,
            ..(*crate::provider()).clone()
        })
    });
    Arc::clone(&PROVIDER)
}

/// What `nonces` bind the random to: SHA-256 over each, its length before
/// it, in the order given, its first [`BINDING`] bytes. The node answers the
/// same of the list it is handed, and finds its own nonce in it.
#[must_use]
pub fn binding(nonces: &[&[u8]]) -> [u8; BINDING] {
    let mut digest = codec::digest::Sha256::new();
    for nonce in nonces {
        let length = u16::try_from(nonce.len()).unwrap_or(u16::MAX);
        digest.update(&length.to_be_bytes());
        digest.update(nonce);
    }
    let mut bound = [0u8; BINDING];
    bound.copy_from_slice(&digest.finish()[..BINDING]);
    bound
}

/// This thread armed with a binding, for the handshake it is about to
/// make, and disarmed when this is dropped — the handshake done, failed or
/// unwinding from a panic — so a binding never reaches a draw meant for
/// something else.
#[must_use = "the thread is disarmed when this is dropped"]
pub(crate) struct Armed(());

impl Armed {
    /// Arm this thread's randoms with `binding`.
    pub(crate) fn arm(binding: [u8; BINDING]) -> Self {
        ARMED.set(Some(binding));
        Self(())
    }
}

impl Drop for Armed {
    fn drop(&mut self) {
        ARMED.set(None);
    }
}

/// Whether this thread is armed.
#[cfg(test)]
pub(super) fn armed() -> bool {
    ARMED.get().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_armed_thread_binds_its_randoms_until_disarmed_and_nothing_else() {
        let bound = binding(&[b"first", b"second"]);
        assert_ne!(bound, binding(&[b"second", b"first"]), "the order is bound");
        let armed = Armed::arm(bound);
        let mut short = [0u8; 16];
        BOUND.fill(&mut short).expect("drawn");
        assert_ne!(
            short[..],
            bound[..16],
            "a draw of another size is the system's"
        );
        let (mut random, mut again) = ([0u8; 32], [0u8; 32]);
        BOUND.fill(&mut random).expect("drawn");
        BOUND.fill(&mut again).expect("drawn");
        assert_eq!(random[..BINDING], bound);
        assert_eq!(again[..BINDING], bound);
        assert_ne!(random[BINDING..], again[BINDING..], "the rest is random");
        drop(armed);
        BOUND.fill(&mut again).expect("drawn");
        assert_ne!(again[..BINDING], bound, "disarmed");
    }

    #[test]
    fn a_panic_while_armed_leaves_the_thread_disarmed() {
        let bound = binding(&[b"a nonce"]);
        let unwound = std::panic::catch_unwind(|| {
            let _armed = Armed::arm(bound);
            panic!("a handshake that panics");
        });
        assert!(unwound.is_err());
        let mut random = [0u8; 32];
        BOUND.fill(&mut random).expect("drawn");
        assert_ne!(random[..BINDING], bound, "disarmed by the unwind");
    }
}
