#![forbid(unsafe_code)]

//! TLS for every transport that needs it: a connection wrapped as a client,
//! one served as a server, and one upgraded in place where a protocol
//! negotiates first.
//!
//! **The key exchange is hybrid, first of all.** X25519MLKEM768 — X25519 and
//! ML-KEM-768 (FIPS 203) together, as the IETF's hybrid design for TLS 1.3
//! names it — so a session is as safe as the stronger of the two: a flaw in
//! the young lattice scheme still leaves X25519, and a recording kept for a
//! quantum computer still faces ML-KEM. A peer that knows only classical
//! groups is served with X25519, so nothing that connects today stops
//! connecting, and [`Guarded::key_exchange`] says which was agreed.
//! ADR-0033, amended 2026-09-22.
//!
//! **Where this lives and why.** TLS was inside `xmip-core-transport-http`
//! until 2026-09-23, so the transports that ride on HTTP could reach it and
//! the twenty that do not — SMTP and IMAP with STARTTLS, MQTT, AMQP, Kafka,
//! the databases, syslog — could not; four of them mapped their `https` URLs
//! to a stack they had no way to load. It is a Foundation repository of its
//! own, on the owner's decision of 2026-09-22.
//!
//! **The protocol inside, agreed in the handshake.** A client offers the
//! application protocols it speaks and the server selects one ([`alpn`],
//! RFC 7301); HTTP agrees HTTP/2 or HTTP/1.1 this way. Which identifiers to
//! offer is the protocol's.
//!
//! **What stays with the protocol.** When to upgrade, what to send before the
//! handshake, which port is implicitly guarded: that is each protocol's, and
//! nothing here knows it.

pub mod alpn;
mod client;
mod server;

pub use client::{Guarded, client, client_offering, client_with, configure};
pub use server::{GuardedServer, server, server_config};

use std::sync::Arc;

/// The key exchange groups offered and accepted, in order of preference: the
/// hybrid first, then the classical groups every TLS 1.3 peer has.
const KEY_EXCHANGE: [&dyn rustls::crypto::SupportedKxGroup; 4] = [
    rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
    rustls::crypto::aws_lc_rs::kx_group::X25519,
    rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
    rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
];

/// The one cryptographic provider both sides build from, so a client and a
/// server of this node offer the same groups in the same order. Listed
/// explicitly rather than taken from the provider's default, so a change of
/// rustls's preference cannot quietly change Xmip's.
#[must_use]
pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::CryptoProvider {
        kx_groups: KEY_EXCHANGE.to_vec(),
        ..rustls::crypto::aws_lc_rs::default_provider()
    })
}

/// Why a connection could not be guarded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsError {
    /// What was wrong, in words.
    pub message: String,
}

impl TlsError {
    /// A failure saying `message`.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl core::fmt::Display for TlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl core::error::Error for TlsError {}

/// The result of guarding a connection.
pub type Result<T> = core::result::Result<T, TlsError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hybrid_is_offered_first_and_the_classical_groups_follow() {
        let groups: Vec<rustls::NamedGroup> =
            provider().kx_groups.iter().map(|g| g.name()).collect();

        assert_eq!(groups[0], rustls::NamedGroup::X25519MLKEM768);
        assert!(groups.contains(&rustls::NamedGroup::X25519), "{groups:?}");
        assert_eq!(groups.len(), 4);
    }
}
