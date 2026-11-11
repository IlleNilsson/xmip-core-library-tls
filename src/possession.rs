//! A browser's possession of its key, proven to a node that did not serve
//! its TLS (ADR-0009, amendment 2026-11-02).
//!
//! A web host takes its browsers' TLS and relays their callers to the
//! nodes, which decide. A certificate alone proves nothing a host could not
//! replay, so the proof is the handshake itself: the host binds every
//! node's fresh nonce into the random its server sends ([`binding`]),
//! records the handshake ([`handshaken`], over [`proving`]'s configuration),
//! recovers its transcript ([`Recorded::transcript`]) and hands each node
//! the transcript, and the node checks that the client's
//! `CertificateVerify` signs it with its certificate's key ([`proved`]) —
//! so the holder of that key made this handshake after the node's nonce
//! was issued, to the server whose certificate the transcript names. TLS
//! 1.3 and 1.2 are both held; a resumed session carries no
//! `CertificateVerify` and proves nothing, and a proving server, as every
//! configuration of this library, resumes none.
//! The handshake secrets TLS 1.3 needs to read its own transcript stay in
//! this module, for one handshake, and are zeroed after.

mod bound;
mod message;
mod proved;
mod recorded;
mod transcript;

pub use bound::{BINDING, binding};
pub use proved::{Proved, proved};
pub use recorded::{Recorded, handshaken, proving};

#[cfg(test)]
mod tests;
