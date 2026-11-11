//! Every configuration this library builds, server and client, built here
//! once: from one cryptographic provider ([`crate::provider`], or the
//! proving one of `possession`), TLS 1.3 and 1.2, and no session resumed
//! but within one login ([`login`]).
//!
//! **No session is resumed.** rustls resumes a session without calling the
//! verifier: a resumed TLS 1.3 handshake asks the client for no
//! certificate and copies the chain the session stored onto the connection
//! (rustls 0.23.46, `server/tls13.rs`), and a client resuming does not look
//! at the server's certificate again either. So a client admitted once was
//! admitted again after its authority revoked it, its certificate expired
//! or its anchor was taken away, for as long as it kept resuming. A server
//! here stores no session and sends no ticket, a client keeps none to
//! offer, and every handshake verifies the peer's certificate as it stands
//! — what taking trust back depends on (ADR-0033, amendment 2026-11-10).
//! A client still keeps the key exchange group each server chose
//! ([`Hinted`]), so a server that takes none of the groups offered first
//! asks again with a `HelloRetryRequest` once, not on every connection.
//! The price is a full handshake on every connection — the certificates'
//! signatures and their checks, and for a TLS 1.2 peer a second round trip
//! — paid once per connection and never by what is sent on one already
//! open. Until 2026-11-10 rustls's defaults stood everywhere but
//! `possession`.
//!
//! **One login resumes its own session.** FTPS (RFC 4217) opens a data
//! connection beside its control connection for every transfer, and a
//! server may refuse a data connection that does not resume the control
//! connection's session (vsftpd's `require_ssl_reuse`, on by default).
//! [`login`] gives one login a store of its own: its control connection's
//! handshake is full and checks the server's certificate, and only the data
//! connections of that login resume it, while the control connection they
//! belong to is open and checked no more than they are. No other login and
//! no other connection sees that store.

use std::sync::Arc;

use rustls::NamedGroup;
use rustls::client::{
    ClientSessionMemoryCache, ClientSessionStore, Resumption, Tls12ClientSessionValue,
    Tls12Resumption, Tls13ClientSessionValue,
};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls::server::danger::ClientCertVerifier;
use rustls::sign::{CertifiedKey, SingleCertAndKey};

use crate::provider;

/// How much a client's store of key exchange groups holds, in rustls's
/// count of eight tickets a server: the groups of 256 servers.
const HINTED: usize = 256 * 8;

/// How much one login's store holds, in the same count: the one server
/// its control connection reached.
const LOGIN: usize = 1;

/// A server built from `provider`, presenting `presented` and verifying a
/// client by `verifier`: it stores no session and sends no ticket.
pub(crate) fn server(
    provider: Arc<CryptoProvider>,
    verifier: Arc<dyn ClientCertVerifier>,
    presented: Arc<CertifiedKey>,
) -> rustls::ServerConfig {
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .unwrap_or_else(|_| unreachable!("the default versions are always supported"))
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(presented)));
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config
}

/// A client checking a server against `roots` and, where it has one,
/// presenting `presented` when asked: it keeps no session to resume, only
/// the group each server chose ([`Hinted`]).
pub(crate) fn client(
    roots: impl Into<Arc<rustls::RootCertStore>>,
    presented: Option<Arc<CertifiedKey>>,
) -> rustls::ClientConfig {
    let trusting = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .unwrap_or_else(|_| unreachable!("the default versions are always supported"))
        .with_root_certificates(roots);
    let mut config = match presented {
        Some(presented) => {
            trusting.with_client_cert_resolver(Arc::new(SingleCertAndKey::from(presented)))
        }
        None => trusting.with_no_client_auth(),
    };
    config.resumption = Resumption::store(Arc::new(Hinted(ClientSessionMemoryCache::new(HINTED))))
        .tls12_resumption(Tls12Resumption::Disabled);
    config
}

/// `config`, for one login alone: the same trust and the same offer, with
/// a session store of its own, so the data connections of the login
/// resume its control connection's session and nothing else does.
pub(crate) fn login(config: &rustls::ClientConfig) -> rustls::ClientConfig {
    let mut login = config.clone();
    login.resumption = Resumption::in_memory_sessions(LOGIN);
    login
}

/// A client's store that keeps no session, only the key exchange group
/// each server chose — rustls's own cache, asked for that alone.
#[derive(Debug)]
struct Hinted(ClientSessionMemoryCache);

impl ClientSessionStore for Hinted {
    fn set_kx_hint(&self, server: ServerName<'static>, group: NamedGroup) {
        self.0.set_kx_hint(server, group);
    }

    fn kx_hint(&self, server: &ServerName<'_>) -> Option<NamedGroup> {
        self.0.kx_hint(server)
    }

    fn set_tls12_session(&self, _: ServerName<'static>, _: Tls12ClientSessionValue) {}

    fn tls12_session(&self, _: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        None
    }

    fn remove_tls12_session(&self, _: &ServerName<'static>) {}

    fn insert_tls13_ticket(&self, _: ServerName<'static>, _: Tls13ClientSessionValue) {}

    fn take_tls13_ticket(&self, _: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::fixture::handshakes;

    const FULL: Option<rustls::HandshakeKind> = Some(rustls::HandshakeKind::Full);
    const RESUMED: Option<rustls::HandshakeKind> = Some(rustls::HandshakeKind::Resumed);

    /// A certificate for `localhost`, the client's roots trusting it, and
    /// the certificate with its key, as `provider` loads them.
    fn signed(provider: &CryptoProvider) -> (rustls::RootCertStore, Arc<CertifiedKey>) {
        let signed = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("a certificate");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(signed.cert.der().clone()).expect("trusted");
        let presented = crate::pem::certified(
            signed.cert.pem().as_bytes(),
            signed.signing_key.serialize_pem().as_bytes(),
            provider,
        )
        .expect("a certificate and key");
        (roots, Arc::new(presented))
    }

    #[test]
    fn a_login_resumes_its_own_session_and_no_other_login_or_client_does() {
        let (roots, presented) = signed(&provider());
        // A server of rustls's defaults, as one insisting on reuse keeps
        // them: a session cache, and tickets sent.
        let resuming = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .expect("versions")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(presented)));
        let resuming = Arc::new(resuming);
        let kept = client(roots, None);
        let one = Arc::new(login(&kept));

        // The control connection in full, each data connection resumed:
        // what a server refusing a data connection that does not resume
        // checks.
        assert_eq!(handshakes(&one, &resuming, 3), [FULL, RESUMED, RESUMED]);
        let other = Arc::new(login(&kept));
        assert_eq!(handshakes(&other, &resuming, 1), [FULL], "another login");
        assert_eq!(handshakes(&Arc::new(kept), &resuming, 1), [FULL]);
    }

    #[test]
    fn a_kept_client_asks_a_server_again_for_its_group_once_not_at_every_connection() {
        // A server that takes P-256 alone, as one limited to the groups a
        // FIPS mode allows: neither the hybrid nor X25519 offered first.
        let only = Arc::new(CryptoProvider {
            kx_groups: vec![rustls::crypto::aws_lc_rs::kx_group::SECP256R1],
            ..rustls::crypto::aws_lc_rs::default_provider()
        });
        let (roots, presented) = signed(&only);
        let limited = server(only, Arc::new(rustls::server::NoClientAuth), presented);
        let kept = Arc::new(client(roots, None));

        let retried = Some(rustls::HandshakeKind::FullWithHelloRetryRequest);
        assert_eq!(handshakes(&kept, &Arc::new(limited), 2), [retried, FULL]);
    }

    /// The code of every source file of the library under `folder` but
    /// this one, before its first `#[cfg(test)]`, and every test file left
    /// out: what a production build compiles.
    fn production(folder: &Path, found: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(folder).expect("the source folder") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                production(&path, found);
                continue;
            }
            let rust = path.extension().is_some_and(|extension| extension == "rs");
            let name = path.file_name().and_then(|name| name.to_str());
            if !rust || matches!(name, Some("configuration.rs" | "tests.rs")) {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("a source file");
            let code = text
                .split("\n#[cfg(test)]")
                .next()
                .unwrap_or_default()
                .to_string();
            found.push((path.display().to_string(), code));
        }
    }

    #[test]
    fn no_other_file_of_the_library_builds_a_configuration_or_sets_its_resumption() {
        let mut files = Vec::new();
        production(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut files,
        );
        assert!(files.len() > 10, "the library's files were read: {files:?}");
        let built: Vec<_> = files
            .iter()
            .flat_map(|(file, code)| {
                [
                    "Config::builder",
                    ".resumption",
                    ".session_storage",
                    ".send_tls13_tickets",
                ]
                .into_iter()
                .filter(|said| code.contains(said))
                .map(move |said| format!("{file}: {said}"))
            })
            .collect();
        assert!(built.is_empty(), "built outside `configuration`: {built:?}");
    }
}
