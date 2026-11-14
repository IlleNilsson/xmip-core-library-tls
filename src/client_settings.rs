//! What a client checks a server by: the trust store its certificate is
//! checked against, and the name it is checked for.
//!
//! The one pair every client with an optional trust store holds — a
//! database's login, FTPS's control and data connections, DRDA, a
//! directory's bind, an authorization server's introspection, an ACME
//! server. Until 2026-11-13 the `MariaDB` library, DB2 and FTP each declared
//! it, and LDAP, OAuth 2.0 and ACME kept its trust store alone.

use std::net::TcpStream;
use std::sync::Arc;

use crate::{Guarded, Result, client};

/// The trust a server's certificate is checked against, and the name it
/// must carry.
#[derive(Clone, Debug, Default)]
pub struct ClientSettings {
    /// The name the certificate must carry; the host reached where `None`.
    name: Option<String>,
    /// The trust a caller holds — a Party's own authority, a directory's,
    /// a test's; the operating system's store where `None`.
    trust: Option<Arc<rustls::ClientConfig>>,
}

impl ClientSettings {
    /// Checked against the operating system's trust store, for the host
    /// reached.
    #[must_use]
    pub const fn native() -> Self {
        Self {
            name: None,
            trust: None,
        }
    }

    /// Checked against the trust `config` holds.
    #[must_use]
    pub fn trusting(config: Arc<rustls::ClientConfig>) -> Self {
        Self {
            name: None,
            trust: Some(config),
        }
    }

    /// Checked for `name` rather than the host reached.
    #[must_use]
    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// The name the certificate must carry, where one is given.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The trust store given, where one is.
    #[must_use]
    pub const fn trust(&self) -> Option<&Arc<rustls::ClientConfig>> {
        self.trust.as_ref()
    }

    /// `tcp`, a connection to `host`, wrapped in TLS and its handshake
    /// begun: checked for these settings' name where they give one and for
    /// `host` where they do not, against their trust store where they give
    /// one and the operating system's where they do not. The same call
    /// serves STARTTLS, on a socket that spoke in the clear first.
    ///
    /// # Errors
    ///
    /// Where the operating system's trust store is empty or unreadable, the
    /// name is not one TLS can use, or the handshake could not be started.
    pub fn client(&self, host: &str, tcp: TcpStream) -> Result<Guarded> {
        let name = self.name.as_deref().unwrap_or(host);
        client::client_with(name, tcp, client::trusted(self.trust.as_ref())?)
    }

    /// These settings for one login — a control connection and the data
    /// connections opened beside it, as FTPS's (RFC 4217): the same name
    /// and trust, over a client configuration of the login's own, so its
    /// connections resume its first session and no other connection does.
    /// Built as the login starts and dropped with it.
    ///
    /// # Errors
    ///
    /// With no trust store given, where the operating system's is empty or
    /// unreadable.
    pub fn login(&self) -> Result<Self> {
        Ok(Self {
            name: self.name.clone(),
            trust: Some(client::login(self.trust.as_ref())?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_login_keeps_the_name_and_trusts_through_a_configuration_of_its_own() {
        let mut roots = rustls::RootCertStore::empty();
        let signed = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("a certificate");
        roots.add(signed.cert.der().clone()).expect("trusted");
        let shared = Arc::new(crate::configure(roots));
        let settings = ClientSettings::trusting(Arc::clone(&shared)).named("localhost");
        let first = settings.login().expect("a login");
        let second = settings.login().expect("a login");
        let held = |one: &ClientSettings| Arc::clone(one.trust().expect("trust"));

        assert!(!Arc::ptr_eq(&held(&first), &shared), "not the shared one");
        assert!(!Arc::ptr_eq(&held(&first), &held(&second)), "one a login");
        assert_eq!(first.name(), Some("localhost"));
        assert_eq!(ClientSettings::native().name(), None);
        assert!(ClientSettings::native().trust().is_none());
    }
}
