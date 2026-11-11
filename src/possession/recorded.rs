//! A browser's handshake served, bound and recorded (ADR-0009, amendment
//! 2026-11-02): the one server configuration that proves possession, and
//! the handshake made over it on a thread of its own — its random bound to
//! the nodes' nonces, both directions' bytes copied as the socket carries
//! them, and the TLS 1.3 handshake traffic secrets kept for that one
//! handshake's transcript and zeroed after. The secrets are never written,
//! logged or kept on the session; the key log that receives them is this
//! module's alone and in no other configuration.

use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use super::bound::{self, BINDING};
use super::transcript::{Secrets, recovered};
use crate::peer::{Unanswered, completed};
use crate::{GuardedServer, Identity, Result, TlsError};

/// The most a handshake's bytes are recorded to, each way: far more than a
/// handshake with a chain of certificates sends.
const MOST: usize = 256 * 1024;

thread_local! {
    static SECRETS: RefCell<Option<Secrets>> = const { RefCell::new(None) };
}

/// The key log of a proving server: on the thread a handshake is recorded
/// on, the two handshake traffic secrets, and nothing else.
#[derive(Debug)]
struct Kept;

const CLIENT: &str = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
const SERVER: &str = "SERVER_HANDSHAKE_TRAFFIC_SECRET";

impl rustls::KeyLog for Kept {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        SECRETS.with_borrow_mut(|kept| {
            let Some(kept) = kept.as_mut() else {
                return;
            };
            match label {
                CLIENT => *kept.client = secret.to_vec(),
                SERVER => *kept.server = secret.to_vec(),
                _ => {}
            }
        });
    }

    fn will_log(&self, label: &str) -> bool {
        label == CLIENT || label == SERVER
    }
}

/// The server a browser proves possession to: `identity` presented, a
/// client's certificate asked for and checked against its anchors, one that
/// presents none let through as no one ([`Identity::server_asking`]), its
/// random bound (`bound`), and its handshake secrets kept for the
/// transcript. A resumed session proves nothing; as no configuration of
/// this library resumes one (`configuration`), every handshake is a full
/// one.
///
/// # Errors
///
/// Where the anchors are empty.
pub fn proving(identity: &Identity) -> Result<rustls::ServerConfig> {
    let mut config = identity.served_by(true, bound::provider())?;
    config.key_log = Arc::new(Kept);
    Ok(config)
}

/// The socket, every byte it carries copied, up to [`MOST`] each way.
struct Recording<'a> {
    socket: &'a mut TcpStream,
    read: Vec<u8>,
    written: Vec<u8>,
}

impl Read for Recording<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.socket.read(buf)?;
        if self.read.len() + read <= MOST {
            self.read.extend_from_slice(&buf[..read]);
        }
        Ok(read)
    }
}

impl Write for Recording<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.socket.write(buf)?;
        if self.written.len() + written <= MOST {
            self.written.extend_from_slice(&buf[..written]);
        }
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.socket.flush()
    }
}

/// One handshake recorded: both directions' bytes as the socket carried
/// them and, for TLS 1.3, its handshake traffic secrets, zeroed when this
/// is dropped. Its transcript is recovered by whoever holds it
/// ([`Recorded::transcript`]), apart from the handshake, so a host can
/// count what possession costs it beside what TLS does.
pub struct Recorded {
    read: Vec<u8>,
    written: Vec<u8>,
    secrets: Secrets,
}

impl Recorded {
    /// The transcript a node checks ([`super::proved`]), the secrets
    /// zeroed as this returns.
    ///
    /// # Errors
    ///
    /// Why there is none: no certificate presented, or a handshake that
    /// does not read.
    pub fn transcript(self) -> Result<Vec<u8>> {
        recovered(&self.read, &self.written, &self.secrets)
    }
}

/// One handshake on this thread: its random armed and its secrets kept
/// while this lives. Dropped — ended, or unwinding from a panic in the
/// handshake — the thread is disarmed and the secrets it kept are taken
/// and zeroed, so nothing of one handshake reaches the next on the thread.
struct Handshaking {
    _armed: bound::Armed,
}

impl Handshaking {
    fn begin(binding: [u8; BINDING]) -> Self {
        SECRETS.set(Some(Secrets::default()));
        Self {
            _armed: bound::Armed::arm(binding),
        }
    }

    /// The secrets kept, zeroed when the record holding them is dropped;
    /// the thread disarmed as this returns.
    fn end(self) -> Secrets {
        let secrets = SECRETS.take().unwrap_or_default();
        drop(self);
        secrets
    }
}

impl Drop for Handshaking {
    fn drop(&mut self) {
        drop(SECRETS.take());
    }
}

/// Whether this thread holds a handshake's secrets or an armed random.
#[cfg(test)]
pub(super) fn armed() -> bool {
    SECRETS.with_borrow(Option::is_some) || bound::armed()
}

/// Serve `tcp` over `config` ([`proving`]) and finish its handshake, its
/// random bound to `binding`: the session, and the handshake recorded.
///
/// # Errors
///
/// Where the handshake did not finish, by kind.
pub fn handshaken(
    mut tcp: TcpStream,
    config: Arc<rustls::ServerConfig>,
    binding: [u8; BINDING],
) -> core::result::Result<(GuardedServer, Recorded), Unanswered> {
    let mut connection = rustls::ServerConnection::new(config).map_err(|failure| {
        Unanswered::Failed(TlsError::new(format!(
            "starting the server tls session: {failure}"
        )))
    })?;
    let handshaking = Handshaking::begin(binding);
    let mut recording = Recording {
        socket: &mut tcp,
        read: Vec::new(),
        written: Vec::new(),
    };
    let done = completed(&mut connection, &mut recording);
    let Recording { read, written, .. } = recording;
    let secrets = handshaking.end();
    done?;
    let recorded = Recorded {
        read,
        written,
        secrets,
    };
    Ok((rustls::StreamOwned::new(connection, tcp), recorded))
}
