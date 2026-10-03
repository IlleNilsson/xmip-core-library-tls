//! One TLS connection read on one thread and written on another, each
//! side waiting only for its own direction.
//!
//! A [`rustls::StreamOwned`] reads and writes through one value, so a
//! thread blocked reading holds the connection and another cannot write
//! until a byte arrives. A protocol that both streams to its peer and
//! listens for it — the Event link between nodes — needs the two apart.
//! [`split`] finishes the handshake and gives a [`Reading`] and a
//! [`Writing`] over the same session: the reading side waits on the socket
//! holding nothing, and takes the session only to decrypt what came; the
//! writing side takes it to encrypt and send. Neither waits for the other
//! except for the microseconds the session is held.
//!
//! A read timeout set on the socket reaches the [`Reading`] side as
//! [`std::io::ErrorKind::WouldBlock`] or `TimedOut`, with nothing of a
//! record lost: what came before it is kept for the next read.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex, PoisonError};

use crate::Result;

/// How much is read off the socket at once.
const CHUNK: usize = 16 * 1024;

/// The session both sides share, and the socket under it.
struct Shared<C> {
    session: Mutex<C>,
    socket: TcpStream,
}

/// The reading side of a split connection.
pub struct Reading<C> {
    shared: Arc<Shared<C>>,
    /// Bytes read off the socket that the session has not taken yet.
    pending: Vec<u8>,
    taken: usize,
}

/// The writing side of a split connection.
pub struct Writing<C> {
    shared: Arc<Shared<C>>,
}

/// A connection split in two, and the protocol it agreed by ALPN, if any.
pub struct Split<C> {
    pub agreed: Option<Vec<u8>>,
    pub reading: Reading<C>,
    pub writing: Writing<C>,
}

/// Finish `stream`'s handshake and split it.
///
/// # Errors
///
/// Where the handshake fails, or the socket cannot be shared.
pub fn split<C, D>(mut stream: rustls::StreamOwned<C, TcpStream>) -> Result<Split<C>>
where
    C: Deref<Target = rustls::ConnectionCommon<D>> + DerefMut,
    D: rustls::SideData,
{
    let agreed = crate::alpn::agreed(&mut stream)?;
    let rustls::StreamOwned { conn, sock } = stream;
    let shared = Arc::new(Shared {
        session: Mutex::new(conn),
        socket: sock,
    });
    let reading = Reading {
        shared: Arc::clone(&shared),
        pending: Vec::new(),
        taken: 0,
    };
    Ok(Split {
        agreed,
        reading,
        writing: Writing { shared },
    })
}

impl<C> Reading<C> {
    /// The socket under the connection: its timeouts are set here.
    #[must_use]
    pub fn socket(&self) -> &TcpStream {
        &self.shared.socket
    }
}

impl<C> Writing<C> {
    /// The socket under the connection.
    #[must_use]
    pub fn socket(&self) -> &TcpStream {
        &self.shared.socket
    }
}

impl<C, D> Read for Reading<C>
where
    C: Deref<Target = rustls::ConnectionCommon<D>> + DerefMut,
    D: rustls::SideData,
{
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        loop {
            {
                let mut session = self.shared.lock();
                let mut refused = None;
                if self.taken < self.pending.len() {
                    let mut rest = &self.pending[self.taken..];
                    let before = rest.len();
                    // Refused only while what was decrypted waits to be read.
                    refused = session.read_tls(&mut rest).err();
                    self.taken += before - rest.len();
                    session
                        .process_new_packets()
                        .map_err(|failure| std::io::Error::new(ErrorKind::InvalidData, failure))?;
                    flush(&mut *session, &self.shared.socket)?;
                }
                match session.reader().read(buffer) {
                    Err(failed) if failed.kind() == ErrorKind::WouldBlock => {}
                    read => return read,
                }
                if let Some(refused) = refused {
                    return Err(refused);
                }
                if self.taken < self.pending.len() {
                    continue;
                }
            }
            self.pending.resize(CHUNK, 0);
            self.taken = 0;
            let came = (&self.shared.socket).read(&mut self.pending);
            let came = came.inspect_err(|_| self.pending.clear())?;
            self.pending.truncate(came);
            if came == 0 {
                // The peer closed: the session says whether it said so first.
                let mut session = self.shared.lock();
                session.read_tls(&mut &[][..])?;
                return session.reader().read(buffer);
            }
        }
    }
}

impl<C, D> Write for Writing<C>
where
    C: Deref<Target = rustls::ConnectionCommon<D>> + DerefMut,
    D: rustls::SideData,
{
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut session = self.shared.lock();
        let written = session.writer().write(bytes)?;
        flush(&mut *session, &self.shared.socket)?;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut session = self.shared.lock();
        session.writer().flush()?;
        flush(&mut *session, &self.shared.socket)
    }
}

impl<C, D> Writing<C>
where
    C: Deref<Target = rustls::ConnectionCommon<D>> + DerefMut,
    D: rustls::SideData,
{
    /// Say the connection is closing, and close the socket both ways: the
    /// peer reads its end, and this side's [`Reading`] wakes to it.
    pub fn close(&mut self) {
        {
            let mut session = self.shared.lock();
            session.send_close_notify();
            let _ = flush(&mut *session, &self.shared.socket);
        }
        let _ = self.shared.socket.shutdown(std::net::Shutdown::Both);
    }
}

impl<C> Shared<C> {
    fn lock(&self) -> std::sync::MutexGuard<'_, C> {
        self.session.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Send whatever the session has to send.
fn flush<C, D>(session: &mut C, socket: &TcpStream) -> std::io::Result<()>
where
    C: Deref<Target = rustls::ConnectionCommon<D>> + DerefMut,
    D: rustls::SideData,
{
    let mut socket = socket;
    while session.wants_write() {
        session.write_tls(&mut socket)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::{client_with, configure, server, server_config};

    /// One side of a split connection.
    type Sides<C> = (Reading<C>, Writing<C>);

    /// A client and a server, split, over loopback.
    fn pair() -> (
        Sides<rustls::ClientConnection>,
        Sides<rustls::ServerConnection>,
    ) {
        let signed = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("a certificate");
        let config = server_config(
            signed.cert.pem().as_bytes(),
            signed.key_pair.serialize_pem().as_bytes(),
        )
        .expect("server config");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(signed.cert.der().clone()).expect("trusted");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bound");
        let address = listener.local_addr().expect("address");

        let near = std::thread::spawn(move || {
            let tcp = TcpStream::connect(address).expect("connected");
            let stream = client_with("localhost", tcp, Arc::new(configure(roots))).expect("tls");
            let split = split(stream).expect("split");
            (split.reading, split.writing)
        });
        let (tcp, _) = listener.accept().expect("accepted");
        let far = split(server(tcp, Arc::new(config)).expect("tls")).expect("split");
        (near.join().expect("client"), (far.reading, far.writing))
    }

    #[test]
    fn one_side_writes_while_the_other_waits_reading_on_the_same_connection() {
        let ((mut near_reading, mut near_writing), (mut far_reading, mut far_writing)) = pair();

        // The near side waits to read on its own thread, holding nothing.
        let waiting = std::thread::spawn(move || {
            let mut heard = [0u8; 5];
            near_reading.read_exact(&mut heard).expect("heard");
            heard
        });
        std::thread::sleep(Duration::from_millis(20));
        // Meanwhile it writes, and is not held up by its own waiting read.
        let started = Instant::now();
        near_writing.write_all(b"wants").expect("written");
        near_writing.flush().expect("flushed");
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "{:?}",
            started.elapsed()
        );

        let mut asked = [0u8; 5];
        far_reading.read_exact(&mut asked).expect("asked");
        assert_eq!(&asked, b"wants");
        far_writing.write_all(b"event").expect("answered");
        assert_eq!(&waiting.join().expect("near reader"), b"event");
    }

    #[test]
    fn a_close_ends_the_peer_cleanly_and_a_timeout_loses_nothing() {
        let ((mut near_reading, _near_writing), (_far_reading, mut far_writing)) = pair();
        near_reading
            .socket()
            .set_read_timeout(Some(Duration::from_millis(10)))
            .expect("timeout");
        let mut one = [0u8; 3];
        let waited = near_reading.read(&mut one).expect_err("nothing came");
        assert!(matches!(
            waited.kind(),
            ErrorKind::WouldBlock | ErrorKind::TimedOut
        ));

        far_writing.write_all(b"one").expect("written");
        near_reading
            .read_exact(&mut one)
            .expect("kept for the next read");
        assert_eq!(&one, b"one");

        far_writing.close();
        near_reading
            .socket()
            .set_read_timeout(None)
            .expect("no timeout");
        assert_eq!(near_reading.read(&mut one).expect("a clean close"), 0);
    }
}
