//! A recorded handshake's transcript, recovered on the host that served it
//! (ADR-0009, amendment 2026-11-02): the handshake messages in the order
//! both ends hashed them, from the `ClientHello` up to and including the
//! client's `CertificateVerify`, as TLS writes each one.
//!
//! TLS 1.2 sends them in the clear until `ChangeCipherSpec`. TLS 1.3 encrypts
//! every message after the `ServerHello` under the handshake traffic secrets,
//! which [`Secrets`] holds for this one recovery and zeroes when dropped;
//! each record is opened here with the key and IV `HKDF-Expand-Label` makes
//! of them (RFC 8446 sections 5.2, 5.3 and 7.3).

use aws_lc_rs::aead::{AES_128_GCM, AES_256_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce};
use aws_lc_rs::aead::{Algorithm, UnboundKey};
use aws_lc_rs::hkdf::{self, HKDF_SHA256, HKDF_SHA384, Prk};
use zeroize::Zeroizing;

use super::message::{self, CERTIFICATE, CERTIFICATE_VERIFY, FINISHED, Hello, SERVER_HELLO};
use super::message::{RECORD_APPLICATION_DATA, RECORD_HANDSHAKE, SERVER_HELLO_DONE};
use crate::{Result, TlsError};

/// The two handshake traffic secrets of one TLS 1.3 handshake, zeroed when
/// dropped; never written, logged or kept past the recovery.
#[derive(Default)]
pub struct Secrets {
    pub client: Zeroizing<Vec<u8>>,
    pub server: Zeroizing<Vec<u8>>,
}

/// The transcript of the handshake whose bytes `from_client` and
/// `from_server` are, as the socket carried them.
///
/// # Errors
///
/// A handshake that carries no client Certificate and `CertificateVerify` —
/// none presented, or a session resumed — or one that does not read.
pub fn recovered(from_client: &[u8], from_server: &[u8], secrets: &Secrets) -> Result<Vec<u8>> {
    let client = records(from_client);
    let server = records(from_server);
    let server_before = message::split(&server.before_change).0;
    let hello = server_before
        .iter()
        .filter(|one| one.kind == SERVER_HELLO)
        .map(|one| Hello::read(one.body))
        .next_back()
        .ok_or_else(|| TlsError::new("the server said no ServerHello"))??;
    let mut transcript = Vec::new();
    if hello.tls13 {
        let (aead, hkdf) = suite(hello.suite)?;
        let server_plain = message::whole(&server.clear)?;
        let client_plain = message::whole(&client.clear)?;
        let server_sealed = opened(&server.sealed, &secrets.server, aead, hkdf)?;
        let client_sealed = opened(&client.sealed, &secrets.client, aead, hkdf)?;
        // CH1, [HRR, CH2], SH: the clear messages, interleaved.
        let mut clients = client_plain.iter();
        for server_one in &server_plain {
            if let Some(client_one) = clients.next() {
                transcript.extend_from_slice(client_one.whole);
            }
            transcript.extend_from_slice(server_one.whole);
        }
        let (sealed, _) = message::split(&server_sealed);
        for one in &sealed {
            transcript.extend_from_slice(one.whole);
        }
        proving(&mut transcript, &message::split(&client_sealed).0)?;
    } else {
        // CH, then the server's SH through `ServerHelloDone`, then the client's.
        let client_plain = message::split(&client.before_change).0;
        let (first, rest) = client_plain
            .split_first()
            .ok_or_else(|| TlsError::new("the client said no ClientHello"))?;
        transcript.extend_from_slice(first.whole);
        let done = server_before
            .iter()
            .position(|one| one.kind == SERVER_HELLO_DONE)
            .ok_or_else(|| TlsError::new("the server said no ServerHelloDone"))?;
        server_before[..=done]
            .iter()
            .for_each(|one| transcript.extend_from_slice(one.whole));
        proving(&mut transcript, rest)?;
    }
    Ok(transcript)
}

/// The client's messages up to and including its `CertificateVerify`, after
/// its Certificate, onto `transcript`.
/// A client that presented no certificate — an empty Certificate, or none
/// at all where a session was resumed — signs no `CertificateVerify`.
fn proving(transcript: &mut Vec<u8>, client: &[message::Message<'_>]) -> Result<()> {
    if client.iter().any(|one| one.kind == CERTIFICATE) {
        for one in client {
            if one.kind == FINISHED {
                break;
            }
            transcript.extend_from_slice(one.whole);
            if one.kind == CERTIFICATE_VERIFY {
                return Ok(());
            }
        }
    }
    Err(TlsError::new(
        "the handshake carried no client certificate's proof: none was presented, or the \
         session was resumed",
    ))
}

/// One direction's records: the handshake bytes sent in the clear — before
/// its first `ChangeCipherSpec`, which in TLS 1.2 is every clear one, and all
/// of them, which TLS 1.3 sends around its compatibility `ChangeCipherSpec` —
/// and the sealed records of TLS 1.3, each header and its payload.
struct Records<'a> {
    before_change: Vec<u8>,
    clear: Vec<u8>,
    sealed: Vec<(&'a [u8], &'a [u8])>,
}

fn records(bytes: &[u8]) -> Records<'_> {
    let mut read = Records {
        before_change: Vec::new(),
        clear: Vec::new(),
        sealed: Vec::new(),
    };
    let mut changed = false;
    let mut at = 0;
    while bytes.len() - at >= 5 {
        let length = usize::from(bytes[at + 3]) << 8 | usize::from(bytes[at + 4]);
        let end = at + 5 + length;
        if end > bytes.len() {
            break;
        }
        let (header, payload) = (&bytes[at..at + 5], &bytes[at + 5..end]);
        match header[0] {
            RECORD_HANDSHAKE => {
                read.clear.extend_from_slice(payload);
                if !changed {
                    read.before_change.extend_from_slice(payload);
                }
            }
            RECORD_APPLICATION_DATA => read.sealed.push((header, payload)),
            message::RECORD_CHANGE_CIPHER_SPEC => changed = true,
            _ => {}
        }
        at = end;
    }
    read
}

/// The record protection and the hash a TLS 1.3 suite names.
fn suite(suite: u16) -> Result<(&'static Algorithm, hkdf::Algorithm)> {
    match suite {
        0x1301 => Ok((&AES_128_GCM, HKDF_SHA256)),
        0x1302 => Ok((&AES_256_GCM, HKDF_SHA384)),
        0x1303 => Ok((&CHACHA20_POLY1305, HKDF_SHA256)),
        other => Err(TlsError::new(format!(
            "no TLS 1.3 suite {other:#06x} is built"
        ))),
    }
}

/// A length HKDF-Expand writes.
struct Length(usize);

impl hkdf::KeyType for Length {
    fn len(&self) -> usize {
        self.0
    }
}

/// `HKDF-Expand-Label`(`secret`, `label`, "", `length`) (RFC 8446 section 7.1).
fn expanded(secret: &[u8], hash: hkdf::Algorithm, label: &str, length: usize) -> Result<Vec<u8>> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(full.len() + 4);
    info.extend_from_slice(&u16::try_from(length).unwrap_or_default().to_be_bytes());
    info.push(u8::try_from(full.len()).unwrap_or_default());
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    let mut out = vec![0u8; length];
    Prk::new_less_safe(hash, secret)
        .expand(&[&info], Length(length))
        .and_then(|okm| okm.fill(&mut out))
        .map_err(|_| TlsError::new("the handshake secret did not expand"))?;
    Ok(out)
}

/// The handshake bytes the `sealed` records hold, opened in order under
/// `secret`, until a `Finished` is whole; a record that does not open — the
/// first of the application's — ends them.
fn opened(
    sealed: &[(&[u8], &[u8])],
    secret: &[u8],
    aead: &'static Algorithm,
    hash: hkdf::Algorithm,
) -> Result<Vec<u8>> {
    if secret.is_empty() {
        return Err(TlsError::new(
            "no handshake secret was kept for this handshake",
        ));
    }
    let key = Zeroizing::new(expanded(secret, hash, "key", aead.key_len())?);
    let iv = Zeroizing::new(expanded(secret, hash, "iv", 12)?);
    let key = UnboundKey::new(aead, &key)
        .map(LessSafeKey::new)
        .map_err(|_| TlsError::new("the handshake key is not one"))?;
    let mut plain = Vec::new();
    for (sequence, (header, payload)) in sealed.iter().enumerate() {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&iv);
        for (byte, counter) in nonce[4..].iter_mut().zip((sequence as u64).to_be_bytes()) {
            *byte ^= counter;
        }
        let mut buffer = payload.to_vec();
        let Ok(inner) = key.open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(*header),
            &mut buffer,
        ) else {
            break;
        };
        // `TLSInnerPlaintext`: the content, its type, then zeros.
        let Some(last) = inner.iter().rposition(|byte| *byte != 0) else {
            continue;
        };
        if inner[last] == RECORD_HANDSHAKE {
            plain.extend_from_slice(&inner[..last]);
        }
        if message::split(&plain)
            .0
            .iter()
            .any(|one| one.kind == FINISHED)
        {
            break;
        }
    }
    Ok(plain)
}
