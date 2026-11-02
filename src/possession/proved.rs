//! A transcript checked where the caller is decided — on the node
//! (ADR-0009, amendment 2026-11-02): the client's `CertificateVerify`
//! verified with its own certificate's key over the messages before it, as
//! TLS 1.3 signs them (RFC 8446 section 4.4.3) or as TLS 1.2 does (RFC 5246
//! section 7.4.8). What a valid one proves is that the holder of the
//! client's key signed this very handshake — its `ServerHello` random
//! included, which the node's nonce is bound into — and to the server
//! whose certificate the transcript names.

use x509_parser::prelude::{FromDer, X509Certificate};

use super::message::{self, CERTIFICATE, CERTIFICATE_VERIFY, CLIENT_HELLO, FINISHED};
use super::message::{Hello, MESSAGE_HASH, Message, Reader, SERVER_HELLO, SERVER_HELLO_DONE};
use crate::{Result, TlsError, provider};

/// What a transcript proves: the client's chain, leaf first, which held its
/// key in this handshake; the server's leaf it was made with; the
/// `ServerHello`'s random; and whether it was TLS 1.3.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proved {
    pub client_chain: Vec<Vec<u8>>,
    pub server_leaf: Vec<u8>,
    pub server_random: [u8; 32],
    pub tls13: bool,
}

/// The schemes a TLS 1.3 `CertificateVerify` may be signed with (RFC 8446
/// section 4.2.3): no PKCS #1 v1.5, no SHA-1.
const TLS13_SCHEMES: [u16; 8] = [
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807, 0x0808,
];

/// The transcript's proof, verified.
///
/// # Errors
///
/// A transcript that does not read, does not end in the client's
/// `CertificateVerify` after its Certificate, or whose signature does not
/// verify with the client certificate's key; in words.
pub fn proved(transcript: &[u8]) -> Result<Proved> {
    let messages = message::whole(transcript)?;
    if messages.first().map(|one| one.kind) != Some(CLIENT_HELLO) {
        return Err(TlsError::new("the transcript opens with no ClientHello"));
    }
    let (verify, before) = messages
        .split_last()
        .filter(|(last, _)| last.kind == CERTIFICATE_VERIFY)
        .ok_or_else(|| TlsError::new("the transcript ends in no client CertificateVerify"))?;
    let hello = before
        .iter()
        .filter(|one| one.kind == SERVER_HELLO)
        .map(|one| Hello::read(one.body))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .rfind(|hello| !hello.retries())
        .ok_or_else(|| TlsError::new("the transcript holds no ServerHello"))?;
    // The server's Certificate is the first after the `ServerHello`; the
    // client's follows the server's `Finished` (1.3) or `ServerHelloDone` (1.2).
    let turn = if hello.tls13 {
        FINISHED
    } else {
        SERVER_HELLO_DONE
    };
    let turned = before
        .iter()
        .position(|one| one.kind == turn)
        .ok_or_else(|| TlsError::new("the transcript holds no server flight's end"))?;
    let server = before[..turned]
        .iter()
        .find(|one| one.kind == CERTIFICATE)
        .ok_or_else(|| TlsError::new("the transcript holds no server certificate"))?;
    let client = before[turned..]
        .iter()
        .find(|one| one.kind == CERTIFICATE)
        .ok_or_else(|| TlsError::new("the transcript holds no client certificate"))?;
    let client_chain = chain(client.body, hello.tls13)?;
    let server_leaf = chain(server.body, hello.tls13)?
        .into_iter()
        .next()
        .ok_or_else(|| TlsError::new("the server's Certificate is empty"))?;
    let leaf = client_chain
        .first()
        .ok_or_else(|| TlsError::new("the client's Certificate is empty"))?;
    let mut signature = Reader::new(verify.body);
    let scheme = u16::try_from(signature.number(2)?).unwrap_or_default();
    let signed = signature.vector(2)?;
    let content = if hello.tls13 {
        if !TLS13_SCHEMES.contains(&scheme) {
            return Err(TlsError::new(format!(
                "scheme {scheme:#06x} signs no TLS 1.3 proof"
            )));
        }
        tls13_content(before, hello.suite)?
    } else {
        before
            .iter()
            .flat_map(|one| one.whole.iter().copied())
            .collect()
    };
    verified(leaf, scheme, &content, signed)?;
    Ok(Proved {
        client_chain,
        server_leaf,
        server_random: hello.random,
        tls13: hello.tls13,
    })
}

/// A Certificate message's chain, leaf first.
fn chain(body: &[u8], tls13: bool) -> Result<Vec<Vec<u8>>> {
    let mut reader = Reader::new(body);
    if tls13 {
        reader.vector(1)?;
    }
    let mut list = Reader::new(reader.vector(3)?);
    let mut certificates = Vec::new();
    while !list.is_empty() {
        certificates.push(list.vector(3)?.to_vec());
        if tls13 {
            list.vector(2)?;
        }
    }
    Ok(certificates)
}

/// What a TLS 1.3 client's `CertificateVerify` signs: 64 spaces, the context
/// string, a zero, and the transcript hash — the first `ClientHello` of a
/// retried handshake replaced by its `message_hash` (RFC 8446 section 4.4.1).
fn tls13_content(before: &[Message<'_>], suite: u16) -> Result<Vec<u8>> {
    let algorithm = match suite {
        0x1301 | 0x1303 => &aws_lc_rs::digest::SHA256,
        0x1302 => &aws_lc_rs::digest::SHA384,
        other => {
            return Err(TlsError::new(format!(
                "no TLS 1.3 suite {other:#06x} is built"
            )));
        }
    };
    let retried = before
        .get(1)
        .filter(|one| one.kind == SERVER_HELLO)
        .map(|one| Hello::read(one.body))
        .transpose()?
        .is_some_and(|hello| hello.retries());
    let mut hash = aws_lc_rs::digest::Context::new(algorithm);
    for (at, one) in before.iter().enumerate() {
        if at == 0 && retried {
            let first = aws_lc_rs::digest::digest(algorithm, one.whole);
            let length = u8::try_from(first.as_ref().len()).unwrap_or_default();
            hash.update(&[MESSAGE_HASH, 0, 0, length]);
            hash.update(first.as_ref());
        } else {
            hash.update(one.whole);
        }
    }
    let mut content = vec![0x20u8; 64];
    content.extend_from_slice(b"TLS 1.3, client CertificateVerify\0");
    content.extend_from_slice(hash.finish().as_ref());
    Ok(content)
}

/// Whether `signed` is `leaf`'s key's signature by `scheme` over `content`,
/// by the provider's own verification algorithms.
fn verified(leaf: &[u8], scheme: u16, content: &[u8], signed: &[u8]) -> Result<()> {
    let (_, certificate) = X509Certificate::from_der(leaf)
        .map_err(|failure| TlsError::new(format!("the client's leaf is not X.509: {failure}")))?;
    let key = certificate.public_key().subject_public_key.data.as_ref();
    let scheme = rustls::SignatureScheme::from(scheme);
    let algorithms = provider()
        .signature_verification_algorithms
        .mapping
        .iter()
        .find(|(named, _)| *named == scheme)
        .map(|(_, algorithms)| *algorithms)
        .ok_or_else(|| TlsError::new(format!("no verification is built for {scheme:?}")))?;
    if algorithms
        .iter()
        .any(|algorithm| algorithm.verify_signature(key, content, signed).is_ok())
    {
        return Ok(());
    }
    Err(TlsError::new(
        "the client's CertificateVerify does not verify with its certificate's key",
    ))
}
