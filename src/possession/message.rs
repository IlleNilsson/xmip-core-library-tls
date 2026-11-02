//! Handshake messages as TLS writes them (RFC 8446 section 4, RFC 5246
//! section 7.4): a type, a 24-bit length and the body — read once here for
//! both sides of the possession proof, the host that records a handshake
//! (`transcript`) and the node that checks it (`proved`).

use crate::{Result, TlsError};

pub const CLIENT_HELLO: u8 = 1;
pub const SERVER_HELLO: u8 = 2;
pub const CERTIFICATE: u8 = 11;
pub const CERTIFICATE_VERIFY: u8 = 15;
pub const SERVER_HELLO_DONE: u8 = 14;
pub const FINISHED: u8 = 20;
pub const MESSAGE_HASH: u8 = 254;

/// The record types the transcript is read from (RFC 8446 section 5.1).
pub const RECORD_CHANGE_CIPHER_SPEC: u8 = 20;
pub const RECORD_HANDSHAKE: u8 = 22;
pub const RECORD_APPLICATION_DATA: u8 = 23;

/// The random a `HelloRetryRequest` carries in place of a `ServerHello`'s
/// (RFC 8446 section 4.1.3).
pub const RETRY_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// One handshake message: its type, its body, and the whole of it as it
/// is hashed and signed.
#[derive(Clone, Copy, Debug)]
pub struct Message<'a> {
    pub kind: u8,
    pub body: &'a [u8],
    pub whole: &'a [u8],
}

/// Every whole message in `bytes`, and how many bytes they took: a message
/// cut short at the end is left for more bytes to finish.
#[must_use]
pub fn split(bytes: &[u8]) -> (Vec<Message<'_>>, usize) {
    let mut messages = Vec::new();
    let mut at = 0;
    while bytes.len() - at >= 4 {
        let length = usize::from(bytes[at + 1]) << 16
            | usize::from(bytes[at + 2]) << 8
            | usize::from(bytes[at + 3]);
        let end = at + 4 + length;
        if end > bytes.len() {
            break;
        }
        messages.push(Message {
            kind: bytes[at],
            body: &bytes[at + 4..end],
            whole: &bytes[at..end],
        });
        at = end;
    }
    (messages, at)
}

/// Every message in `bytes`, which must hold nothing else.
///
/// # Errors
///
/// Bytes left over that make no whole message.
pub fn whole(bytes: &[u8]) -> Result<Vec<Message<'_>>> {
    let (messages, taken) = split(bytes);
    if taken != bytes.len() {
        return Err(TlsError::new(
            "the transcript ends inside a handshake message",
        ));
    }
    Ok(messages)
}

/// A cursor over a message's body.
pub struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// The next `count` bytes.
    ///
    /// # Errors
    ///
    /// Fewer left.
    pub fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        if self.bytes.len() < count {
            return Err(TlsError::new("a handshake message ends too soon"));
        }
        let (taken, rest) = self.bytes.split_at(count);
        self.bytes = rest;
        Ok(taken)
    }

    /// A big-endian number of `width` bytes.
    ///
    /// # Errors
    ///
    /// Fewer left.
    pub fn number(&mut self, width: usize) -> Result<usize> {
        Ok(self
            .take(width)?
            .iter()
            .fold(0, |sum, byte| sum << 8 | usize::from(*byte)))
    }

    /// A vector whose length is a number of `width` bytes before it.
    ///
    /// # Errors
    ///
    /// Fewer left.
    pub fn vector(&mut self, width: usize) -> Result<&'a [u8]> {
        let length = self.number(width)?;
        self.take(length)
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// What a `ServerHello` says: its random, its cipher suite and the version
/// it agreed — TLS 1.3 where `supported_versions` names it, else 1.2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hello {
    pub random: [u8; 32],
    pub suite: u16,
    pub tls13: bool,
}

impl Hello {
    /// The `ServerHello` `body`.
    ///
    /// # Errors
    ///
    /// A body that is no `ServerHello`.
    pub fn read(body: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(body);
        reader.take(2)?;
        let mut random = [0u8; 32];
        random.copy_from_slice(reader.take(32)?);
        reader.vector(1)?;
        let suite = u16::try_from(reader.number(2)?).unwrap_or_default();
        reader.take(1)?;
        let mut tls13 = false;
        if !reader.is_empty() {
            let mut extensions = Reader::new(reader.vector(2)?);
            while !extensions.is_empty() {
                let kind = extensions.number(2)?;
                let data = extensions.vector(2)?;
                // supported_versions (RFC 8446 section 4.2.1): 0x0304.
                tls13 |= kind == 43 && data == [3, 4];
            }
        }
        Ok(Self {
            random,
            suite,
            tls13,
        })
    }

    /// Whether this is a `HelloRetryRequest`.
    #[must_use]
    pub fn retries(&self) -> bool {
        self.random == RETRY_RANDOM
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_messages_are_split_and_one_cut_short_is_left() {
        let bytes = [1, 0, 0, 2, 9, 9, 2, 0, 0, 3, 7];
        let (messages, taken) = split(&bytes);
        assert_eq!((messages.len(), taken), (1, 6));
        assert_eq!((messages[0].kind, messages[0].body), (1, &[9, 9][..]));
        assert!(whole(&bytes).is_err());
        let mut reader = Reader::new(&[0, 2, 5, 6]);
        assert_eq!(reader.vector(2).expect("a vector"), [5, 6]);
        assert!(reader.is_empty() && reader.take(1).is_err());
    }
}
