//! A certificate read once (RFC 5280 section 4.1): every part the estate
//! looks at — its serial, its issuer and subject, its validity, its key,
//! its extensions and the signature over what it signs — so a name, a
//! validity, a usage, a key identifier and a chain are each read from the
//! same walk, over the estate's X.690 reader (`xmip-core-library-asn1`).
//!
//! The one certificate reader in Xmip. Until 2026-11-13 there were three:
//! provisioning's over asn1, this library's and the authentication gates'
//! over x509-parser, and the SAML gate's over x509-parser again.

pub mod oid;
mod part;

pub use part::{
    Attribute, attributes, dns_names, general_names, point_of, subject_public_key, text_attributes,
    time,
};

use asn1::{BIT_STRING, INTEGER, OBJECT_IDENTIFIER, OCTET_STRING, SEQUENCE};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};

use crate::{Result, TlsError};
use oid::{AUTHORITY_KEY_IDENTIFIER, COMMON_NAME, EXT_KEY_USAGE, SUBJECT_ALT_NAME};

/// A certificate's parts, as its DER holds them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    /// What its issuer signed, `TBSCertificate` DER whole.
    pub signed: Vec<u8>,
    /// Its serial number's contents, as written.
    pub serial: Vec<u8>,
    /// Its issuer, `Name` DER whole.
    pub issuer: Vec<u8>,
    /// Its subject, `Name` DER whole.
    pub subject: Vec<u8>,
    /// From when it is valid, seconds since the epoch.
    pub not_before: i64,
    /// Until when.
    pub not_after: i64,
    /// Its key, `SubjectPublicKeyInfo` DER whole.
    pub public_key_info: Vec<u8>,
    /// Every extension, its identifier and its value's DER, in the order
    /// written.
    pub extensions: Vec<(Vec<u32>, Vec<u8>)>,
    /// Its issuer's signature, DER as X.509 carries an ECDSA one.
    pub signature: Vec<u8>,
}

impl Certificate {
    /// The certificate `der` is.
    ///
    /// # Errors
    ///
    /// Where it is not a certificate, in words.
    pub fn read(der: &[u8]) -> Result<Self> {
        let (certificate, _) = asn1::expect(der, SEQUENCE)?;
        let (_, contents, after) = asn1::read(certificate)?;
        let signed = certificate[..certificate.len() - after.len()].to_vec();
        let (_, rest) = asn1::expect(after, SEQUENCE)?;
        let (bits, _) = asn1::expect(rest, BIT_STRING)?;
        let signature = match bits.split_first() {
            Some((0, signature)) => signature.to_vec(),
            _ => {
                return Err(TlsError::new(
                    "the certificate's signature is not whole bytes",
                ));
            }
        };

        let mut rest = contents;
        if let (tag, _, after) = asn1::read(rest)?
            && tag == asn1::context(0, true)
        {
            rest = after;
        }
        let (serial, after) = asn1::expect(rest, INTEGER)?;
        // The signature algorithm, inside, is the one outside.
        let after = asn1::read(after)?.2;
        let (issuer, after) = whole(after)?;
        let (times, after) = asn1::expect(after, SEQUENCE)?;
        let (first_tag, first, second) = asn1::read(times)?;
        let (second_tag, second, _) = asn1::read(second)?;
        let (subject, after) = whole(after)?;
        let (public_key_info, mut after) = whole(after)?;
        let mut extensions = Vec::new();
        while !after.is_empty() {
            let (tag, inner, next) = asn1::read(after)?;
            if tag == asn1::context(3, true) {
                extensions = read_extensions(inner)?;
            }
            after = next;
        }
        Ok(Self {
            signed,
            serial: serial.to_vec(),
            issuer,
            subject,
            not_before: time(first_tag, first)?,
            not_after: time(second_tag, second)?,
            public_key_info,
            extensions,
            signature,
        })
    }

    /// The first certificate of the PEM `text`: a chain's leaf.
    ///
    /// # Errors
    ///
    /// Where the text holds no certificate, or its first is not one.
    pub fn first(text: &str) -> Result<Self> {
        let blocks = codec::pem::decode("CERTIFICATE", text)?;
        let first = blocks
            .first()
            .ok_or_else(|| TlsError::new("the text holds no CERTIFICATE"))?;
        Self::read(first)
    }

    /// The value of the extension `id`, where it has one.
    #[must_use]
    pub fn extension(&self, id: &[u32]) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(held, _)| held == id)
            .map(|(_, value)| value.as_slice())
    }

    /// The value of the extension `id`, where it has one, and a refusal
    /// where it has it more than once (RFC 5280 section 4.2).
    ///
    /// # Errors
    ///
    /// Where the extension appears twice or more.
    pub fn unique_extension(&self, id: &[u32]) -> Result<Option<&[u8]>> {
        let mut found = self.extensions.iter().filter(|(held, _)| held == id);
        let first = found.next().map(|(_, value)| value.as_slice());
        if found.next().is_some() {
            return Err(TlsError::new(format!(
                "the extension {} appears more than once in the certificate",
                asn1::dotted(id)
            )));
        }
        Ok(first)
    }

    /// Its serial number in hexadecimal, uppercase, as a register files it
    /// and an operator types it.
    #[must_use]
    pub fn serial_hex(&self) -> String {
        codec::hex::encode(&self.serial).to_ascii_uppercase()
    }

    /// Its subject's common name, where it names one.
    ///
    /// # Errors
    ///
    /// Where the subject is not a `Name` of text.
    pub fn common_name(&self) -> Result<Option<String>> {
        Ok(text_attributes(&self.subject)?
            .into_iter()
            .find(|(kind, _)| kind == COMMON_NAME)
            .map(|(_, value)| value))
    }

    /// The DNS names it is for.
    ///
    /// # Errors
    ///
    /// Where its alternative names do not read.
    pub fn names(&self) -> Result<Vec<String>> {
        self.extension(SUBJECT_ALT_NAME)
            .map_or_else(|| Ok(Vec::new()), dns_names)
    }

    /// Each `otherName` its alternative names carry: its type, and its
    /// value, `[0] EXPLICIT`, whole — a smart card's user principal name
    /// under Microsoft's type, say.
    ///
    /// # Errors
    ///
    /// Where its alternative names do not read.
    pub fn other_names(&self) -> Result<Vec<(Vec<u32>, Vec<u8>)>> {
        let Some(value) = self.extension(SUBJECT_ALT_NAME) else {
            return Ok(Vec::new());
        };
        general_names(value)?
            .into_iter()
            .filter(|(tag, _)| *tag == asn1::context(0, true))
            .map(|(_, name)| {
                let (kind, held) = asn1::expect(name, OBJECT_IDENTIFIER)?;
                Ok((asn1::read_object_identifier(kind)?, held.to_vec()))
            })
            .collect()
    }

    /// The key identifier its issuer is named by: its authority key
    /// identifier's `keyIdentifier`, where it has one.
    ///
    /// # Errors
    ///
    /// Where the extension does not read.
    pub fn authority_key_identifier(&self) -> Result<Option<Vec<u8>>> {
        let Some(value) = self.extension(AUTHORITY_KEY_IDENTIFIER) else {
            return Ok(None);
        };
        let (fields, _) = asn1::expect(value, SEQUENCE)?;
        Ok(asn1::read_all(fields)?
            .into_iter()
            .find(|(tag, _)| *tag == asn1::context(0, false))
            .map(|(_, identifier)| identifier.to_vec()))
    }

    /// The extended key usages it names, or `None` where it names none:
    /// what it was issued to authenticate.
    ///
    /// # Errors
    ///
    /// Where the extension does not read.
    pub fn extended_key_usages(&self) -> Result<Option<Vec<Vec<u32>>>> {
        let Some(value) = self.extension(EXT_KEY_USAGE) else {
            return Ok(None);
        };
        let (usages, _) = asn1::expect(value, SEQUENCE)?;
        asn1::read_all(usages)?
            .into_iter()
            .map(|(_, usage)| asn1::read_object_identifier(usage).map_err(Into::into))
            .collect::<Result<Vec<_>>>()
            .map(Some)
    }

    /// Whether `issuer` — the certificate it names as its issuer — signed
    /// it: the names match and the signature verifies under its key.
    ///
    /// # Errors
    ///
    /// Where the issuer's key is not P-256.
    pub fn signed_by(&self, issuer: &Self) -> Result<bool> {
        Ok(self.issuer == issuer.subject && issuer.verifies(&self.signed, &self.signature)?)
    }

    /// Whether its key made `signature`, DER, over `message`: what an
    /// authority signs that is no certificate, a node's slice among them
    /// (ADR-0031, amendment 2026-11-06).
    ///
    /// # Errors
    ///
    /// Where its key is not P-256.
    pub fn verifies(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        Ok(verify(
            &point_of(&self.public_key_info)?,
            message,
            signature,
        ))
    }
}

/// Whether `signature`, DER as X.509 and PKCS #10 write it, is the P-256
/// key `point`'s over `message`, by the provider rustls already brings.
#[must_use]
pub fn verify(point: &[u8], message: &[u8], signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
        .verify(message, signature)
        .is_ok()
}

/// The element `bytes` opens with, whole, and what follows it.
fn whole(bytes: &[u8]) -> Result<(Vec<u8>, &[u8])> {
    let (_, _, after) = asn1::read(bytes)?;
    Ok((bytes[..bytes.len() - after.len()].to_vec(), after))
}

/// Every extension `Extensions` holds.
fn read_extensions(explicit: &[u8]) -> Result<Vec<(Vec<u32>, Vec<u8>)>> {
    let (list, _) = asn1::expect(explicit, SEQUENCE)?;
    let mut found = Vec::new();
    for (_, one) in asn1::read_all(list)? {
        let (id, rest) = asn1::expect(one, OBJECT_IDENTIFIER)?;
        let rest = match asn1::read(rest)? {
            (asn1::BOOLEAN, _, after) => after,
            _ => rest,
        };
        let (value, _) = asn1::expect(rest, OCTET_STRING)?;
        found.push((asn1::read_object_identifier(id)?, value.to_vec()));
    }
    Ok(found)
}

/// PEM that is not PEM.
impl From<codec::CodecError> for TlsError {
    fn from(error: codec::CodecError) -> Self {
        Self::new(error.message)
    }
}

#[cfg(test)]
mod tests;
