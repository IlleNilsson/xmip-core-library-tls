//! A distinguished name as the estate writes it, read from a certificate
//! or from text.
//!
//! A server that terminates TLS reports the subject and issuer of the
//! certificate its client presented (`peer`), the first gate presents that
//! subject — `CN=party-x.example,O=Party X` — and the second gate must find
//! the same name in the leaf it verified. Two writers render one name two
//! ways: RFC 4514 reverses the order and OpenSSL keeps it, one puts a space
//! after the comma and the other does not. So a name here is its
//! attributes, and two names are the same when they hold the same
//! attributes, in any order; written, they are in one order, so a name
//! read from a certificate is always written the same way.
//!
//! Here, below the transports and the identity gates both, since
//! 2026-10-19: the reading lived in `xmip-core-authenticate`, where a
//! transport writing what it read could not reach it.

use std::fmt;

use crate::Result;
use crate::certificate::{Certificate, attributes};

/// A distinguished name: its attributes, type and value.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Name {
    attributes: Vec<(String, String)>,
}

impl Name {
    /// Parse `TYPE=value,TYPE=value`. A comma inside a value is escaped with
    /// a backslash, as RFC 4514 writes it. Types are compared without case.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut attributes = Vec::new();
        let mut part = String::new();
        let mut escaped = false;

        for character in text.chars() {
            match (escaped, character) {
                (false, '\\') => escaped = true,
                (false, ',') => {
                    push(&mut attributes, &part);
                    part.clear();
                }
                (_, character) => {
                    escaped = false;
                    part.push(character);
                }
            }
        }

        push(&mut attributes, &part);
        Self { attributes }
    }

    /// The subject of a certificate, DER.
    ///
    /// # Errors
    ///
    /// The bytes are not an X.509 certificate.
    pub fn subject_of(certificate: &[u8]) -> Result<Self> {
        Self::of(&Certificate::read(certificate)?.subject)
    }

    /// The issuer of a certificate, DER.
    ///
    /// # Errors
    ///
    /// The bytes are not an X.509 certificate.
    pub fn issuer_of(certificate: &[u8]) -> Result<Self> {
        Self::of(&Certificate::read(certificate)?.issuer)
    }

    /// Whether the name is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.attributes.is_empty()
    }

    /// Its common name, `CN`, where it names one that is not empty: what a
    /// node certificate is issued for, `CN=<node>` (`xmip-core-provision`),
    /// and what a Storage node counts a node's traffic against (ADR-0052,
    /// amendment 2026-11-11). The one reading of it from a name.
    #[must_use]
    pub fn common_name(&self) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(kind, value)| kind == "CN" && !value.is_empty())
            .map(|(_, value)| value.as_str())
    }

    /// The name `name`, a `Name` DER whole, holds: a value that is not text
    /// written `#` and its hexadecimal.
    fn of(name: &[u8]) -> Result<Self> {
        let mut attributes: Vec<(String, String)> = attributes(name)?
            .into_iter()
            .map(|attribute| {
                let value = attribute.text().map_or_else(
                    || format!("#{}", codec::hex::encode(&attribute.value)),
                    ToString::to_string,
                );
                (short(&asn1::dotted(&attribute.kind)), value)
            })
            .collect();
        attributes.sort();

        Ok(Self { attributes })
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, (kind, value)) in self.attributes.iter().enumerate() {
            if index > 0 {
                f.write_str(",")?;
            }

            write!(f, "{kind}={}", value.replace(',', "\\,"))?;
        }

        Ok(())
    }
}

fn push(attributes: &mut Vec<(String, String)>, part: &str) {
    let part = part.trim();

    if part.is_empty() {
        return;
    }

    let (kind, value) = part.split_once('=').unwrap_or((part, ""));
    attributes.push((short(kind.trim()).to_uppercase(), value.trim().to_string()));
    attributes.sort();
}

/// The short name for the attribute types a subject commonly carries; a
/// dotted OID stands for the rest, and a short name already given stays.
fn short(kind: &str) -> String {
    match kind {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SN",
        "2.5.4.5" => "SERIALNUMBER",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "STREET",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "TITLE",
        "2.5.4.42" => "GN",
        "0.9.2342.19200300.100.1.1" => "UID",
        "0.9.2342.19200300.100.1.25" => "DC",
        "1.2.840.113549.1.9.1" => "EMAILADDRESS",
        other => return other.to_uppercase(),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_attributes_in_either_order_and_spacing_are_one_name() {
        let ours = Name::parse("CN=party-x.example,O=Party X");
        let theirs = Name::parse("O = Party X, cn = party-x.example");

        assert_eq!(ours, theirs);
        assert_eq!(ours.to_string(), "CN=party-x.example,O=Party X");
    }

    #[test]
    fn a_comma_in_a_value_is_escaped_and_survives() {
        let name = Name::parse("CN=Party\\, Inc,O=Party X");

        assert_eq!(name.to_string(), "CN=Party\\, Inc,O=Party X");
        assert_ne!(name, Name::parse("CN=Party,O=Party X"));
    }

    #[test]
    fn its_common_name_is_read_in_any_case_order_and_escape() {
        assert_eq!(Name::parse("CN=edge-01").common_name(), Some("edge-01"));
        assert_eq!(
            Name::parse("O=Xmip, cn = store-02 ").common_name(),
            Some("store-02")
        );
        assert_eq!(
            Name::parse("CN=Party\\, Inc,O=Party X").common_name(),
            Some("Party, Inc"),
            "an escaped comma is the value's"
        );
        assert_eq!(Name::parse("O=Xmip").common_name(), None);
        assert_eq!(Name::parse("CN=").common_name(), None);
    }

    #[test]
    fn a_certificate_is_read_for_its_subject_and_its_issuer_in_one_order() {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Party X");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Party CA");
        let key = rcgen::KeyPair::generate().expect("a key");
        let authority = rcgen::Issuer::new(params, key);
        let leaf_key = rcgen::KeyPair::generate().expect("a key");
        let mut leaf =
            rcgen::CertificateParams::new(vec!["party-x.example".into()]).expect("params");
        leaf.distinguished_name = rcgen::DistinguishedName::new();
        leaf.distinguished_name
            .push(rcgen::DnType::CommonName, "party-x.example");
        let leaf = leaf.signed_by(&leaf_key, &authority).expect("issued");

        let subject = Name::subject_of(leaf.der()).expect("a subject");
        assert_eq!(subject.to_string(), "CN=party-x.example");
        let issuer = Name::issuer_of(leaf.der()).expect("an issuer");
        assert_eq!(issuer.to_string(), "CN=Party CA,O=Party X");
        assert_eq!(issuer, Name::parse("O=Party X, CN=Party CA"));
        assert!(Name::subject_of(b"not a certificate").is_err());
    }
}
