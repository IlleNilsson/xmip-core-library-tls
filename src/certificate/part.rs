//! The parts of X.509 (RFC 5280) a certificate, a request and a revocation
//! list are made of, read once: a name's attributes, the alternative
//! names, a time, a public key. Written by `xmip-core-provision`, which
//! reads them back here.

use asn1::{BIT_STRING, OBJECT_IDENTIFIER, SEQUENCE, UTC_TIME};
use codec::civil::CivilTime;

use super::oid::{EC_PUBLIC_KEY, P256};
use crate::{Result, TlsError};

/// One attribute of a distinguished name: its type, and its value with the
/// tag it was written under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribute {
    /// Its type: `2.5.4.3`, the common name, say.
    pub kind: Vec<u32>,
    /// The tag its value is written under: `UTF8String`, `PrintableString`.
    pub tag: u8,
    /// Its value's contents.
    pub value: Vec<u8>,
}

impl Attribute {
    /// Its value as text, where it is one of the string types a name is
    /// written in and its bytes are UTF-8; `None` for any other — a
    /// `BMPString`, say, which a reader shows as hexadecimal.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        // NumericString, PrintableString, TeletexString, VideotexString,
        // IA5String, GraphicString, VisibleString, GeneralString and
        // UTF8String.
        const TEXT: [u8; 9] = [0x12, 0x13, 0x14, 0x15, 0x16, 0x19, 0x1a, 0x1b, 0x0c];
        TEXT.contains(&self.tag)
            .then(|| core::str::from_utf8(&self.value).ok())
            .flatten()
    }
}

/// The attributes a `Name` holds, in the order written.
///
/// # Errors
///
/// Where it is not a `Name`.
pub fn attributes(name: &[u8]) -> Result<Vec<Attribute>> {
    let (sets, _) = asn1::expect(name, SEQUENCE)?;
    let mut attributes = Vec::new();
    for (_, set) in asn1::read_all(sets)? {
        for (_, attribute) in asn1::read_all(set)? {
            let (kind, rest) = asn1::expect(attribute, OBJECT_IDENTIFIER)?;
            let (tag, value, _) = asn1::read(rest)?;
            attributes.push(Attribute {
                kind: asn1::read_object_identifier(kind)?,
                tag,
                value: value.to_vec(),
            });
        }
    }
    Ok(attributes)
}

/// The attributes a `Name` holds, each its type and its value as text, in
/// the order written: what a request's subject is read as, strictly.
///
/// # Errors
///
/// Where it is not a `Name`, or a value is not text.
pub fn text_attributes(name: &[u8]) -> Result<Vec<(Vec<u32>, String)>> {
    attributes(name)?
        .into_iter()
        .map(|attribute| match attribute.text() {
            Some(text) => Ok((attribute.kind.clone(), text.to_string())),
            None => Err(TlsError::new("a name's value is not text")),
        })
        .collect()
}

/// Each name an alternative-names value (`GeneralNames`) holds, its tag
/// and its contents: a `dNSName` is `[2]`, an `iPAddress` `[7]`, an
/// `otherName` `[0]`, constructed.
///
/// # Errors
///
/// Where the value is not a `SEQUENCE` of names.
pub fn general_names(value: &[u8]) -> Result<Vec<(u8, &[u8])>> {
    let (contents, _) = asn1::expect(value, SEQUENCE)?;
    Ok(asn1::read_all(contents)?)
}

/// The `dNSName`s an alternative-names value holds; other kinds of name are
/// passed over.
///
/// # Errors
///
/// Where the value is not a `SEQUENCE` of names.
pub fn dns_names(value: &[u8]) -> Result<Vec<String>> {
    Ok(general_names(value)?
        .into_iter()
        .filter(|(tag, _)| *tag == asn1::context(2, false))
        .map(|(_, name)| String::from_utf8_lossy(name).into_owned())
        .collect())
}

/// A `UTCTime` or `GeneralizedTime` in UTC, as seconds since the epoch.
///
/// # Errors
///
/// Where the tag is neither, or the text is not a time.
pub fn time(tag: u8, contents: &[u8]) -> Result<i64> {
    let text = core::str::from_utf8(contents).unwrap_or_default();
    let (year, rest) = match tag {
        UTC_TIME if text.len() == 13 => {
            let two: i64 = text[..2].parse().unwrap_or(-1);
            (if two < 50 { 2000 + two } else { 1900 + two }, &text[2..])
        }
        asn1::GENERALIZED_TIME if text.len() == 15 => (text[..4].parse().unwrap_or(-1), &text[4..]),
        _ => return Err(TlsError::new(format!("not a certificate time: {text:?}"))),
    };
    let part = |at: usize| rest.get(at..at + 2).and_then(|two| two.parse::<u32>().ok());
    let read = || {
        CivilTime::new(year, part(0)?, part(2)?, part(4)?, part(6)?, part(8)?)
            .filter(|_| rest.ends_with('Z'))
    };
    read()
        .map(|at| at.unix())
        .ok_or_else(|| TlsError::new(format!("not a certificate time: {text:?}")))
}

/// The key a `SubjectPublicKeyInfo` holds: its `BIT STRING`'s bytes.
///
/// # Errors
///
/// Where it is not one, or its key is not whole bytes.
pub fn subject_public_key(info: &[u8]) -> Result<&[u8]> {
    let (contents, _) = asn1::expect(info, SEQUENCE)?;
    let (_, rest) = asn1::expect(contents, SEQUENCE)?;
    let (bits, _) = asn1::expect(rest, BIT_STRING)?;
    match bits.split_first() {
        Some((0, key)) => Ok(key),
        _ => Err(TlsError::new("the public key is not whole bytes")),
    }
}

/// The P-256 point a `SubjectPublicKeyInfo` holds.
///
/// # Errors
///
/// Where it is not one, or its key is not P-256.
pub fn point_of(info: &[u8]) -> Result<Vec<u8>> {
    let (contents, _) = asn1::expect(info, SEQUENCE)?;
    let (algorithm, _) = asn1::expect(contents, SEQUENCE)?;
    let named = [
        asn1::tlv(OBJECT_IDENTIFIER, &asn1::object_identifier(EC_PUBLIC_KEY)),
        asn1::tlv(OBJECT_IDENTIFIER, &asn1::object_identifier(P256)),
    ]
    .concat();
    if algorithm != named {
        return Err(TlsError::new("the public key is not a P-256 key"));
    }
    match subject_public_key(info)? {
        point if point.len() == 65 => Ok(point.to_vec()),
        _ => Err(TlsError::new(
            "the P-256 public key is not an uncompressed point",
        )),
    }
}

/// DER that is not what X.509 says.
impl From<asn1::Asn1Error> for TlsError {
    fn from(error: asn1::Asn1Error) -> Self {
        Self::new(format!("the DER: {}", error.message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(text: &str) -> Vec<u8> {
        asn1::tlv(UTC_TIME, text.as_bytes())
    }

    #[test]
    fn a_time_is_read_from_either_form_and_nonsense_is_refused() {
        let epoch = utc("700101000000Z");
        let (tag, contents, _) = asn1::read(&epoch).expect("read");
        assert_eq!(time(tag, contents).expect("time"), 0);
        let last = utc("491231235959Z");
        let (tag, contents, _) = asn1::read(&last).expect("read");
        assert_eq!(time(tag, contents).expect("time"), 2_524_607_999);
        let general = asn1::tlv(asn1::GENERALIZED_TIME, b"20500101000000Z");
        let (tag, contents, _) = asn1::read(&general).expect("read");
        assert_eq!(time(tag, contents).expect("time"), 2_524_608_000);
        assert!(time(UTC_TIME, b"nonsense").is_err());
        assert!(time(UTC_TIME, b"700101000000+").is_err());
    }

    #[test]
    fn an_attribute_is_text_only_in_a_string_type_and_a_foreign_key_is_refused() {
        let text = Attribute {
            kind: vec![2, 5, 4, 3],
            tag: 0x13,
            value: b"x".to_vec(),
        };
        assert_eq!(text.text(), Some("x"));
        let bmp = Attribute { tag: 0x1e, ..text };
        assert_eq!(bmp.text(), None);
        let rsa = asn1::tlv(
            OBJECT_IDENTIFIER,
            &asn1::object_identifier(&[1, 2, 840, 113_549, 1, 1, 1]),
        );
        let foreign = asn1::tlv(SEQUENCE, &asn1::tlv(SEQUENCE, &rsa));
        assert!(point_of(&foreign).is_err());
        assert!(attributes(&[0x02, 0x01, 0x00]).is_err());
    }
}
