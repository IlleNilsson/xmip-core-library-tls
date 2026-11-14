//! The object identifiers X.509 (RFC 5280) and PKCS #10 (RFC 2986) name a
//! certificate's parts by, as their arcs: what the reader here looks for
//! and what `xmip-core-provision` writes, one list for both.

/// id-ecPublicKey (RFC 5480).
pub const EC_PUBLIC_KEY: &[u32] = &[1, 2, 840, 10_045, 2, 1];
/// secp256r1, P-256 (RFC 5480).
pub const P256: &[u32] = &[1, 2, 840, 10_045, 3, 1, 7];
/// ecdsa-with-SHA256 (RFC 5758).
pub const ECDSA_SHA256: &[u32] = &[1, 2, 840, 10_045, 4, 3, 2];
/// id-at-commonName.
pub const COMMON_NAME: &[u32] = &[2, 5, 4, 3];
/// id-ce-subjectAltName.
pub const SUBJECT_ALT_NAME: &[u32] = &[2, 5, 29, 17];
/// id-ce-basicConstraints.
pub const BASIC_CONSTRAINTS: &[u32] = &[2, 5, 29, 19];
/// id-ce-keyUsage.
pub const KEY_USAGE: &[u32] = &[2, 5, 29, 15];
/// id-ce-extKeyUsage.
pub const EXT_KEY_USAGE: &[u32] = &[2, 5, 29, 37];
/// id-kp-serverAuth.
pub const SERVER_AUTH: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 3, 1];
/// id-kp-clientAuth.
pub const CLIENT_AUTH: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 3, 2];
/// pkcs-9-at-extensionRequest (RFC 2985).
pub const EXTENSION_REQUEST: &[u32] = &[1, 2, 840, 113_549, 1, 9, 14];
/// id-ce-subjectKeyIdentifier.
pub const SUBJECT_KEY_IDENTIFIER: &[u32] = &[2, 5, 29, 14];
/// id-ce-authorityKeyIdentifier.
pub const AUTHORITY_KEY_IDENTIFIER: &[u32] = &[2, 5, 29, 35];
/// id-ce-cRLDistributionPoints.
pub const CRL_DISTRIBUTION_POINTS: &[u32] = &[2, 5, 29, 31];
/// id-ce-cRLNumber.
pub const CRL_NUMBER: &[u32] = &[2, 5, 29, 20];
/// id-ce-cRLReasons.
pub const CRL_REASON: &[u32] = &[2, 5, 29, 21];
/// id-pe-authorityInfoAccess.
pub const AUTHORITY_INFORMATION_ACCESS: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 1, 1];
/// id-ad-caIssuers.
pub const CA_ISSUERS: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 48, 2];
