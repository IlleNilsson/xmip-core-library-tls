use super::*;

/// An authority, and a leaf it issued for `party-x.example` with the
/// user principal name a smart card carries.
fn issued() -> (rcgen::Certificate, rcgen::Certificate, rcgen::Certificate) {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Party CA");
    let key = rcgen::KeyPair::generate().expect("a key");
    let own = params.self_signed(&key).expect("self-signed");
    let authority = rcgen::Issuer::new(params, key);
    let mut leaf = rcgen::CertificateParams::new(vec!["party-x.example".into()]).expect("params");
    leaf.distinguished_name = rcgen::DistinguishedName::new();
    leaf.distinguished_name
        .push(rcgen::DnType::CommonName, "party-x.example");
    leaf.not_before = rcgen::date_time_ymd(2030, 1, 1);
    leaf.not_after = rcgen::date_time_ymd(2031, 1, 1);
    leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    leaf.use_authority_key_identifier_extension = true;
    leaf.subject_alt_names.push(rcgen::SanType::OtherName((
        vec![1, 3, 6, 1, 4, 1, 311, 20, 2, 3],
        rcgen::OtherNameValue::Utf8String("jane@party-x.example".into()),
    )));
    let leaf_key = rcgen::KeyPair::generate().expect("a key");
    let signed = leaf.signed_by(&leaf_key, &authority).expect("issued");
    let stranger_key = rcgen::KeyPair::generate().expect("a key");
    let stranger = rcgen::CertificateParams::new(vec!["s.example".into()])
        .expect("params")
        .self_signed(&stranger_key)
        .expect("self-signed");
    (own, signed, stranger)
}

#[test]
fn a_leaf_is_read_for_its_names_times_usages_and_issuer() {
    let (authority, leaf, stranger) = issued();
    let read = Certificate::read(leaf.der()).expect("a certificate");
    let issuer = Certificate::read(authority.der()).expect("the authority");

    assert_eq!(
        read.common_name().expect("a name").as_deref(),
        Some("party-x.example")
    );
    assert_eq!(read.names().expect("names"), ["party-x.example"]);
    assert_eq!(
        (read.not_before, read.not_after),
        (1_893_456_000, 1_924_992_000)
    );
    assert_eq!(
        read.serial_hex(),
        codec::hex::encode(&read.serial).to_uppercase()
    );
    assert_eq!(
        read.extended_key_usages().expect("usages"),
        Some(vec![oid::SERVER_AUTH.to_vec()])
    );
    assert!(read.authority_key_identifier().expect("read").is_some());
    assert_eq!(read.issuer, issuer.subject);
    assert!(read.signed_by(&issuer).expect("checked"));
    let other = Certificate::read(stranger.der()).expect("a stranger");
    assert!(!read.signed_by(&other).expect("checked"));
    assert_eq!(point_of(&read.public_key_info).expect("a point").len(), 65);
    assert_eq!(Certificate::first(&leaf.pem()).expect("from PEM"), read);
    assert!(Certificate::read(b"not a certificate").is_err());
    assert!(Certificate::first("no PEM here").is_err());
}

#[test]
fn an_other_name_is_read_whole_under_its_type() {
    let (_, leaf, _) = issued();
    let read = Certificate::read(leaf.der()).expect("a certificate");
    let other = read.other_names().expect("other names");
    assert_eq!(other.len(), 1);
    assert_eq!(other[0].0, [1, 3, 6, 1, 4, 1, 311, 20, 2, 3]);
    let (inner, _) = asn1::expect(&other[0].1, asn1::context(0, true)).expect("[0]");
    let (text, _) = asn1::expect(inner, asn1::UTF8_STRING).expect("text");
    assert_eq!(text, b"jane@party-x.example");
}

#[test]
fn an_extension_carried_twice_is_refused_where_it_must_be_unique() {
    let (_, leaf, _) = issued();
    let mut read = Certificate::read(leaf.der()).expect("a certificate");
    assert!(
        read.unique_extension(&[2, 5, 29, 72])
            .expect("absent")
            .is_none()
    );
    read.extensions.push((vec![2, 5, 29, 72], vec![1]));
    assert_eq!(
        read.unique_extension(&[2, 5, 29, 72]).expect("once"),
        Some(&[1][..])
    );
    read.extensions.push((vec![2, 5, 29, 72], vec![2]));
    let refused = read.unique_extension(&[2, 5, 29, 72]).expect_err("twice");
    assert!(refused.message.contains("2.5.29.72"), "{refused}");
}
