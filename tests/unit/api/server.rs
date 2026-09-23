use super::*;

#[test]
fn validates_external_identifiers() {
    assert!(valid_object_name("roa-abc.roa"));
    assert!(!valid_object_name("../ca.key"));
    assert_eq!(parse_asn_identifier("64496").unwrap(), 64496);
    assert!(parse_asn_identifier("AS64496").is_err());
    assert!(validate_content_key(&"a".repeat(64)).is_ok());
    assert!(validate_content_key("request-id").is_err());
    assert!(withdrawable_object_kind("current.roa").is_err());
    assert_eq!(
        withdrawable_object_kind("customer.asa").unwrap(),
        ObjectKind::Aspa
    );
    assert!(withdrawable_object_kind("current.cer").is_err());
    assert!(withdrawable_object_kind("../current.roa").is_err());
}

#[test]
fn selects_registered_repository_media_types() {
    assert_eq!(repository_content_type("key.cer"), "application/pkix-cert");
    assert_eq!(repository_content_type("key.crl"), "application/pkix-crl");
    assert_eq!(
        repository_content_type("key.mft"),
        "application/rpki-manifest"
    );
    assert_eq!(repository_content_type("key.roa"), "application/rpki-roa");
    assert_eq!(repository_content_type("key.asa"), "application/rpki-aspa");
    assert_eq!(repository_content_type("key.toa"), "application/rpki-toa");
    assert_eq!(repository_content_type("key.sav"), "application/rpki-sispi");
    assert_eq!(
        repository_content_type("key.bin"),
        "application/octet-stream"
    );
}
