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

#[test]
fn snapshot_tar_contains_only_exported_public_materials() {
    let temporary = tempfile::tempdir().unwrap();
    let repository = temporary.path().join("repository");
    std::fs::create_dir(&repository).unwrap();
    std::fs::write(repository.join("example.roa"), b"signed object").unwrap();
    std::fs::write(temporary.path().join("trust-anchor.tal"), b"tal").unwrap();
    let archive = tar_experiment(temporary.path()).unwrap();
    assert_eq!(archive.len() % 512, 0);
    assert!(archive.ends_with(&[0u8; 1024]));
    let names = archive
        .chunks(512)
        .filter_map(|chunk| {
            let end = chunk[..100].iter().position(|byte| *byte == 0)?;
            let name = std::str::from_utf8(&chunk[..end]).ok()?;
            (!name.is_empty()).then(|| name.to_string())
        })
        .collect::<Vec<_>>();
    assert!(names.contains(&"repository/example.roa".to_string()));
    assert!(names.contains(&"trust-anchor.tal".to_string()));
    assert!(!names.iter().any(|name| name.contains("key")));
}
