use super::*;
use crate::{CaConfig, CaManager, RoaPayload, RoaRequest, SispiRequest};

#[test]
fn reports_valid_current_roa_and_sispi_publications() {
    let dir = tempfile::tempdir().unwrap();
    let config = CaConfig {
        development_asns: vec![64496],
        ..CaConfig::default()
    };
    let ca = CaManager::init(dir.path(), config).unwrap();
    ca.sign_roa(
        &RoaRequest {
            asn: 64496,
            prefixes: vec![RoaPayload {
                prefix: "192.0.2.0/24".parse().unwrap(),
                max_length: Some(26),
            }],
        },
        "report-test.roa",
    )
    .unwrap();
    let name = ca
        .list_published_objects()
        .unwrap()
        .into_iter()
        .find(|name| name.ends_with(".roa"))
        .unwrap();
    let report = ca.validate_published_object(&name).unwrap();
    assert_eq!(report.overall, ValidationStatus::Valid);
    assert_eq!(
        report.scope,
        "configured_trust_anchor_to_current_publication"
    );
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.id == "signed_object")
    );

    ca.sign_sispi(
        &SispiRequest {
            asn: 64496,
            addresses: vec!["192.0.2.1".parse().unwrap()],
        },
        "report-test.sav",
    )
    .unwrap();
    let name = ca
        .list_published_objects()
        .unwrap()
        .into_iter()
        .find(|name| name.ends_with(".sav"))
        .unwrap();
    let report = ca.validate_published_object(&name).unwrap();
    assert_eq!(report.overall, ValidationStatus::Valid);
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.id == "signed_object")
    );
}
