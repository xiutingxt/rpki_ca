use super::*;
use crate::infrastructure::state_store::LocalStateStore;
use rpki::repository::{aspa::Aspa, cert::Cert, crl::Crl, manifest::Manifest, tal::TalInfo};
use std::fs;

fn repository_file(root: &std::path::Path, extension: &str) -> std::path::PathBuf {
    fs::read_dir(root.join("repository"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().and_then(|value| value.to_str()) == Some(extension))
        .unwrap()
}

#[test]
fn signs_aspa_and_atomically_updates_crl_and_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let config = CaConfig {
        development_asns: vec![64496],
        ..CaConfig::default()
    };
    let ca = crate::CaManager::init(dir.path(), config).unwrap();
    let request = AspaRequest {
        customer_asn: 64496,
        provider_asns: vec![64498, 64497],
    };
    let bytes = ca.sign_aspa(&request, "customer.asa").unwrap();
    let object = Aspa::decode(bytes.as_slice(), true).unwrap();
    let expected_name = publication::key_filename(&object.cert().subject_key_identifier(), "asa");
    let resource_cert = Cert::decode(
        fs::read(repository_file(dir.path(), "cer"))
            .unwrap()
            .as_slice(),
    )
    .unwrap()
    .validate_ta(TalInfo::from_name("test".into()).into_arc(), true)
    .unwrap();
    object.process(&resource_cert, true, |_| Ok(())).unwrap();
    let crl = Crl::decode(
        fs::read(repository_file(dir.path(), "crl"))
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    crl.verify_signature(resource_cert.subject_public_key_info())
        .unwrap();
    let manifest = Manifest::decode(
        fs::read(repository_file(dir.path(), "mft"))
            .unwrap()
            .as_slice(),
        true,
    )
    .unwrap();
    let (_, content) = manifest.validate(&resource_cert, true).unwrap();
    let state = LocalStateStore::new(dir.path()).load().unwrap();
    let aspa_name = state.published_name("aspa:AS64496").unwrap().to_owned();
    assert_eq!(aspa_name, expected_name);
    assert!(
        content
            .iter()
            .any(|entry| entry.file().as_ref() == aspa_name.as_bytes())
    );
    assert!(state.object(&aspa_name).is_some());

    let serial = state.object(&aspa_name).unwrap().serial;
    assert!(ca.withdraw_aspa(64496).unwrap());
    assert!(!ca.withdraw_aspa(64496).unwrap());
    assert!(!dir.path().join("repository").join(&aspa_name).exists());
    let crl = Crl::decode(
        fs::read(repository_file(dir.path(), "crl"))
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    assert!(crl.contains(serial.into()));
    let manifest = Manifest::decode(
        fs::read(repository_file(dir.path(), "mft"))
            .unwrap()
            .as_slice(),
        true,
    )
    .unwrap();
    let (_, content) = manifest.validate(&resource_cert, true).unwrap();
    assert!(
        !content
            .iter()
            .any(|entry| entry.file().as_ref() == aspa_name.as_bytes())
    );
}
