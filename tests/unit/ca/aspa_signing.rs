use super::*;
use crate::infrastructure::state_store::LocalStateStore;
use rpki::repository::{aspa::Aspa, cert::Cert, crl::Crl, manifest::Manifest, tal::TalInfo};
use std::fs;

#[test]
fn batch_update_is_idempotent_and_supports_replacement_and_removal() {
    let dir = tempfile::tempdir().unwrap();
    let config = CaConfig {
        development_asns: vec![64496, 64497],
        ..CaConfig::default()
    };
    let ca = crate::CaManager::init(dir.path(), config).unwrap();
    let initial = crate::AspaDelta {
        added: vec![
            AspaRequest {
                customer_asn: 64496,
                provider_asns: vec![64500],
            },
            AspaRequest {
                customer_asn: 64497,
                provider_asns: vec![64501],
            },
        ],
        removed: vec![],
    };
    let created = ca.update_aspas(initial.clone()).unwrap();
    assert_eq!(created.created, vec!["aspa:AS64496", "aspa:AS64497"]);
    let names: Vec<_> = created
        .objects
        .iter()
        .map(|object| object.object_name.clone())
        .collect();

    let replay = ca.update_aspas(initial).unwrap();
    assert!(replay.created.is_empty());
    assert_eq!(replay.unchanged, vec!["aspa:AS64496", "aspa:AS64497"]);
    assert_eq!(
        replay
            .objects
            .iter()
            .map(|object| object.object_name.clone())
            .collect::<Vec<_>>(),
        names
    );

    let changed = ca
        .update_aspas(crate::AspaDelta {
            added: vec![AspaRequest {
                customer_asn: 64496,
                provider_asns: vec![64502],
            }],
            removed: vec![64497, 64555],
        })
        .unwrap();
    assert_eq!(changed.updated, vec!["aspa:AS64496"]);
    assert_eq!(changed.removed, vec!["aspa:AS64497"]);
    assert_eq!(changed.unchanged, vec!["aspa:AS64555"]);
    assert_eq!(changed.objects.len(), 1);
}

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
    let withdrawal = ca.withdraw_published_object(&aspa_name).unwrap().unwrap();
    assert_eq!(withdrawal.object_name, aspa_name);
    assert_eq!(withdrawal.kind, ObjectKind::Aspa);
    assert_eq!(withdrawal.ee_certificate_serial, serial);
    assert!(withdrawal.ee_certificate_revoked);
    assert!(withdrawal.revocation_time.is_some());
    assert!(
        ca.withdraw_published_object(&withdrawal.object_name)
            .unwrap()
            .is_none()
    );
    assert!(!dir.path().join("repository").join(&aspa_name).exists());
    let crl = Crl::decode(
        fs::read(repository_file(dir.path(), "crl"))
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    assert!(crl.contains(serial.into()));
    assert_eq!(crl.crl_number(), withdrawal.crl_number.into());
    let manifest = Manifest::decode(
        fs::read(repository_file(dir.path(), "mft"))
            .unwrap()
            .as_slice(),
        true,
    )
    .unwrap();
    let (_, content) = manifest.validate(&resource_cert, true).unwrap();
    assert_eq!(content.manifest_number(), withdrawal.manifest_number.into());
    assert!(
        !content
            .iter()
            .any(|entry| entry.file().as_ref() == aspa_name.as_bytes())
    );
}
