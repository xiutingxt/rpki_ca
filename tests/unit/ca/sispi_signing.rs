use super::*;
use crate::{
    ca::signed_objects::sispi::object::Sispi, infrastructure::state_store::LocalStateStore,
};
use rpki::repository::{cert::Cert, tal::TalInfo};
use std::fs;

#[test]
fn sispi_batch_replay_does_not_reissue_objects() {
    let dir = tempfile::tempdir().unwrap();
    let config = CaConfig {
        development_asns: vec![64496],
        ..CaConfig::default()
    };
    let ca = crate::CaManager::init(dir.path(), config).unwrap();
    let delta = crate::SispiDelta {
        added: vec![SispiRequest {
            as_id: 64496,
            addresses: vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
        }],
        removed: vec![],
    };
    let first = ca.update_sispis(delta.clone()).unwrap();
    let first_object = first.objects[0].clone();
    let replay = ca.update_sispis(delta).unwrap();
    assert_eq!(replay.unchanged, vec!["sispi:AS64496"]);
    assert_eq!(replay.objects[0].object_name, first_object.object_name);
    assert_eq!(
        replay.objects[0].ee_certificate_serial,
        first_object.ee_certificate_serial
    );

    let withdrawn = ca
        .update_sispis(crate::SispiDelta {
            added: vec![],
            removed: vec![64496],
        })
        .unwrap();
    assert_eq!(withdrawn.removed, vec!["sispi:AS64496"]);
    assert!(withdrawn.objects.is_empty());
    let replay_withdrawal = ca
        .update_sispis(crate::SispiDelta {
            added: vec![],
            removed: vec![64496],
        })
        .unwrap();
    assert_eq!(replay_withdrawal.unchanged, vec!["sispi:AS64496"]);
}

#[test]
fn signs_and_validates_draft_sispi_publication() {
    let dir = tempfile::tempdir().unwrap();
    let config = CaConfig {
        development_asns: vec![64496],
        ..CaConfig::default()
    };
    let ca = crate::CaManager::init(dir.path(), config).unwrap();
    let request = SispiRequest {
        as_id: 64496,
        addresses: vec![
            "2001:db8::1".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
        ],
    };
    let bytes = ca.sign_sispi(&request, "test.sav").unwrap();
    let object = Sispi::decode(bytes.clone().into()).unwrap();
    assert_eq!(object.to_captured().as_slice(), bytes.as_slice());
    assert!(object.cert().as_resources().is_present());
    assert!(!object.cert().as_resources().is_inherited());
    assert!(!object.cert().has_ip_resources());

    let cert_path = fs::read_dir(dir.path().join("repository"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().and_then(|value| value.to_str()) == Some("cer"))
        .unwrap();
    let issuer = Cert::decode(fs::read(cert_path).unwrap().as_slice())
        .unwrap()
        .validate_ta(TalInfo::from_name("test".into()).into_arc(), true)
        .unwrap();
    let object_ski = object.cert().subject_key_identifier();
    let (ee, content) = object.process(&issuer, |_| Ok(())).unwrap();
    assert_eq!(content.as_id(), 64496.into());
    assert_eq!(
        content.v4_addresses(),
        &[rpki::repository::resources::Prefix::new(
            "192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap(),
            32,
        )]
    );
    assert_eq!(
        content.v6_addresses(),
        &[rpki::repository::resources::Prefix::new(
            "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap(),
            128,
        )]
    );
    assert_eq!(ee.subject_key_identifier(), object_ski);

    let state = LocalStateStore::new(dir.path()).load().unwrap();
    let name = state.published_name("sispi:AS64496").unwrap();
    assert_eq!(
        name,
        publication::key_filename(
            &Sispi::decode(
                fs::read(dir.path().join("repository").join(name))
                    .unwrap()
                    .into(),
            )
            .unwrap()
            .cert()
            .subject_key_identifier(),
            "sav",
        )
    );
}

#[test]
fn rejects_sispi_as_id_outside_ca_resources() {
    let dir = tempfile::tempdir().unwrap();
    let config = CaConfig {
        development_asns: vec![64496],
        ..CaConfig::default()
    };
    let ca = crate::CaManager::init(dir.path(), config).unwrap();
    let error = ca
        .sign_sispi(
            &SispiRequest {
                as_id: 64497,
                addresses: vec!["192.0.2.1".parse().unwrap()],
            },
            "test.sav",
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("AS64497"));
}
