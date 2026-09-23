use super::*;
use crate::{ca::signed_objects::toa::object::Toa, infrastructure::state_store::LocalStateStore};
use rpki::repository::{cert::Cert, tal::TalInfo};
use std::fs;

#[test]
fn signs_and_validates_draft_toa_publication() {
    let dir = tempfile::tempdir().unwrap();
    let ca = crate::CaManager::init(dir.path(), CaConfig::default()).unwrap();
    let request = ToaRequest {
        asns: vec![u32::MAX, 0, 64496, 64496],
        prefixes: vec![
            "2001:db8::/48".parse().unwrap(),
            "192.0.2.0/24".parse().unwrap(),
        ],
        roa_overlap_justification: None,
    };
    let logical_key = crate::ObjectDefinition::Toa(request.clone())
        .canonicalized()
        .logical_key();
    let bytes = ca.sign_toa(&request, "test.toa").unwrap();
    let object = Toa::decode(bytes.clone().into()).unwrap();
    assert_eq!(object.to_captured().as_slice(), bytes.as_slice());
    assert!(!object.cert().as_resources().is_present());
    assert!(!object.cert().v4_resources().is_inherited());
    assert!(!object.cert().v6_resources().is_inherited());
    let cert_path = fs::read_dir(dir.path().join("repository"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().and_then(|v| v.to_str()) == Some("cer"))
        .unwrap();
    let issuer = Cert::decode(fs::read(cert_path).unwrap().as_slice())
        .unwrap()
        .validate_ta(TalInfo::from_name("test".into()).into_arc(), true)
        .unwrap();
    let object_ski = object.cert().subject_key_identifier();
    let (ee, content) = object.process(&issuer, |_| Ok(())).unwrap();
    assert_eq!(content.asns(), &[0.into(), 64496.into(), u32::MAX.into()]);
    assert_eq!(ee.subject_key_identifier(), object_ski);
    let state = LocalStateStore::new(dir.path()).load().unwrap();
    let name = state.published_name(&logical_key).unwrap();
    assert_eq!(
        name,
        publication::key_filename(
            &Toa::decode(
                fs::read(dir.path().join("repository").join(name))
                    .unwrap()
                    .into()
            )
            .unwrap()
            .cert()
            .subject_key_identifier(),
            "toa"
        )
    );
}

#[test]
fn enforces_roa_overlap_exception_and_tracks_periodic_review() {
    let dir = tempfile::tempdir().unwrap();
    let ca = crate::CaManager::init(dir.path(), CaConfig::default()).unwrap();
    ca.sign_roa(
        &RoaRequest {
            asn: 64496,
            prefixes: vec![crate::RoaPayload {
                prefix: "192.0.2.0/24".parse().unwrap(),
                max_length: Some(26),
            }],
        },
        "route-origin.roa",
    )
    .unwrap();
    let request = ToaRequest {
        asns: vec![64496],
        prefixes: vec!["192.0.2.0/25".parse().unwrap()],
        roa_overlap_justification: None,
    };
    let error = ca.sign_toa(&request, "traffic-origin.toa").unwrap_err();
    assert!(error.to_string().contains("roa_overlap_justification"));

    let mut allowed = request;
    allowed.roa_overlap_justification = Some("separate traffic-origin workflow".into());
    let output = ca
        .sign_object(ObjectDefinition::Toa(allowed), "traffic-origin.toa")
        .unwrap();
    assert_eq!(output.advisories.len(), 1);
    let statuses = ca.toa_review_statuses().unwrap();
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].object_name, output.name);
    assert!(!statuses[0].overdue);
    assert_eq!(statuses[0].roa_covered_pairs, 1);
    assert!(ca.review_toa(&output.name, None).is_err());
    assert!(
        ca.review_toa(&output.name, Some("reviewed exception".into()))
            .is_ok()
    );
}
