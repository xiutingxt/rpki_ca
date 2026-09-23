use super::*;

#[test]
fn replaces_aspa_by_customer_logical_key_and_withdraws_old_name() {
    let mut state = CaState::new(1).unwrap();
    let first = IssuedObject {
        kind: ObjectKind::Aspa,
        logical_key: "aspa:AS64496".into(),
        name: "old.asa".into(),
        definition: Some(crate::ObjectDefinition::Aspa(crate::AspaRequest {
            customer_asn: 64496,
            provider_asns: vec![64497],
        })),
        ee: IssuedEe {
            serial: 1,
            not_after: 100,
        },
        toa_review: None,
    };
    assert_eq!(state.replace_object(first, 10), None);
    let replacement = IssuedObject {
        kind: ObjectKind::Aspa,
        logical_key: "aspa:AS64496".into(),
        name: "new.asa".into(),
        definition: Some(crate::ObjectDefinition::Aspa(crate::AspaRequest {
            customer_asn: 64496,
            provider_asns: vec![64498],
        })),
        ee: IssuedEe {
            serial: 2,
            not_after: 100,
        },
        toa_review: None,
    };
    assert_eq!(
        state.replace_object(replacement, 20).as_deref(),
        Some("old.asa")
    );
    assert_eq!(state.revocations().next().unwrap().serial, 1);
    assert!(state.object("old.asa").is_none());
    assert_eq!(state.object("new.asa").unwrap().serial, 2);
    assert_eq!(
        state
            .remove_object("aspa:AS64496", 30)
            .map(|object| object.name),
        Some("new.asa".into())
    );
    assert!(state.object("new.asa").is_none());
}
