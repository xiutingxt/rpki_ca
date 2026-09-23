use super::*;

#[test]
fn logical_keys_use_profile_identity_and_canonical_content() {
    let first = ObjectDefinition::Aspa(crate::AspaRequest {
        customer_asn: 64496,
        provider_asns: vec![64500, 64499],
    })
    .canonicalized();
    let reordered = ObjectDefinition::Aspa(crate::AspaRequest {
        customer_asn: 64496,
        provider_asns: vec![64499, 64500],
    })
    .canonicalized();
    assert_eq!(first.logical_key(), reordered.logical_key());

    let toa = crate::ToaRequest {
        asns: vec![64497, 64496],
        prefixes: vec!["192.0.2.0/24".parse().unwrap()],
        roa_overlap_justification: None,
    };
    let mut reviewed = toa.clone();
    reviewed.roa_overlap_justification = Some("operational exception".into());
    assert_eq!(
        ObjectDefinition::Toa(toa).canonicalized().logical_key(),
        ObjectDefinition::Toa(reviewed)
            .canonicalized()
            .logical_key()
    );
}
