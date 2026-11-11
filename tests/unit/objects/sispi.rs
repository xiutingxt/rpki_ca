use super::*;

#[test]
fn requires_asn_without_legacy_aliases() {
    let request: SispiRequest =
        serde_json::from_str(r#"{"asn":64496,"addresses":["192.0.2.1"]}"#).unwrap();
    assert_eq!(request.asn, 64496);
    let encoded = serde_json::to_value(&request).unwrap();
    assert_eq!(encoded["asn"], 64496);
    assert!(encoded.get("as_id").is_none());
    assert!(toml::to_string(&request).unwrap().contains("asn = 64496"));
    assert!(
        serde_json::from_str::<SispiRequest>(r#"{"as_id":64496,"addresses":["192.0.2.1"]}"#,)
            .is_err()
    );
    assert!(
        serde_json::from_str::<SispiRequest>(
            r#"{"asn":64496,"as_id":64496,"addresses":["192.0.2.1"]}"#,
        )
        .is_err()
    );
    assert!(
        toml::from_str::<SispiRequest>("as_id = 64496\naddresses = [\"192.0.2.1\"]\n",).is_err()
    );
}

#[test]
fn validates_and_canonicalizes_sispi_addresses() {
    let request = SispiRequest {
        asn: 64496,
        addresses: vec![
            "2001:db8::1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
        ],
    };
    request.validate().unwrap();
    assert_eq!(
        request.canonical_addresses(),
        vec![
            "192.0.2.1".parse::<IpAddr>().unwrap(),
            "192.0.2.2".parse::<IpAddr>().unwrap(),
            "2001:db8::1".parse::<IpAddr>().unwrap(),
        ]
    );
}

#[test]
fn rejects_empty_savnet_agent_address_list() {
    assert!(
        SispiRequest {
            asn: 64496,
            addresses: Vec::new(),
        }
        .validate()
        .is_err()
    );
}
