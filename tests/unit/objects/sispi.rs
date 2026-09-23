use super::*;

#[test]
fn validates_and_canonicalizes_sispi_addresses() {
    let request = SispiRequest {
        as_id: 64496,
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
            as_id: 64496,
            addresses: Vec::new(),
        }
        .validate()
        .is_err()
    );
}
