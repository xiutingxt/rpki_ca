use super::*;

#[test]
fn validates_and_canonicalizes_toa_profile() {
    let request = ToaRequest {
        asns: vec![u32::MAX, 0, 64496, 64496],
        prefixes: vec![
            "2001:db8::/48".parse().unwrap(),
            "192.0.2.0/25".parse().unwrap(),
            "192.0.2.0/24".parse().unwrap(),
            "192.0.2.0/24".parse().unwrap(),
        ],
        roa_overlap_justification: None,
    };
    request.validate().unwrap();
    assert_eq!(request.canonical_asns(), vec![0, 64496, u32::MAX]);
    assert_eq!(
        request.canonical_prefixes(),
        vec![
            "192.0.2.0/24".parse().unwrap(),
            "192.0.2.0/25".parse().unwrap(),
            "2001:db8::/48".parse().unwrap(),
        ]
    );
}

#[test]
fn rejects_empty_sets_and_host_bits() {
    assert!(
        ToaRequest {
            asns: vec![],
            prefixes: vec!["192.0.2.0/24".parse().unwrap()],
            roa_overlap_justification: None,
        }
        .validate()
        .is_err()
    );
    assert!(
        ToaRequest {
            asns: vec![64496],
            prefixes: vec![],
            roa_overlap_justification: None,
        }
        .validate()
        .is_err()
    );
    let host = ipnet::IpNet::new("192.0.2.1".parse().unwrap(), 24).unwrap();
    let error = ToaRequest {
        asns: vec![64496],
        prefixes: vec![host],
        roa_overlap_justification: None,
    }
    .validate()
    .unwrap_err()
    .to_string();
    assert!(error.contains("192.0.2.0/24"));
    assert!(error.contains("主机位必须全部为 0"));
}

#[test]
fn applies_asn_limit_after_canonicalization() {
    let request = ToaRequest {
        asns: vec![64496; 10_001],
        prefixes: vec!["192.0.2.0/24".parse().unwrap()],
        roa_overlap_justification: None,
    };
    request.validate().unwrap();
    assert_eq!(request.canonical_asns(), vec![64496]);
}
