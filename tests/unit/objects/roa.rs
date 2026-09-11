use super::*;

#[test]
fn rejects_invalid_max_length() {
    let request = RoaRequest {
        asn: 64496,
        prefixes: vec![RoaPayload {
            prefix: "192.0.2.0/24".parse().unwrap(),
            max_length: Some(23),
        }],
    };
    assert!(request.validate().is_err());
}

#[test]
fn produces_rfc_9582_canonical_order() {
    let request = RoaRequest {
        asn: 0,
        prefixes: vec![
            RoaPayload {
                prefix: "2001:db8::/48".parse().unwrap(),
                max_length: Some(48),
            },
            RoaPayload {
                prefix: "192.0.2.0/24".parse().unwrap(),
                max_length: Some(24),
            },
            RoaPayload {
                prefix: "192.0.2.0/24".parse().unwrap(),
                max_length: None,
            },
        ],
    };
    request.validate().unwrap();
    let values = request.canonical_prefixes();
    assert_eq!(values.len(), 2);
    assert_eq!(values[0].prefix.to_string(), "192.0.2.0/24");
    assert_eq!(values[0].max_length, None);
}
