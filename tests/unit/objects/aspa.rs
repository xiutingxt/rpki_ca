use super::*;

#[test]
fn validates_and_canonicalizes_profile_values() {
    let request = AspaRequest {
        customer_asn: 64496,
        provider_asns: vec![64498, 64497, 64498],
    };
    request.validate().unwrap();
    assert_eq!(request.canonical_providers(), vec![64497, 64498]);
    assert!(
        AspaRequest {
            customer_asn: 0,
            provider_asns: vec![64497]
        }
        .validate()
        .is_err()
    );
    assert!(
        AspaRequest {
            customer_asn: 64496,
            provider_asns: vec![64496]
        }
        .validate()
        .is_err()
    );
    assert!(
        AspaRequest {
            customer_asn: 64496,
            provider_asns: vec![0, 64497]
        }
        .validate()
        .is_err()
    );
}
