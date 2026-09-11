use super::*;

#[test]
fn validates_external_identifiers() {
    assert!(validate_idempotency_key("frontend:request-1").is_ok());
    assert!(validate_idempotency_key("../escape").is_err());
    assert!(valid_object_name("roa-abc.roa"));
    assert!(!valid_object_name("../ca.key"));
    assert_ne!(
        idempotency_id(ObjectKind::Roa, "same-request"),
        idempotency_id(ObjectKind::Aspa, "same-request")
    );
}
