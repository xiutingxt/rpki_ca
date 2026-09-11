use super::*;
use rpki::crypto::KeyIdentifier;

#[test]
fn encodes_rfc_6481_key_identifier_filename() {
    let key = KeyIdentifier::try_from(&[0u8; 20][..]).unwrap();
    let basename = key_identifier_basename(&key);
    assert_eq!(basename, "AAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert_eq!(basename.len(), 27);
    assert_eq!(key_filename(&key, "crl"), format!("{basename}.crl"));
}
