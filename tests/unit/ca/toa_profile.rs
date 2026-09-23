use super::*;
use bytes::Bytes;

fn decode_content(bytes: Bytes) -> anyhow::Result<ToaContent> {
    Ok(Mode::Der.decode(bytes, ToaContent::take_from)?)
}

#[test]
fn preserves_ipv6_family_for_prefixes_shorter_than_32_bits() {
    let prefix: ipnet::IpNet = "2000::/20".parse().unwrap();
    let rpki_prefix = Prefix::new(prefix.addr(), prefix.prefix_len());
    let content = ToaContent::new(vec![64496.into()], Vec::new(), vec![rpki_prefix]);
    let bytes = content.encode_ref().to_captured(Mode::Der).into_bytes();
    let decoded = decode_content(bytes).unwrap();

    assert_eq!(decoded.v4_prefixes(), &[]);
    assert_eq!(decoded.v6_prefixes(), &[rpki_prefix]);
    assert!(!decoded.v4_resources().is_present());
    assert!(decoded.v6_resources().is_present());
}

#[test]
fn rejects_non_increasing_as_set() {
    let prefix: ipnet::IpNet = "192.0.2.0/24".parse().unwrap();
    let bytes = encode::sequence((
        encode::sequence((Asn::from(2).encode(), Asn::from(1).encode())),
        encode::sequence((encode_family(
            AddressFamily::Ipv4,
            &[Prefix::new(prefix.addr(), prefix.prefix_len())],
        ),)),
    ))
    .to_captured(Mode::Der)
    .into_bytes();
    assert!(decode_content(bytes).is_err());
}

#[test]
fn rejects_duplicate_prefixes_and_empty_families() {
    let prefix: ipnet::IpNet = "192.0.2.0/24".parse().unwrap();
    let duplicate = encode::sequence((
        encode::sequence((Asn::from(1).encode(),)),
        encode::sequence((encode_family(
            AddressFamily::Ipv4,
            &[
                Prefix::new(prefix.addr(), prefix.prefix_len()),
                Prefix::new(prefix.addr(), prefix.prefix_len()),
            ],
        ),)),
    ))
    .to_captured(Mode::Der)
    .into_bytes();
    assert!(decode_content(duplicate).is_err());

    let empty = encode::sequence((
        encode::sequence((Asn::from(1).encode(),)),
        encode::sequence((encode::sequence((
            AddressFamily::Ipv4.encode(),
            encode::sequence(bcder::Captured::empty(Mode::Der)),
        )),)),
    ))
    .to_captured(Mode::Der)
    .into_bytes();
    assert!(decode_content(empty).is_err());
}

#[test]
fn rejects_explicit_default_version_in_der() {
    let prefix: ipnet::IpNet = "192.0.2.0/24".parse().unwrap();
    let bytes = encode::sequence((
        encode::sequence_as(Tag::CTX_0, 0u8.encode()),
        encode::sequence((Asn::from(1).encode(),)),
        encode::sequence((encode_family(
            AddressFamily::Ipv4,
            &[Prefix::new(prefix.addr(), prefix.prefix_len())],
        ),)),
    ))
    .to_captured(Mode::Der)
    .into_bytes();
    assert!(decode_content(bytes).is_err());
}
