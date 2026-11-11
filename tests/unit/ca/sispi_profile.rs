use super::*;
use bytes::Bytes;

fn decode_content(bytes: Bytes) -> anyhow::Result<SispiContent> {
    Ok(Mode::Der.decode(bytes, SispiContent::take_from)?)
}

#[test]
fn roundtrips_ipv4_and_ipv6_addresses() {
    let content = SispiContent::new(
        64496.into(),
        vec![Prefix::new(
            "192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap(),
            32,
        )],
        vec![Prefix::new(
            "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap(),
            128,
        )],
    );
    let bytes = content.encode_ref().to_captured(Mode::Der).into_bytes();
    let decoded = decode_content(bytes).unwrap();
    assert_eq!(decoded.asn(), 64496.into());
    assert_eq!(
        decoded.v4_addresses(),
        &[Prefix::new(
            "192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap(),
            32,
        )]
    );
    assert_eq!(
        decoded.v6_addresses(),
        &[Prefix::new(
            "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap(),
            128,
        )]
    );
}

#[test]
fn accepts_address_prefix_length_per_draft_asn1() {
    let prefix: ipnet::IpNet = "192.0.2.0/24".parse().unwrap();
    let bytes = encode::sequence((
        Asn::from(64496).encode(),
        encode::sequence((encode_family(
            AddressFamily::Ipv4,
            &[Prefix::new(prefix.addr(), prefix.prefix_len())],
        ),)),
    ))
    .to_captured(Mode::Der)
    .into_bytes();
    let decoded = decode_content(bytes).unwrap();
    assert_eq!(
        decoded.v4_addresses(),
        &[Prefix::new(prefix.addr(), prefix.prefix_len())]
    );
    assert_eq!(decoded.v6_addresses(), &[]);
}

#[test]
fn rejects_explicit_default_version_and_empty_addresses() {
    let prefix: ipnet::IpNet = "192.0.2.1/32".parse().unwrap();
    let explicit_default = encode::sequence((
        encode::sequence_as(Tag::CTX_0, 0u8.encode()),
        Asn::from(64496).encode(),
        encode::sequence((encode_family(
            AddressFamily::Ipv4,
            &[Prefix::new(prefix.addr(), prefix.prefix_len())],
        ),)),
    ))
    .to_captured(Mode::Der)
    .into_bytes();
    assert!(decode_content(explicit_default).is_err());

    let empty = encode::sequence((
        Asn::from(64496).encode(),
        encode::sequence(bcder::Captured::empty(Mode::Der)),
    ))
    .to_captured(Mode::Der)
    .into_bytes();
    assert!(decode_content(empty).is_err());
}
