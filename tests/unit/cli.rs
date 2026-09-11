use super::*;

#[test]
fn parses_direct_roa_prefixes() {
    let plain = "192.0.2.0/24".parse::<CliRoaPayload>().unwrap().0;
    assert_eq!(plain.prefix, "192.0.2.0/24".parse::<IpNet>().unwrap());
    assert_eq!(plain.max_length, None);
    assert_eq!(
        "2001:db8::/48,64"
            .parse::<CliRoaPayload>()
            .unwrap()
            .0
            .max_length,
        Some(64)
    );
}
