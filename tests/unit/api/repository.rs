use super::*;

#[test]
fn classifies_registered_repository_extensions() {
    assert_eq!(kind("example.cer"), "ca_certificate");
    assert_eq!(kind("example.crl"), "crl");
    assert_eq!(kind("example.mft"), "manifest");
    assert_eq!(kind("example.roa"), "roa");
    assert_eq!(kind("example.asa"), "aspa");
    assert_eq!(kind("example.toa"), "toa");
    assert_eq!(kind("example.sav"), "sispi");
    assert_eq!(kind("example.bin"), "unknown");
}

#[test]
fn summary_contains_stable_urls_and_digest() {
    let summary = summarize("example.roa".into(), b"object", true);
    assert_eq!(summary.kind, "roa");
    assert_eq!(summary.size, 6);
    assert_eq!(summary.download_url, "/repository/example.roa");
    assert_eq!(
        summary.inspect_url,
        "/api/v1/repository/objects/example.roa"
    );
    assert_eq!(summary.sha256.len(), 64);
    assert_eq!(
        summary.withdraw_url.as_deref(),
        Some("/api/v1/signed-objects/example.roa")
    );
    assert!(
        summarize("example.crl".into(), b"crl", false)
            .withdraw_url
            .is_none()
    );
}

#[test]
fn formats_full_sispi_addresses_without_cidr_suffix() {
    assert_eq!(
        format_prefix(
            rpki::repository::resources::Prefix::new(
                "192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap(),
                32,
            ),
            true,
            true,
        ),
        "192.0.2.1"
    );
    assert_eq!(
        format_prefix(
            rpki::repository::resources::Prefix::new(
                "192.0.2.0".parse::<std::net::Ipv4Addr>().unwrap(),
                24,
            ),
            true,
            true,
        ),
        "192.0.2.0/24"
    );
}

#[test]
fn uses_profile_field_names_for_toa_and_sispi_address_families() {
    let v4 = [rpki::repository::resources::Prefix::new(
        "192.0.2.0".parse::<std::net::Ipv4Addr>().unwrap(),
        24,
    )];
    let v6 = [rpki::repository::resources::Prefix::new(
        "2001:db8::".parse::<std::net::Ipv6Addr>().unwrap(),
        48,
    )];
    let toa = prefix_address_families(&v4, &v6, "addressFamily", "addresses", false);
    assert_eq!(toa[0]["addressFamily"], "0001");
    assert_eq!(toa[0]["addresses"][0], "192.0.2.0/24");
    assert!(toa[0].get("ipFamily").is_none());

    let sispi = prefix_address_families(&v4, &v6, "ipFamily", "ipAddresses", true);
    assert_eq!(sispi[1]["ipFamily"], "0002");
    assert_eq!(sispi[1]["ipAddresses"][0], "2001:db8::/48");
    assert!(sispi[1].get("addressFamily").is_none());
}

#[test]
fn maps_resource_certificate_profiles_to_their_registered_oids() {
    let strict = resource_certificate_profile(Overclaim::Refuse);
    assert_eq!(strict.name, "rfc6487");
    assert_eq!(strict.policy_oid, "1.3.6.1.5.5.7.14.2");
    assert_eq!(strict.ip_resources_oid, "1.3.6.1.5.5.7.1.7");
    assert_eq!(strict.as_resources_oid, "1.3.6.1.5.5.7.1.8");

    let trimming = resource_certificate_profile(Overclaim::Trim);
    assert_eq!(trimming.name, "rfc8360");
    assert_eq!(trimming.policy_oid, "1.3.6.1.5.5.7.14.3");
    assert_eq!(trimming.ip_resources_oid, "1.3.6.1.5.5.7.1.28");
    assert_eq!(trimming.as_resources_oid, "1.3.6.1.5.5.7.1.29");
}
