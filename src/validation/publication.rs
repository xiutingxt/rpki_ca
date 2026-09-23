//! Object-specific validation layered on the common publication-set checks.

use super::publication_set::PublicationSet;
use crate::ca::signed_objects::{sispi::object::Sispi, toa::object::Toa};
use crate::ca::state::CaStateStore;
use crate::infrastructure::{repository::LocalRepository, state_store::LocalStateStore};
use anyhow::{Result, ensure};
use rpki::repository::{
    aspa::Aspa,
    resources::{Asn, Prefix},
    roa::Roa,
};
use std::net::IpAddr;
use std::{
    collections::{BTreeSet, HashSet},
    path::Path,
};

pub fn verify_roa_publication(
    ca_dir: &Path,
    roa_name: &str,
    expected_asn: u32,
    expected_payloads: &[String],
) -> Result<Vec<String>> {
    validate_name(roa_name, "roa")?;
    let repository = LocalRepository::new(ca_dir);
    let state = LocalStateStore::new(ca_dir).load()?;
    let publication = PublicationSet::load(&repository, state.validation_context())?;
    let path = ca_dir.join("repository").join(roa_name);
    let roa = Roa::decode(std::fs::read(&path)?.as_slice(), true)?;
    let bytes = publication.validate_object(roa_name, roa.cert(), "roa")?;
    let roa = Roa::decode(bytes.as_slice(), true)?;
    let (_, content) = roa
        .process(&publication.ca, true, |_| Ok(()))
        .map_err(|error| anyhow::anyhow!("ROA validation failed: {error}"))?;
    ensure!(
        u32::from(content.as_id()) == expected_asn,
        "origin ASN mismatch"
    );
    let actual = content
        .iter()
        .map(|item| {
            format!(
                "{}/{}-{}",
                item.address(),
                item.address_length(),
                item.max_length()
            )
        })
        .collect::<BTreeSet<_>>();
    let expected = expected_payloads.iter().cloned().collect::<BTreeSet<_>>();
    ensure!(
        actual == expected,
        "ROA payload mismatch: expected {expected:?}, got {actual:?}"
    );
    Ok(vec![
        "CA certificate, current CRL, and current Manifest valid".into(),
        format!("ROA: CMS, EE certificate, ASN {expected_asn}, and payloads valid"),
        "Manifest: complete file hashes and selected CRL valid".into(),
    ])
}

pub fn verify_aspa_publication(
    ca_dir: &Path,
    aspa_name: &str,
    customer_asn: u32,
    expected_providers: &[u32],
) -> Result<Vec<String>> {
    validate_name(aspa_name, "asa")?;
    let repository = LocalRepository::new(ca_dir);
    let state = LocalStateStore::new(ca_dir).load()?;
    let publication = PublicationSet::load(&repository, state.validation_context())?;
    let path = ca_dir.join("repository").join(aspa_name);
    let aspa = Aspa::decode(std::fs::read(&path)?.as_slice(), true)?;
    let bytes = publication.validate_object(aspa_name, aspa.cert(), "asa")?;
    let aspa = Aspa::decode(bytes.as_slice(), true)?;
    let (_, content) = aspa
        .process(&publication.ca, true, |_| Ok(()))
        .map_err(|error| anyhow::anyhow!("ASPA validation failed: {error}"))?;
    ensure!(
        u32::from(content.customer_as()) == customer_asn,
        "customer ASN mismatch"
    );
    let actual = content
        .provider_as_set()
        .iter()
        .map(u32::from)
        .collect::<BTreeSet<_>>();
    let expected = expected_providers.iter().copied().collect::<BTreeSet<_>>();
    ensure!(
        actual == expected,
        "provider ASN mismatch: expected {expected:?}, got {actual:?}"
    );
    Ok(vec![
        "CA certificate, current CRL, and current Manifest valid".into(),
        format!("ASPA: CMS, EE certificate, customer AS{customer_asn}, and providers valid"),
        "Manifest: complete file hashes and selected CRL valid".into(),
    ])
}

pub fn verify_toa_publication(
    ca_dir: &Path,
    toa_name: &str,
    expected_asns: &[u32],
    expected_prefixes: &[ipnet::IpNet],
) -> Result<Vec<String>> {
    validate_name(toa_name, "toa")?;
    let repository = LocalRepository::new(ca_dir);
    let state = LocalStateStore::new(ca_dir).load()?;
    let publication = PublicationSet::load(&repository, state.validation_context())?;
    let path = ca_dir.join("repository").join(toa_name);
    let toa = Toa::decode(std::fs::read(&path)?.into())?;
    let bytes = publication.validate_object(toa_name, toa.cert(), "toa")?;
    let toa = Toa::decode(bytes.into())?;
    let (_, content) = toa
        .process(&publication.ca, |_| Ok(()))
        .map_err(|error| anyhow::anyhow!("TOA validation failed: {error}"))?;
    ensure!(
        content.asns().iter().copied().collect::<BTreeSet<_>>()
            == expected_asns.iter().copied().map(Asn::from).collect(),
        "TOA AS set mismatch"
    );
    let expected_v4 = expected_prefixes
        .iter()
        .filter(|prefix| prefix.addr().is_ipv4())
        .map(|prefix| Prefix::new(prefix.addr(), prefix.prefix_len()))
        .collect::<HashSet<_>>();
    let expected_v6 = expected_prefixes
        .iter()
        .filter(|prefix| prefix.addr().is_ipv6())
        .map(|prefix| Prefix::new(prefix.addr(), prefix.prefix_len()))
        .collect::<HashSet<_>>();
    ensure!(
        content
            .v4_prefixes()
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            == expected_v4
            && content
                .v6_prefixes()
                .iter()
                .copied()
                .collect::<HashSet<_>>()
                == expected_v6,
        "TOA prefix set mismatch"
    );
    Ok(vec![
        "CA certificate, current CRL, and current Manifest valid".into(),
        "TOA CMS, profile, EE resources, ASN set, and prefixes valid".into(),
        "Manifest: complete file hashes and selected CRL valid".into(),
    ])
}

pub fn verify_sispi_publication(
    ca_dir: &Path,
    sispi_name: &str,
    expected_as_id: u32,
    expected_addresses: &[IpAddr],
) -> Result<Vec<String>> {
    validate_name(sispi_name, "sav")?;
    let repository = LocalRepository::new(ca_dir);
    let state = LocalStateStore::new(ca_dir).load()?;
    let publication = PublicationSet::load(&repository, state.validation_context())?;
    let path = ca_dir.join("repository").join(sispi_name);
    let sispi = Sispi::decode(std::fs::read(&path)?.into())?;
    let bytes = publication.validate_object(sispi_name, sispi.cert(), "sav")?;
    let sispi = Sispi::decode(bytes.into())?;
    let (_, content) = sispi
        .process(&publication.ca, |_| Ok(()))
        .map_err(|error| anyhow::anyhow!("SiSPI validation failed: {error}"))?;
    ensure!(
        content.as_id() == Asn::from(expected_as_id),
        "SiSPI AS ID mismatch"
    );
    let expected_v4 = expected_addresses
        .iter()
        .filter_map(|address| match address {
            IpAddr::V4(address) => Some(Prefix::new(*address, 32)),
            IpAddr::V6(_) => None,
        })
        .collect::<HashSet<_>>();
    let expected_v6 = expected_addresses
        .iter()
        .filter_map(|address| match address {
            IpAddr::V4(_) => None,
            IpAddr::V6(address) => Some(Prefix::new(*address, 128)),
        })
        .collect::<HashSet<_>>();
    ensure!(
        content
            .v4_addresses()
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            == expected_v4
            && content
                .v6_addresses()
                .iter()
                .copied()
                .collect::<HashSet<_>>()
                == expected_v6,
        "SiSPI address mismatch"
    );
    Ok(vec![
        "CA certificate, current CRL, and current Manifest valid".into(),
        format!("SiSPI CMS, profile, AS{expected_as_id}, and SAVNET Agent addresses valid"),
        "Manifest: complete file hashes and selected CRL valid".into(),
    ])
}

fn validate_name(name: &str, extension: &str) -> Result<()> {
    ensure!(
        name.ends_with(&format!(".{extension}")) && !name.contains(['/', '\\']),
        "invalid signed-object name"
    );
    Ok(())
}
