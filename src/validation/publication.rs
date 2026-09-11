//! Validation of ROA and ASPA publication sets.

use crate::ca::publication;
use anyhow::{Context, Result, ensure};
use rpki::{
    crypto::digest::DigestAlgorithm,
    repository::{aspa::Aspa, cert::Cert, crl::Crl, manifest::Manifest, roa::Roa, tal::TalInfo},
};
use std::{collections::BTreeSet, fs, path::Path};

pub fn verify_roa_publication(
    ca_dir: &Path,
    roa_name: &str,
    expected_asn: u32,
    expected_payloads: &[String],
) -> Result<Vec<String>> {
    ensure!(
        roa_name.ends_with(".roa") && !roa_name.contains(['/', '\\']),
        "invalid ROA object name"
    );
    let repository = ca_dir.join("repository");
    let ca_name = find_one(&repository, "cer")?;
    let crl_name = find_one(&repository, "crl")?;
    let manifest_name = find_one(&repository, "mft")?;
    let ca_bytes = read(&repository, &ca_name)?;
    let crl_bytes = read(&repository, &crl_name)?;
    let roa_bytes = read(&repository, roa_name)?;
    let manifest_bytes = read(&repository, &manifest_name)?;

    let ca = Cert::decode(ca_bytes.as_slice())?
        .validate_ta(
            TalInfo::from_name("local-verification".into()).into_arc(),
            true,
        )
        .map_err(|err| anyhow::anyhow!("CA certificate validation failed: {err}"))?;
    ensure_recommended_name(&ca_name, &ca.subject_key_identifier(), "cer")?;
    ensure_recommended_name(&crl_name, &ca.subject_key_identifier(), "crl")?;
    ensure_recommended_name(&manifest_name, &ca.subject_key_identifier(), "mft")?;
    let mut report = vec!["CA certificate: valid resource trust anchor".to_owned()];

    let crl = Crl::decode(crl_bytes.as_slice())?;
    crl.verify_signature(ca.subject_public_key_info())
        .map_err(|err| anyhow::anyhow!("CRL signature validation failed: {err}"))?;
    ensure!(
        crl.this_update() < crl.next_update(),
        "invalid CRL update window"
    );
    report.push("CRL: signature and update window valid".to_owned());

    let roa = Roa::decode(roa_bytes.as_slice(), true)?;
    ensure_recommended_name(roa_name, &roa.cert().subject_key_identifier(), "roa")?;
    ensure!(
        !crl.contains(roa.cert().serial_number()),
        "ROA EE certificate is revoked"
    );
    let (_, content) = roa
        .process(&ca, true, |_| Ok(()))
        .map_err(|err| anyhow::anyhow!("ROA validation failed: {err}"))?;
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
    report.push(format!(
        "ROA: CMS, EE certificate, ASN {expected_asn}, and payloads valid"
    ));

    let manifest = Manifest::decode(manifest_bytes.as_slice(), true)?;
    ensure!(
        !crl.contains(manifest.cert().serial_number()),
        "Manifest EE certificate is revoked"
    );
    ensure!(
        manifest.cert().validity().not_before() == manifest.content().this_update()
            && manifest.cert().validity().not_after() == manifest.content().next_update(),
        "Manifest EE validity does not equal its update window"
    );
    let (_, content) = manifest
        .validate(&ca, true)
        .map_err(|err| anyhow::anyhow!("Manifest validation failed: {err}"))?;
    ensure!(
        content.file_hash_alg() == DigestAlgorithm::sha256(),
        "Manifest is not SHA-256"
    );
    let mut listed = BTreeSet::new();
    for entry in content.iter() {
        let name = std::str::from_utf8(entry.file())?.to_owned();
        let bytes = read(&repository, &name)?;
        ensure!(
            content.file_hash_alg().digest(&bytes).as_ref() == entry.hash().as_ref(),
            "Manifest hash mismatch for {name}"
        );
        listed.insert(name);
    }
    ensure!(
        listed.contains(&crl_name),
        "Manifest does not list {crl_name}"
    );
    ensure!(
        listed.contains(roa_name),
        "Manifest does not list {roa_name}"
    );
    report.push(format!(
        "Manifest: CMS, EE certificate, SHA-256, and {} file hashes valid",
        listed.len()
    ));
    Ok(report)
}

pub fn verify_aspa_publication(
    ca_dir: &Path,
    aspa_name: &str,
    customer_asn: u32,
    expected_providers: &[u32],
) -> Result<Vec<String>> {
    ensure!(
        aspa_name.ends_with(".asa") && !aspa_name.contains(['/', '\\']),
        "invalid ASPA object name"
    );
    let repository = ca_dir.join("repository");
    let ca_name = find_one(&repository, "cer")?;
    let crl_name = find_one(&repository, "crl")?;
    let manifest_name = find_one(&repository, "mft")?;
    let ca = Cert::decode(read(&repository, &ca_name)?.as_slice())?
        .validate_ta(
            TalInfo::from_name("local-verification".into()).into_arc(),
            true,
        )
        .map_err(|err| anyhow::anyhow!("CA certificate validation failed: {err}"))?;
    ensure_recommended_name(&ca_name, &ca.subject_key_identifier(), "cer")?;
    ensure_recommended_name(&crl_name, &ca.subject_key_identifier(), "crl")?;
    ensure_recommended_name(&manifest_name, &ca.subject_key_identifier(), "mft")?;
    let crl = Crl::decode(read(&repository, &crl_name)?.as_slice())?;
    crl.verify_signature(ca.subject_public_key_info())
        .map_err(|err| anyhow::anyhow!("CRL signature validation failed: {err}"))?;
    let aspa = Aspa::decode(read(&repository, aspa_name)?.as_slice(), true)?;
    ensure_recommended_name(aspa_name, &aspa.cert().subject_key_identifier(), "asa")?;
    ensure!(
        !crl.contains(aspa.cert().serial_number()),
        "ASPA EE certificate is revoked"
    );
    let (_, content) = aspa
        .process(&ca, true, |_| Ok(()))
        .map_err(|err| anyhow::anyhow!("ASPA validation failed: {err}"))?;
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

    let manifest = Manifest::decode(read(&repository, &manifest_name)?.as_slice(), true)?;
    let (_, manifest) = manifest
        .validate(&ca, true)
        .map_err(|err| anyhow::anyhow!("Manifest validation failed: {err}"))?;
    let entry = manifest
        .iter()
        .find(|entry| entry.file().as_ref() == aspa_name.as_bytes())
        .context("Manifest does not list ASPA")?;
    let bytes = read(&repository, aspa_name)?;
    ensure!(
        manifest.file_hash_alg().digest(&bytes).as_ref() == entry.hash().as_ref(),
        "Manifest hash mismatch for {aspa_name}"
    );
    Ok(vec![
        "CA certificate and CRL valid".to_owned(),
        format!("ASPA: CMS, EE certificate, customer AS{customer_asn}, and providers valid"),
        "Manifest: ASPA entry and SHA-256 hash valid".to_owned(),
    ])
}

fn read(repository: &Path, name: &str) -> Result<Vec<u8>> {
    fs::read(repository.join(name)).with_context(|| format!("cannot read repository object {name}"))
}

fn ensure_recommended_name(
    actual: &str,
    key: &rpki::crypto::KeyIdentifier,
    extension: &str,
) -> Result<()> {
    let expected = publication::key_filename(key, extension);
    ensure!(
        actual == expected,
        "object name {actual} is not the RFC 6481 recommended name {expected}"
    );
    Ok(())
}

fn find_one(repository: &Path, extension: &str) -> Result<String> {
    let suffix = format!(".{extension}");
    let mut matches = fs::read_dir(repository)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.ends_with(&suffix));
    let name = matches
        .next()
        .with_context(|| format!("repository contains no {suffix} object"))?;
    ensure!(
        matches.next().is_none(),
        "repository contains multiple {suffix} objects"
    );
    Ok(name)
}
