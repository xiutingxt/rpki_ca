use anyhow::{Context, Result, bail};
use rpki::repository::{
    cert::Cert, crl::Crl, manifest::Manifest, resources::ResourceSet, tal::TalInfo, x509::Time,
};
use std::{collections::BTreeSet, sync::Arc};

/// Validates an imported certificate from the trust anchor through every
/// issuing CA and checks the current CRL for each hop.
pub(crate) fn validate_import_path(
    cert: &Cert,
    chain: &[Vec<u8>],
    crls: &[Vec<u8>],
    manifests: &[Vec<u8>],
) -> Result<ResourceSet> {
    if cert.is_self_signed() {
        if !chain.is_empty() || !crls.is_empty() || !manifests.is_empty() {
            bail!("a trust anchor import must not include a parent chain or issuer CRLs");
        }
        let validated = cert
            .clone()
            .validate_ta(Arc::new(TalInfo::from_name("imported-ta".into())), true)
            .map_err(|err| anyhow::anyhow!("trust anchor validation failed: {err}"))?;
        return Ok(ResourceSet::new(
            validated.as_resources().clone(),
            validated.v4_resources().clone().into(),
            validated.v6_resources().clone().into(),
        ));
    }
    if chain.is_empty() {
        bail!("a non-self-signed RC requires --chain-certificate entries from TA to parent");
    }
    if crls.len() != chain.len() {
        bail!("one --chain-crl is required for every issuing CA in the chain");
    }
    if manifests.len() != chain.len() {
        bail!("one --chain-manifest is required for every issuing CA in the chain");
    }

    let ta = Cert::decode(chain[0].as_slice())
        .context("invalid trust anchor certificate")?
        .validate_ta(Arc::new(TalInfo::from_name("import-chain".into())), true)
        .map_err(|err| anyhow::anyhow!("trust anchor validation failed: {err}"))?;
    let mut issuer = ta;
    for (index, ((crl_bytes, manifest_bytes), _)) in
        crls.iter().zip(manifests).zip(chain).enumerate()
    {
        let crl = Crl::decode(crl_bytes.as_slice()).context("invalid issuer CRL")?;
        crl.verify_signature(issuer.subject_public_key_info())
            .map_err(|err| anyhow::anyhow!("issuer CRL signature validation failed: {err}"))?;
        if crl.issuer() != issuer.subject()
            || crl.authority_key_identifier() != &issuer.subject_key_identifier()
        {
            bail!("issuer CRL name or authority key identifier does not match its CA");
        }
        let now = Time::now();
        if crl.this_update() > now || crl.next_update() < now {
            bail!("issuer CRL is not currently valid");
        }

        let manifest =
            Manifest::decode(manifest_bytes.as_slice(), true).context("invalid issuer manifest")?;
        if manifest.cert().signed_object() != issuer.rpki_manifest() {
            bail!("issuer manifest EE SIA does not match the issuer certificate manifest URI");
        }
        let manifest_ee_serial = manifest.cert().serial_number();
        let (_, manifest_content) = manifest
            .validate(&issuer, true)
            .map_err(|err| anyhow::anyhow!("issuer manifest validation failed: {err}"))?;
        if manifest_content.this_update() > now || manifest_content.next_update() < now {
            bail!("issuer manifest is not currently valid");
        }
        if manifest_content.this_update() != crl.this_update()
            || manifest_content.next_update() != crl.next_update()
        {
            bail!("issuer manifest and CRL update times do not match");
        }
        if crl.contains(manifest_ee_serial) {
            bail!("issuer manifest EE certificate is revoked");
        }

        let child = if index + 1 < chain.len() {
            Cert::decode(chain[index + 1].as_slice())
                .context("invalid intermediate CA certificate")?
        } else {
            cert.clone()
        };
        let hash_algorithm = manifest_content.file_hash_alg();
        let mut names = BTreeSet::new();
        let mut crl_entries = 0usize;
        let child_hash = hash_algorithm.digest(child.to_captured().as_slice());
        let mut child_is_listed = false;
        for entry in manifest_content.iter() {
            let name = std::str::from_utf8(entry.file())
                .context("issuer manifest contains a non-ASCII filename")?;
            if !names.insert(name.to_owned()) {
                bail!("issuer manifest contains duplicate filename '{name}'");
            }
            if name.ends_with(".crl") {
                crl_entries += 1;
            }
            if name.ends_with(".cer") && entry.hash().as_ref() == child_hash.as_ref() {
                child_is_listed = true;
            }
        }
        if crl_entries != 1 {
            bail!("issuer manifest must contain exactly one CRL entry");
        }
        if !child_is_listed {
            bail!(
                "issued CA certificate is not listed with a matching hash on its issuer manifest"
            );
        }
        let crl_uri = child
            .crl_uri()
            .context("issued certificate has no CRL distribution point")?;
        let crl_name = crl_uri
            .path()
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .context("certificate CRL distribution point has no filename")?;
        let expected_crl_uri = issuer
            .ca_repository()
            .context("issuing CA has no caRepository SIA")?
            .join(crl_name.as_bytes())?;
        if crl_uri != &expected_crl_uri {
            bail!("certificate CRL distribution point is outside the issuer publication point");
        }
        let expected_hash = manifest_content
            .iter()
            .find(|item| item.file().as_ref() == crl_name.as_bytes())
            .context("issuer CRL is not listed on the issuer's current manifest")?;
        let actual_hash = hash_algorithm.digest(crl_bytes);
        if expected_hash.hash().as_ref() != actual_hash.as_ref() {
            bail!("issuer CRL hash does not match the issuer's current manifest");
        }
        if crl.contains(child.serial_number()) {
            bail!(
                "certificate serial {} is revoked by its issuer",
                child.serial_number()
            );
        }
        issuer = child
            .validate_ca(&issuer, true)
            .map_err(|err| anyhow::anyhow!("resource certificate path validation failed: {err}"))?;
    }
    Ok(ResourceSet::new(
        issuer.as_resources().clone(),
        issuer.v4_resources().clone().into(),
        issuer.v6_resources().clone().into(),
    ))
}
