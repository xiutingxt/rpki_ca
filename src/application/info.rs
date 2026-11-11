//! Public-material inspection. Never loads a signing key or performs recovery.
use crate::CaConfig;
use crate::ca::state::CaStateStore;
use crate::infrastructure::{
    repository::{LocalRepository, PublicationRepository},
    state_store::LocalStateStore,
};
use anyhow::{Context, Result, ensure};
use chrono::Utc;
use rpki::repository::{cert::Cert, crl::Crl, manifest::Manifest, sigobj::SignedObject};
use serde_json::{Value, json};
use std::{fs, path::Path};

pub fn ca_info(root: &Path) -> Result<Value> {
    ensure!(root.is_dir(), "CA directory does not exist");
    let store = LocalStateStore::new(root);
    let _guard = store.lock()?;
    ensure!(
        root.join("state.toml").is_file(),
        "missing state; recovery is required"
    );
    let state = store.load()?;
    let config: CaConfig = toml::from_str(&fs::read_to_string(root.join("ca.toml"))?)?;
    let repo = LocalRepository::new(root);
    let names = repo.list()?;
    let certificates: Vec<_> = names.iter().filter(|n| n.ends_with(".cer")).collect();
    ensure!(
        certificates.len() == 1,
        "expected exactly one CA certificate"
    );
    let name = certificates[0];
    let bytes = repo.read(name)?;
    let cert = Cert::decode(bytes.as_slice())?;
    let (_, parsed) = x509_parser::parse_x509_certificate(&bytes)
        .map_err(|e| anyhow::anyhow!("cannot decode subject: {e}"))?;
    let now = Utc::now().timestamp();
    let mut warnings = Vec::new();
    if let Err(error) = config.validate() {
        warnings.push(format!("invalid configuration: {error:#}"));
    }
    if state.pending_publication().is_some() {
        warnings.push(
            "publication transaction pending; displayed files may not form a committed snapshot"
                .into(),
        );
    }
    let actual_repository = cert.ca_repository().map(ToString::to_string);
    if actual_repository
        .as_deref()
        .map(|s| s.trim_end_matches('/'))
        != Some(config.repository_uri.trim_end_matches('/'))
    {
        warnings.push("configured repository_uri differs from certificate SIA; editing TOML does not reissue certificates".into());
    }
    if config.certificate_uri.rsplit('/').next() != Some(name.as_str()) {
        warnings.push(
            "configured certificate_uri filename differs from the published certificate".into(),
        );
    }
    let mut files = serde_json::Map::new();
    if !state.validation_context().is_imported() {
        use rpki::repository::resources::ResourceSet;
        let asns = config
            .development_asns
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let v4 = config
            .development_resources
            .iter()
            .filter(|p| matches!(p, ipnet::IpNet::V4(_)))
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let v6 = config
            .development_resources
            .iter()
            .filter(|p| matches!(p, ipnet::IpNet::V6(_)))
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        if let (Ok(desired), Ok(actual)) = (
            ResourceSet::from_strs(&asns, &v4, &v6),
            ResourceSet::try_from(&cert),
        ) {
            if desired != actual {
                warnings.push("configured development resources differ from certified resources; editing TOML does not change authorization".into());
            }
        }
    }
    for name in names {
        let data = repo.read(&name)?;
        let (start, end, ee_end) = if name.ends_with(".cer") {
            let c = Cert::decode(data.as_slice())?;
            (
                c.validity().not_before().timestamp(),
                c.validity().not_after().timestamp(),
                None,
            )
        } else if name.ends_with(".crl") {
            let c = Crl::decode(data.as_slice())?;
            (
                c.this_update().timestamp(),
                c.next_update().timestamp(),
                None,
            )
        } else if name.ends_with(".mft") {
            let m = Manifest::decode(data.as_slice(), true)?;
            (
                m.content().this_update().timestamp(),
                m.content().next_update().timestamp(),
                Some(m.cert().validity().not_after().timestamp()),
            )
        } else {
            let s = SignedObject::decode(data.as_slice(), true)
                .with_context(|| format!("cannot decode {name}"))?;
            (
                s.cert().validity().not_before().timestamp(),
                s.cert().validity().not_after().timestamp(),
                None,
            )
        };
        files.insert(
            name,
            json!({"valid_from": start, "valid_until": end, "ee_not_after": ee_end,
            "time_valid": start <= now && now <= end && ee_end.is_none_or(|v| now <= v)}),
        );
    }
    Ok(json!({
        "scope": "public_material_inspection_not_signature_or_path_validation",
        "observed_at": Utc::now().to_rfc3339(),
        "configured": config,
        "mode": if state.validation_context().is_imported() { "imported" } else { "development_trust_anchor" },
        "certificate": {
            "subject": parsed.subject().to_string(), "issuer": parsed.issuer().to_string(),
            "serial": cert.serial_number().to_string(), "key_identifier": cert.subject_key_identifier().to_string(),
            "repository_uri": actual_repository,
            "manifest_uri": cert.rpki_manifest().map(ToString::to_string),
            "ca_issuers": cert.ca_issuer().map(ToString::to_string),
            "not_before": cert.validity().not_before().timestamp(), "not_after": cert.validity().not_after().timestamp(),
            "renewal_required": cert.validity().not_after().timestamp() - now <= i64::from(config.ca_renew_before_days) * 86400,
            "resources": {
                "ipv4": cert.v4_resources().to_blocks().ok().map(|b| b.as_v4().to_string()),
                "ipv6": cert.v6_resources().to_blocks().ok().map(|b| b.as_v6().to_string()),
                "asn": cert.as_resources().to_blocks().ok().map(|b| b.to_string()),
                "ipv4_inherited": cert.v4_resources().is_inherited(),
                "ipv6_inherited": cert.v6_resources().is_inherited(),
                "asn_inherited": cert.as_resources().is_inherited()
            }
        },
        "files": files, "warnings": warnings,
        "configuration_effects": {
            "name": "local label only; does not change certificate Subject",
            "timing": "loaded at process startup; applies to future issuance/refresh only",
            "development_resources": "used when creating a development CA; does not modify existing certified resources",
            "repository_uri": "bound into certificates; changing TOML is not a repository migration",
            "development_ca_validity_days": "initial development CA certificate only; does not extend existing certificates"
        }
    }))
}
