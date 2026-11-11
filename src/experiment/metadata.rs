//! Reproducible public metadata; configuration is explicitly informational.
use super::*;
use serde_json::{Value, json};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CaMetadata {
    pub certificate: Value,
    pub configuration: Value,
}

pub(super) fn public_config(c: &CaConfig) -> Value {
    // Explicit allowlist: never serialize future credentials or local paths.
    json!({
        "name": c.name, "repository_uri": c.repository_uri,
        "certificate_uri": c.certificate_uri,
        "development_ca_validity_days": c.development_ca_validity_days,
        "ca_renew_before_days": c.ca_renew_before_days,
        "development_resources": c.development_resources, "development_asns": c.development_asns,
        "timing": {
            "roa_valid_weeks": c.timing.roa_valid_weeks,
            "aspa_valid_weeks": c.timing.aspa_valid_weeks,
            "toa_valid_weeks": c.timing.toa_valid_weeks,
            "sispi_valid_weeks": c.timing.sispi_valid_weeks,
            "toa_review_days": c.timing.toa_review_days,
            "publish_next_hours": c.timing.publish_next_hours,
            "publish_next_jitter_hours": c.timing.publish_next_jitter_hours,
            "publish_hours_before_next": c.timing.publish_hours_before_next
        }
    })
}

fn time(value: i64) -> Result<String> {
    Ok(chrono::DateTime::from_timestamp(value, 0)
        .context("unrepresentable metadata time")?
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

pub(super) fn certificate(bytes: &[u8]) -> Result<Value> {
    let cert = Cert::decode(bytes)?;
    let (_, parsed) = x509_parser::parse_x509_certificate(bytes)
        .map_err(|e| anyhow::anyhow!("cannot decode certificate metadata: {e}"))?;
    Ok(json!({
        "sha256": digest(bytes), "size": bytes.len(),
        "subject": parsed.subject().to_string(), "issuer": parsed.issuer().to_string(),
        "serial": cert.serial_number().to_string(),
        "subject_key_identifier": cert.subject_key_identifier().to_string(),
        "repository_uri": cert.ca_repository().map(ToString::to_string),
        "manifest_uri": cert.rpki_manifest().map(ToString::to_string),
        "ca_issuers": cert.ca_issuer().map(ToString::to_string),
        "not_before": cert.validity().not_before().timestamp(),
        "not_after": cert.validity().not_after().timestamp(),
        "not_before_utc": time(cert.validity().not_before().timestamp())?,
        "not_after_utc": time(cert.validity().not_after().timestamp())?,
        "resources": {
            "ipv4": cert.v4_resources().to_blocks().ok().map(|b| b.as_v4().to_string()),
            "ipv6": cert.v6_resources().to_blocks().ok().map(|b| b.as_v6().to_string()),
            "asn": cert.as_resources().to_blocks().ok().map(|b| b.to_string()),
            "ipv4_inherited": cert.v4_resources().is_inherited(),
            "ipv6_inherited": cert.v6_resources().is_inherited(),
            "asn_inherited": cert.as_resources().is_inherited()
        }
    }))
}

pub(super) fn ca(repository: &LocalRepository, config: &CaConfig) -> Result<CaMetadata> {
    let names = repository.list()?;
    let name = names
        .iter()
        .find(|n| n.ends_with(".cer"))
        .context("missing CA")?;
    Ok(CaMetadata {
        certificate: certificate(&repository.read(name)?)?,
        configuration: public_config(config),
    })
}

pub(super) fn parents(context: Option<&ParentValidationContext>) -> Result<Vec<Value>> {
    let Some(ParentValidationContext::Imported {
        chain_base64,
        crls_base64,
        manifests_base64,
        ..
    }) = context
    else {
        return Ok(Vec::new());
    };
    let mut result = Vec::new();
    for (field, kind, values) in [
        ("chain_base64", "certificate", chain_base64),
        ("crls_base64", "crl", crls_base64),
        ("manifests_base64", "manifest", manifests_base64),
    ] {
        for (index, value) in values.iter().enumerate() {
            let bytes = STANDARD.decode(value)?;
            let details = match kind {
                "certificate" => certificate(&bytes)?,
                "crl" => {
                    let crl = Crl::decode(bytes.as_slice())?;
                    json!({"this_update": crl.this_update().timestamp(), "next_update": crl.next_update().timestamp(),
                        "this_update_utc": time(crl.this_update().timestamp())?, "next_update_utc": time(crl.next_update().timestamp())?,
                        "authority_key_identifier": crl.authority_key_identifier().to_string()})
                }
                _ => {
                    let m = Manifest::decode(bytes.as_slice(), true)?;
                    json!({"this_update": m.content().this_update().timestamp(), "next_update": m.content().next_update().timestamp(),
                        "this_update_utc": time(m.content().this_update().timestamp())?, "next_update_utc": time(m.content().next_update().timestamp())?,
                        "signed_object_uri": m.cert().signed_object().map(ToString::to_string),
                        "ee_certificate": certificate(m.cert().to_captured().as_slice())?})
                }
            };
            result.push(json!({"source": format!("parent_context.{field}[{index}]"),
                "kind": kind, "sha256": digest(&bytes), "size": bytes.len(), "details": details}));
        }
    }
    Ok(result)
}

pub(super) fn profiles(objects: &BTreeMap<String, ObjectDefinition>) -> BTreeMap<String, String> {
    objects
        .values()
        .map(|definition| {
            let (kind, profile) = match definition.kind() {
                ObjectKind::Roa => ("roa", "RFC 9582; OID 1.2.840.113549.1.9.16.1.24".into()),
                ObjectKind::Aspa => (
                    "aspa",
                    "draft-ietf-sidrops-aspa-profile-29; OID 1.2.840.113549.1.9.16.1.49".into(),
                ),
                ObjectKind::Toa => (
                    "toa",
                    format!(
                        "draft-qin-savnet-toa-02; experimental OID {}",
                        crate::constants::TOA_CONTENT_TYPE_OID
                    ),
                ),
                ObjectKind::Sispi => (
                    "sispi",
                    format!(
                        "draft-chen-sidrops-sispi-06; experimental OID {}",
                        crate::constants::SISPI_CONTENT_TYPE_OID
                    ),
                ),
            };
            (kind.into(), profile)
        })
        .collect()
}
