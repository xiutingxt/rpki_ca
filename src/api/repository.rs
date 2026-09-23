//! Read-only views over the current publication repository.

use crate::ca::signed_objects::{sispi::object::Sispi, toa::object::Toa};
use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use rpki::repository::{
    aspa::Aspa,
    cert::{Cert, KeyUsage, Overclaim},
    crl::Crl,
    manifest::Manifest,
    roa::{Roa, RouteOriginAttestation},
    sigobj::SignedObject,
    x509::Time,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use x509_parser::{
    objects::oid2sn,
    parse_x509_certificate, parse_x509_crl,
    prelude::{ASN1Time, oid_registry},
};

#[derive(Debug, Serialize)]
pub(super) struct RepositoryList {
    pub objects: Vec<RepositoryObject>,
}

#[derive(Debug, Serialize)]
pub(super) struct RepositoryObject {
    pub name: String,
    pub kind: &'static str,
    pub size: usize,
    pub sha256: String,
    pub download_url: String,
    pub inspect_url: String,
    pub withdraw_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct RepositoryInspection {
    pub name: String,
    pub kind: &'static str,
    pub size: usize,
    pub sha256: String,
    pub content_base64: String,
    pub decoded: Value,
}

pub(super) fn summarize(name: String, bytes: &[u8], withdrawable: bool) -> RepositoryObject {
    RepositoryObject {
        kind: kind(&name),
        size: bytes.len(),
        sha256: digest_hex(bytes),
        download_url: format!("/repository/{name}"),
        inspect_url: format!("/api/v1/repository/objects/{name}"),
        withdraw_url: withdrawable.then(|| format!("/api/v1/signed-objects/{name}")),
        name,
    }
}

pub(super) fn inspect(name: String, bytes: Vec<u8>) -> Result<RepositoryInspection> {
    let object_kind = kind(&name);
    let decoded = match object_kind {
        "ca_certificate" => inspect_certificate(&bytes)?,
        "crl" => inspect_crl(&bytes)?,
        "manifest" => inspect_manifest(&bytes)?,
        "roa" => inspect_roa(&bytes)?,
        "aspa" => inspect_aspa(&bytes)?,
        "toa" => inspect_toa(&bytes)?,
        "sispi" => inspect_sispi(&bytes)?,
        _ => bail!("unsupported repository object type"),
    };
    Ok(RepositoryInspection {
        name,
        kind: object_kind,
        size: bytes.len(),
        sha256: digest_hex(&bytes),
        content_base64: STANDARD.encode(&bytes),
        decoded,
    })
}

fn inspect_certificate(bytes: &[u8]) -> Result<Value> {
    let cert = Cert::decode(bytes).context("invalid DER resource certificate")?;
    let cert_profile = resource_certificate_profile(cert.overclaim());
    Ok(json!({
        "profile": profile("Resource Certificate", cert_profile.document, cert_profile.url),
        "certificate": certificate_fields(&cert)?,
    }))
}

fn certificate_fields(cert: &Cert) -> Result<Value> {
    let encoded = cert.to_captured();
    let (remaining, parsed) = parse_x509_certificate(encoded.as_slice())
        .map_err(|error| anyhow::anyhow!("cannot decode certificate details: {error}"))?;
    ensure_no_trailing(remaining, "DER resource certificate")?;
    let as_resources = cert.as_resources();
    let v4_resources = cert.v4_resources();
    let v6_resources = cert.v6_resources();
    let cert_profile = resource_certificate_profile(cert.overclaim());
    let ip_resources_present = v4_resources.is_present() || v6_resources.is_present();
    let as_resources_present = as_resources.is_present();
    let ip_addr_blocks = json!({
        "present": ip_resources_present,
        "oid": ip_resources_present.then_some(cert_profile.ip_resources_oid),
        "critical": ip_resources_present.then_some(true),
        "ipv4": resource_family(
            v4_resources.is_present(),
            v4_resources.is_inherited(),
            v4_resources.to_blocks().map(|blocks| blocks.as_v4().to_string()),
        )?,
        "ipv6": resource_family(
            v6_resources.is_present(),
            v6_resources.is_inherited(),
            v6_resources.to_blocks().map(|blocks| blocks.as_v6().to_string()),
        )?,
    });
    let as_identifiers = json!({
        "present": as_resources_present,
        "oid": as_resources_present.then_some(cert_profile.as_resources_oid),
        "critical": as_resources_present.then_some(true),
        "asnum": resource_family(
            as_resources.is_present(),
            as_resources.is_inherited(),
            as_resources.to_blocks().map(|blocks| blocks.to_string()),
        )?,
        "rdi": { "mode": "absent" },
    });
    let signature_algorithm = algorithm_identifier(&parsed.signature_algorithm.algorithm);
    let tbs_signature_algorithm = algorithm_identifier(&parsed.tbs_certificate.signature.algorithm);
    let public_key_algorithm = algorithm_identifier(&parsed.public_key().algorithm.algorithm);
    let key_usage = match cert.key_usage() {
        KeyUsage::Ca => vec!["keyCertSign", "cRLSign"],
        KeyUsage::Ee => vec!["digitalSignature"],
    };
    Ok(json!({
        "resourceCertificateProfile": cert_profile.name,
        "tbsCertificate": {
            "version": 3,
            "serialNumber": cert.serial_number().to_string(),
            "signature": tbs_signature_algorithm,
            "issuer": parsed.issuer().to_string(),
            "validity": {
                "notBefore": time(cert.validity().not_before()),
                "notAfter": time(cert.validity().not_after()),
            },
            "subject": parsed.subject().to_string(),
            "subjectPublicKeyInfo": {
                "algorithm": public_key_algorithm,
                "subjectPublicKey": {
                    "encoding": "base64",
                    "value": STANDARD.encode(cert.subject_public_key_info().bits()),
                },
            },
            "extensions": {
            "basicConstraints": {
                "present": cert.basic_ca().is_some(),
                "critical": cert.basic_ca().is_some(),
                "cA": cert.basic_ca(),
                "pathLenConstraint": Value::Null,
            },
            "subjectKeyIdentifier": {
                "critical": false,
                "keyIdentifier": cert.subject_key_identifier().to_string(),
            },
            "authorityKeyIdentifier": cert.authority_key_identifier().map(|value| json!({
                "critical": false,
                "keyIdentifier": value.to_string(),
            })),
            "keyUsage": {
                "critical": true,
                "bits": key_usage,
            },
            "extendedKeyUsage": {
                "present": cert.extended_key_usage().is_some(),
            },
            "crlDistributionPoints": cert.crl_uri().map(|uri| vec![uri.to_string()]).unwrap_or_default(),
            "authorityInfoAccess": {
                "caIssuers": cert.ca_issuer().map(ToString::to_string),
            },
            "subjectInfoAccess": {
                "caRepository": cert.ca_repository().map(ToString::to_string),
                "rpkiManifest": cert.rpki_manifest().map(ToString::to_string),
                "signedObject": cert.signed_object().map(ToString::to_string),
                "rpkiNotify": cert.rpki_notify().map(ToString::to_string),
            },
            "certificatePolicies": {
                "critical": true,
                "policyIdentifier": cert_profile.policy_oid,
            },
            "ipAddrBlocks": ip_addr_blocks,
            "asIdentifiers": as_identifiers,
            },
        },
        "signatureAlgorithm": signature_algorithm,
        "signatureValue": {
            "encoding": "base64",
            "value": STANDARD.encode(parsed.signature_value.data.as_ref()),
        },
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResourceCertificateProfile {
    name: &'static str,
    document: &'static str,
    url: &'static str,
    policy_oid: &'static str,
    ip_resources_oid: &'static str,
    as_resources_oid: &'static str,
}

fn resource_certificate_profile(overclaim: Overclaim) -> ResourceCertificateProfile {
    match overclaim {
        Overclaim::Refuse => ResourceCertificateProfile {
            name: "rfc6487",
            document: "RFC 6487",
            url: "https://www.rfc-editor.org/rfc/rfc6487.html",
            policy_oid: "1.3.6.1.5.5.7.14.2",
            ip_resources_oid: "1.3.6.1.5.5.7.1.7",
            as_resources_oid: "1.3.6.1.5.5.7.1.8",
        },
        Overclaim::Trim => ResourceCertificateProfile {
            name: "rfc8360",
            document: "RFC 8360",
            url: "https://www.rfc-editor.org/rfc/rfc8360.html",
            policy_oid: "1.3.6.1.5.5.7.14.3",
            ip_resources_oid: "1.3.6.1.5.5.7.1.28",
            as_resources_oid: "1.3.6.1.5.5.7.1.29",
        },
    }
}

fn inspect_crl(bytes: &[u8]) -> Result<Value> {
    let crl = Crl::decode(bytes).context("invalid DER CRL")?;
    let (remaining, parsed) = parse_x509_crl(bytes)
        .map_err(|error| anyhow::anyhow!("cannot decode CRL details: {error}"))?;
    ensure_no_trailing(remaining, "DER CRL")?;
    let revoked_certificates = parsed
        .iter_revoked_certificates()
        .map(|entry| {
            Ok(json!({
                "userCertificate": entry.serial().to_string(),
                "revocationDate": x509_time(entry.revocation_date)?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let revoked_certificate_count = revoked_certificates.len();
    let signature_algorithm = algorithm_identifier(&parsed.signature_algorithm.algorithm);
    let tbs_signature = algorithm_identifier(&parsed.tbs_cert_list.signature.algorithm);
    Ok(json!({
        "profile": profile("Resource Certificate Revocation List", "RFC 6487 Section 5", "https://www.rfc-editor.org/rfc/rfc6487.html#section-5"),
        "certificateList": {
            "tbsCertList": {
                "version": parsed.version().map(|version| version.0 + 1).unwrap_or(1),
                "signature": tbs_signature,
                "issuer": parsed.issuer().to_string(),
                "thisUpdate": time(crl.this_update()),
                "nextUpdate": time(crl.next_update()),
                "revokedCertificates": revoked_certificates,
                "crlExtensions": {
                    "authorityKeyIdentifier": {
                        "critical": false,
                        "keyIdentifier": crl.authority_key_identifier().to_string(),
                    },
                    "cRLNumber": {
                        "critical": false,
                        "value": crl.crl_number().to_string(),
                    },
                },
            },
            "signatureAlgorithm": signature_algorithm,
            "signatureValue": {
                "encoding": "base64",
                "value": STANDARD.encode(parsed.signature_value.data.as_ref()),
            },
        },
        "summary": {
            "revokedCertificateCount": revoked_certificate_count,
        },
    }))
}

fn inspect_manifest(bytes: &[u8]) -> Result<Value> {
    let manifest = Manifest::decode(bytes, true).context("invalid DER Manifest")?;
    let cms = signed_object_fields(
        bytes,
        manifest.cert(),
        "id-ct-rpkiManifest",
        "1.2.840.113549.1.9.16.1.26",
    )?;
    let content = manifest.content();
    let files = content
        .iter()
        .map(|entry| {
            let (name, hash) = entry.into_pair();
            json!({
                "file": String::from_utf8_lossy(name.as_ref()),
                "hash": hex(hash.as_ref()),
            })
        })
        .collect::<Vec<_>>();
    let file_hash_algorithm = content.file_hash_alg();
    Ok(json!({
        "profile": profile("RPKI Manifest", "RFC 9286", "https://www.rfc-editor.org/rfc/rfc9286.html"),
        "cms": cms,
        "eContent": {
            "version": 0,
            "manifestNumber": content.manifest_number().to_string(),
            "thisUpdate": time(content.this_update()),
            "nextUpdate": time(content.next_update()),
            "fileHashAlg": {
                "name": if file_hash_algorithm.is_sha256() { "sha256" } else { "unsupported" },
                "oid": if file_hash_algorithm.is_sha256() { "2.16.840.1.101.3.4.2.1" } else { "unknown" },
            },
            "fileList": files,
        },
    }))
}

fn resource_family<E: std::fmt::Display>(
    present: bool,
    inherited: bool,
    blocks: std::result::Result<String, E>,
) -> Result<Value> {
    if inherited {
        return Ok(json!({ "mode": "inherited" }));
    }
    if !present {
        return Ok(json!({ "mode": "missing", "blocks": "" }));
    }
    let blocks =
        blocks.map_err(|error| anyhow::anyhow!("cannot decode certificate resources: {error}"))?;
    Ok(json!({ "mode": "explicit", "blocks": blocks }))
}

fn inspect_roa(bytes: &[u8]) -> Result<Value> {
    let roa = Roa::decode(bytes, true).context("invalid DER ROA")?;
    let content = roa.content();
    let ip_addr_blocks = roa_ip_address_families(content);
    Ok(json!({
        "profile": profile("Route Origin Authorization", "RFC 9582", "https://www.rfc-editor.org/rfc/rfc9582.html"),
        "cms": signed_object_fields(bytes, roa.cert(), "id-ct-routeOriginAuthz", "1.2.840.113549.1.9.16.1.24")?,
        "eContent": {
            "version": 0,
            "asID": u32::from(content.as_id()),
            "ipAddrBlocks": ip_addr_blocks,
        },
    }))
}

fn inspect_aspa(bytes: &[u8]) -> Result<Value> {
    let aspa = Aspa::decode(bytes, true).context("invalid DER ASPA")?;
    let content = aspa.content();
    Ok(json!({
        "profile": profile("Autonomous System Provider Authorization", "draft-ietf-sidrops-aspa-profile-29", "https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-aspa-profile-29"),
        "cms": signed_object_fields(bytes, aspa.cert(), "id-ct-ASPA", "1.2.840.113549.1.9.16.1.49")?,
        "eContent": {
            "version": 1,
            "customerASID": u32::from(content.customer_as()),
            "providers": content.provider_as_set().iter().map(u32::from).collect::<Vec<_>>(),
        },
    }))
}

fn inspect_toa(bytes: &[u8]) -> Result<Value> {
    let toa = Toa::decode(Bytes::copy_from_slice(bytes)).context("invalid DER TOA")?;
    Ok(json!({
        "profile": profile("Traffic Origin Authorization", "draft-qin-savnet-toa-02", "https://datatracker.ietf.org/doc/html/draft-qin-savnet-toa-02"),
        "cms": signed_object_fields(bytes, toa.cert(), "id-ct-trafficOriginAuthz", crate::constants::TOA_CONTENT_TYPE_OID)?,
        "eContent": {
            "version": 0,
            "asSet": toa.content().asns().iter().copied().map(u32::from).collect::<Vec<_>>(),
            "ipAddrBlocks": prefix_address_families(
                toa.content().v4_prefixes(),
                toa.content().v6_prefixes(),
                "addressFamily",
                "addresses",
                false,
            ),
        },
    }))
}

fn inspect_sispi(bytes: &[u8]) -> Result<Value> {
    let sispi = Sispi::decode(Bytes::copy_from_slice(bytes)).context("invalid DER SiSPI")?;
    Ok(json!({
        "profile": profile("Signed SAVNET-Peering Information", "draft-chen-sidrops-sispi-06", "https://www.ietf.org/archive/id/draft-chen-sidrops-sispi-06.html"),
        "cms": signed_object_fields(bytes, sispi.cert(), "id-ct-rpkiSiSPI", crate::constants::SISPI_CONTENT_TYPE_OID)?,
        "eContent": {
            "version": 0,
            "asID": u32::from(sispi.content().as_id()),
            "addresses": prefix_address_families(
                sispi.content().v4_addresses(),
                sispi.content().v6_addresses(),
                "ipFamily",
                "ipAddresses",
                true,
            ),
        },
    }))
}

fn profile(name: &str, document: &str, url: &str) -> Value {
    json!({ "name": name, "document": document, "url": url })
}

fn signed_object_fields(
    bytes: &[u8],
    cert: &Cert,
    content_type_name: &str,
    expected_content_type_oid: &str,
) -> Result<Value> {
    let signed = SignedObject::decode(bytes, true).context("invalid RFC 6488 signed object")?;
    let actual_content_type_oid = signed.content_type().to_string();
    if actual_content_type_oid != expected_content_type_oid {
        bail!(
            "signed object eContentType is {actual_content_type_oid}, expected {expected_content_type_oid}"
        );
    }
    Ok(json!({
        "profile": profile("Signed Object Template", "RFC 6488", "https://www.rfc-editor.org/rfc/rfc6488.html"),
        "contentInfo": {
            "contentType": { "name": "signedData", "oid": "1.2.840.113549.1.7.2" },
            "content": {
                "signedData": {
                    "version": 3,
                    "digestAlgorithms": [{
                        "name": "sha256",
                        "oid": "2.16.840.1.101.3.4.2.1",
                    }],
                    "encapContentInfo": {
                        "eContentType": {
                            "name": content_type_name,
                            "oid": actual_content_type_oid,
                        },
                    },
                    "certificates": [certificate_fields(cert)?],
                    "signerInfos": [{
                        "version": 3,
                        "sid": {
                            "subjectKeyIdentifier": cert.subject_key_identifier().to_string(),
                        },
                        "digestAlgorithm": {
                            "name": "sha256",
                            "oid": "2.16.840.1.101.3.4.2.1",
                        },
                        "signedAttrs": {
                            "contentType": {
                                "name": content_type_name,
                                "oid": expected_content_type_oid,
                            },
                            "signingTime": time(signed.signing_time()),
                        },
                        "signatureAlgorithm": {
                            "name": "sha256WithRSAEncryption",
                            "oid": "1.2.840.113549.1.1.11",
                        },
                    }],
                },
            },
        },
    }))
}

fn roa_ip_address_families(content: &RouteOriginAttestation) -> Vec<Value> {
    let mut families = Vec::new();
    if !content.v4_addrs().is_empty() {
        families.push(json!({
            "addressFamily": "0001",
            "addresses": content.v4_addrs().iter().map(|address| json!({
                "address": format!("{}/{}", address.prefix().to_v4(), address.prefix().addr_len()),
                "maxLength": address.max_length(),
            })).collect::<Vec<_>>(),
        }));
    }
    if !content.v6_addrs().is_empty() {
        families.push(json!({
            "addressFamily": "0002",
            "addresses": content.v6_addrs().iter().map(|address| json!({
                "address": format!("{}/{}", address.prefix().to_v6(), address.prefix().addr_len()),
                "maxLength": address.max_length(),
            })).collect::<Vec<_>>(),
        }));
    }
    families
}

fn prefix_address_families(
    v4: &[rpki::repository::resources::Prefix],
    v6: &[rpki::repository::resources::Prefix],
    family_field: &str,
    addresses_field: &str,
    omit_full_length: bool,
) -> Vec<Value> {
    let mut families = Vec::new();
    if !v4.is_empty() {
        families.push(prefix_family_values(
            family_field,
            "0001",
            addresses_field,
            v4,
            true,
            omit_full_length,
        ));
    }
    if !v6.is_empty() {
        families.push(prefix_family_values(
            family_field,
            "0002",
            addresses_field,
            v6,
            false,
            omit_full_length,
        ));
    }
    families
}

fn prefix_family_values(
    family_field: &str,
    family: &str,
    addresses_field: &str,
    values: &[rpki::repository::resources::Prefix],
    is_v4: bool,
    omit_full_length: bool,
) -> Value {
    let values = values
        .iter()
        .copied()
        .map(|prefix| format_prefix(prefix, is_v4, omit_full_length))
        .collect::<Vec<_>>();
    let mut object = serde_json::Map::new();
    object.insert(family_field.into(), json!(family));
    object.insert(addresses_field.into(), json!(values));
    Value::Object(object)
}

fn algorithm_identifier(oid: &x509_parser::der_parser::oid::Oid<'_>) -> Value {
    let oid_string = oid.to_id_string();
    json!({
        "name": oid2sn(oid, oid_registry()).unwrap_or(&oid_string),
        "oid": oid_string,
    })
}

fn ensure_no_trailing(remaining: &[u8], object: &str) -> Result<()> {
    if !remaining.is_empty() {
        bail!("{object} contains trailing data");
    }
    Ok(())
}

fn format_prefix(
    prefix: rpki::repository::resources::Prefix,
    is_v4: bool,
    omit_full_length: bool,
) -> String {
    let address = if is_v4 {
        prefix.to_v4().to_string()
    } else {
        prefix.to_v6().to_string()
    };
    let full_length = if is_v4 { 32 } else { 128 };
    if omit_full_length && prefix.addr_len() == full_length {
        address
    } else {
        format!("{address}/{}", prefix.addr_len())
    }
}

fn kind(name: &str) -> &'static str {
    match name.rsplit_once('.').map(|(_, extension)| extension) {
        Some("cer") => "ca_certificate",
        Some("crl") => "crl",
        Some("mft") => "manifest",
        Some("roa") => "roa",
        Some("asa") => "aspa",
        Some("toa") => "toa",
        Some("sav") => "sispi",
        _ => "unknown",
    }
}

fn time(value: Time) -> String {
    DateTime::<Utc>::from(value).to_rfc3339()
}

fn x509_time(value: ASN1Time) -> Result<String> {
    DateTime::<Utc>::from_timestamp(value.timestamp(), 0)
        .map(|value| value.to_rfc3339())
        .context("CRL contains an out-of-range revocation time")
}

fn digest_hex(value: &[u8]) -> String {
    hex(Sha256::digest(value).as_slice())
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
#[path = "../../tests/unit/api/repository.rs"]
mod tests;
