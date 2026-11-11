//! Portable offline experiments. Signing keys exist only in a temporary CA.
mod metadata;

use crate::ca::{parent::ParentValidationContext, state::CaStateStore};
use crate::infrastructure::repository::{LocalRepository, PublicationRepository};
use crate::infrastructure::state_store::LocalStateStore;
use crate::validation::{publication::*, publication_set::PublicationSet};
use crate::{CaConfig, CaManager, ObjectDefinition, ObjectKind};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use ipnet::IpNet;
use rpki::repository::{cert::Cert, crl::Crl, manifest::Manifest, sigobj::SignedObject};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentRequest {
    #[serde(default)]
    pub ca: ExperimentCaConfig,
    /// CRL/Manifest validity for this isolated experiment, without jitter.
    #[serde(default = "default_valid_days")]
    pub valid_days: u32,
    pub resources: Vec<IpNet>,
    pub asn_resources: Vec<u32>,
    pub objects: Vec<ObjectDefinition>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExperimentCaConfig {
    pub name: String,
    pub repository_uri: String,
    pub development_ca_validity_days: u32,
    pub ca_renew_before_days: u32,
    pub roa_valid_weeks: u32,
    pub aspa_valid_weeks: u32,
    pub toa_valid_weeks: u32,
    pub sispi_valid_weeks: u32,
}

impl Default for ExperimentCaConfig {
    fn default() -> Self {
        let config = CaConfig::default();
        Self {
            name: "offline-experiment".into(),
            repository_uri: config.repository_uri,
            development_ca_validity_days: config.development_ca_validity_days,
            ca_renew_before_days: config.ca_renew_before_days,
            roa_valid_weeks: config.timing.roa_valid_weeks,
            aspa_valid_weeks: config.timing.aspa_valid_weeks,
            toa_valid_weeks: config.timing.toa_valid_weeks,
            sispi_valid_weeks: config.timing.sispi_valid_weeks,
        }
    }
}

fn default_valid_days() -> u32 {
    30
}

fn experiment_config(request: &ExperimentRequest) -> Result<CaConfig> {
    // Keep the publication window below the existing 52-week object EE and
    // 365-day CA lifetimes, with at least a day of headroom for issuance.
    ensure!(
        (1..=363).contains(&request.valid_days),
        "valid_days must be between 1 and 363"
    );
    let mut config = CaConfig {
        name: request.ca.name.clone(),
        repository_uri: request.ca.repository_uri.clone(),
        development_ca_validity_days: request.ca.development_ca_validity_days,
        ca_renew_before_days: request.ca.ca_renew_before_days,
        development_resources: request.resources.clone(),
        development_asns: request.asn_resources.clone(),
        ..CaConfig::default()
    };
    config.timing.publish_next_hours = request.valid_days * 24;
    config.timing.publish_next_jitter_hours = 0;
    config.timing.roa_valid_weeks = request.ca.roa_valid_weeks;
    config.timing.aspa_valid_weeks = request.ca.aspa_valid_weeks;
    config.timing.toa_valid_weeks = request.ca.toa_valid_weeks;
    config.timing.sispi_valid_weeks = request.ca.sispi_valid_weeks;
    config.validate_development()?;
    ensure!(
        request.valid_days < config.development_ca_validity_days,
        "valid_days must leave at least one day before CA expiry"
    );
    for definition in &request.objects {
        let weeks = match definition.kind() {
            ObjectKind::Roa => config.timing.roa_valid_weeks,
            ObjectKind::Aspa => config.timing.aspa_valid_weeks,
            ObjectKind::Toa => config.timing.toa_valid_weeks,
            ObjectKind::Sispi => config.timing.sispi_valid_weeks,
        };
        ensure!(
            request.valid_days < weeks * 7,
            "valid_days must leave at least one day before {:?} EE expiry",
            definition.kind()
        );
    }
    Ok(config)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    format_version: u32,
    #[serde(default)]
    ca_metadata: Option<metadata::CaMetadata>,
    #[serde(default)]
    parent_materials: Vec<serde_json::Value>,
    generator_version: String,
    created_at: String,
    request: Option<ExperimentRequest>,
    #[serde(default)]
    source: String,
    #[serde(default)]
    parent_context: Option<ParentValidationContext>,
    #[serde(default)]
    files: BTreeMap<String, FileMetadata>,
    objects: BTreeMap<String, ObjectDefinition>,
    profiles: BTreeMap<String, String>,
    repository_sha256: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct ExperimentReport {
    pub status: &'static str,
    pub verified_at: String,
    pub trust: &'static str,
    pub publication_valid_until: i64,
    pub objects: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
struct FileMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decoded: Option<serde_json::Value>,
    uri: String,
    sha256: String,
    size: usize,
    valid_from: i64,
    valid_until: i64,
    ca_issuers: Option<String>,
    crl_distribution_point: Option<String>,
    manifest_uri: Option<String>,
    signed_object_uri: Option<String>,
    ee_not_before: Option<i64>,
    ee_not_after: Option<i64>,
    content_type_oid: Option<String>,
}

fn metadata(name: &str, bytes: &[u8], ca_uri: &str, base: &str) -> Result<FileMetadata> {
    let mut result = FileMetadata {
        decoded: None,
        uri: if name.ends_with(".cer") {
            ca_uri.into()
        } else {
            format!("{}/{name}", base.trim_end_matches('/'))
        },
        sha256: digest(bytes),
        size: bytes.len(),
        valid_from: 0,
        valid_until: 0,
        ca_issuers: None,
        crl_distribution_point: None,
        manifest_uri: None,
        signed_object_uri: None,
        ee_not_before: None,
        ee_not_after: None,
        content_type_oid: None,
    };
    if name.ends_with(".crl") {
        let crl = Crl::decode(bytes)?;
        result.valid_from = crl.this_update().timestamp();
        result.valid_until = crl.next_update().timestamp();
        return Ok(result);
    }
    let cert = if name.ends_with(".cer") {
        Cert::decode(bytes)?
    } else {
        let signed = SignedObject::decode(bytes, true)?;
        result.content_type_oid = Some(signed.content_type().to_string());
        result.ee_not_before = Some(signed.cert().validity().not_before().timestamp());
        result.ee_not_after = Some(signed.cert().validity().not_after().timestamp());
        signed.cert().clone()
    };
    result.valid_from = cert.validity().not_before().timestamp();
    result.valid_until = cert.validity().not_after().timestamp();
    result.ca_issuers = cert.ca_issuer().map(ToString::to_string);
    result.crl_distribution_point = cert.crl_uri().map(ToString::to_string);
    result.manifest_uri = cert.rpki_manifest().map(ToString::to_string);
    result.signed_object_uri = cert.signed_object().map(ToString::to_string);
    if let Some(uri) = &result.signed_object_uri {
        result.uri = uri.clone();
    }
    if name.ends_with(".mft") {
        let manifest = Manifest::decode(bytes, true)?;
        result.valid_from = manifest.content().this_update().timestamp();
        result.valid_until = manifest.content().next_update().timestamp();
    }
    Ok(result)
}

fn collect_metadata(
    repository: &LocalRepository,
    ca_uri: &str,
) -> Result<BTreeMap<String, FileMetadata>> {
    let names = repository.list()?;
    let ca_name = names
        .iter()
        .find(|n| n.ends_with(".cer"))
        .context("missing CA certificate")?;
    let cert = Cert::decode(repository.read(ca_name)?.as_slice())?;
    let base = cert
        .ca_repository()
        .context("CA has no repository URI")?
        .to_string();
    names
        .into_iter()
        .map(|name| {
            let bytes = repository.read(&name)?;
            let mut info = metadata(&name, &bytes, ca_uri, &base)?;
            info.decoded = Some(crate::api::decode(&name, &bytes)?);
            Ok((name, info))
        })
        .collect()
}

/// Creates a fresh test CA, signs all inputs, exports only public material and
/// verifies the exported bytes before committing the new output directory.
pub fn create(request: &ExperimentRequest, output: &Path) -> Result<ExperimentReport> {
    let config = experiment_config(request)?;
    ensure!(
        !output.exists(),
        "output already exists; choose a new experiment directory"
    );
    ensure!(
        !request.objects.is_empty(),
        "experiment requires at least one object"
    );
    let mut keys = BTreeSet::new();
    for definition in &request.objects {
        definition.validate()?;
        ensure!(
            keys.insert(definition.clone().canonicalized().logical_key()),
            "duplicate object identity in experiment"
        );
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".experiment-")
        .tempdir_in(parent)?;
    let private = tempfile::tempdir()?;
    let ca = CaManager::init(private.path().join("ca"), config)?;
    // Issue ROAs first so TOA overlap policy sees the complete requested ROA set.
    let mut definitions = request.objects.clone();
    definitions.sort_by_key(|d| if d.kind() == ObjectKind::Roa { 0 } else { 1 });
    let mut objects = BTreeMap::new();
    for definition in definitions {
        let key = definition.clone().canonicalized().logical_key();
        let name = format!("experiment.{}", definition.kind().extension());
        match &definition {
            ObjectDefinition::Roa(value) => {
                ca.sign_roa(value, &name)?;
            }
            _ => {
                ca.issue_object(definition.clone(), &name)?;
            }
        }
        let published = ca
            .published_name(&key)?
            .context("signed object missing from inventory")?;
        objects.insert(published, definition.canonicalized());
    }
    let repository = staging.path().join("repository");
    fs::create_dir(&repository)?;
    let mut hashes = BTreeMap::new();
    let mut tal = None;
    let mut publication_time = 0;
    for name in ca.list_published_objects()? {
        let bytes = ca.read_published_object(&name)?;
        if name.ends_with(".cer") {
            let cert = Cert::decode(bytes.as_slice())?;
            tal = Some(format!(
                "{}{name}\n\n{}\n",
                cert.ca_repository().context("CA missing repository URI")?,
                STANDARD.encode(cert.subject_public_key_info().to_info_bytes())
            ));
        }
        if name.ends_with(".mft") {
            publication_time = Manifest::decode(bytes.as_slice(), true)?
                .content()
                .this_update()
                .timestamp();
        }
        hashes.insert(name.clone(), digest(&bytes));
        fs::write(repository.join(name), bytes)?;
    }
    fs::write(
        staging.path().join("trust-anchor.tal"),
        tal.context("missing test TA")?,
    )?;
    let effective_config: CaConfig =
        toml::from_str(&fs::read_to_string(private.path().join("ca/ca.toml"))?)?;
    let bundle = Bundle {
        format_version: 4,
        ca_metadata: Some(metadata::ca(
            &LocalRepository::new(staging.path()),
            &effective_config,
        )?),
        parent_materials: Vec::new(),
        generator_version: env!("CARGO_PKG_VERSION").into(),
        created_at: Utc::now().to_rfc3339(),
        request: Some(request.clone()),
        source: "generated_experiment".into(),
        parent_context: None,
        files: collect_metadata(
            &LocalRepository::new(staging.path()),
            &format!(
                "{}/{}",
                request.ca.repository_uri.trim_end_matches('/'),
                hashes
                    .keys()
                    .find(|n| n.ends_with(".cer"))
                    .context("missing CA")?
            ),
        )?,
        profiles: metadata::profiles(&objects),
        objects,
        repository_sha256: hashes,
    };
    fs::write(
        staging.path().join("experiment.json"),
        serde_json::to_vec_pretty(&bundle)?,
    )?;
    // The CA uses strictly increasing thisUpdate values. Fast successive
    // publications can be a few seconds ahead; wait instead of backdating or
    // weakening current-time validation of the exported snapshot.
    let delay = publication_time.saturating_sub(Utc::now().timestamp());
    ensure!(
        delay <= 60,
        "publication time is too far ahead; check the system clock"
    );
    if delay > 0 {
        std::thread::sleep(std::time::Duration::from_secs(delay as u64));
    }
    let report = verify(staging.path(), None)?;
    fs::write(
        staging.path().join("verification.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    // The private CA is never moved into the bundle.
    drop(ca);
    private.close()?;
    ensure!(
        !output.exists(),
        "output appeared while signing; refusing to replace it"
    );
    fs::rename(staging.path(), output).context("cannot commit experiment bundle")?;
    Ok(report)
}

/// Current-time verification. Does not read CA state, load a key or fetch URLs.
pub fn verify(dir: &Path, trusted_tal: Option<&Path>) -> Result<ExperimentReport> {
    verify_inner(dir, trusted_tal, &mut "input", &mut None)
}

/// Always serializable, including failures. Codes describe verification stages
/// and never depend on parsing an underlying library's error text.
pub fn verification_report(dir: &Path, trusted_tal: Option<&Path>) -> (bool, serde_json::Value) {
    let mut code = "input";
    let mut object = None;
    match verify_inner(dir, trusted_tal, &mut code, &mut object) {
        Ok(report) => (
            true,
            serde_json::to_value(report).expect("serializable report"),
        ),
        Err(error) => (
            false,
            serde_json::json!({
                "status": "invalid", "verified_at": Utc::now().to_rfc3339(),
                "error": {"code": code, "object": object, "message": format!("{error:#}")}
            }),
        ),
    }
}

fn verify_inner(
    dir: &Path,
    trusted_tal: Option<&Path>,
    code: &mut &'static str,
    object: &mut Option<String>,
) -> Result<ExperimentReport> {
    let bundle: Bundle = serde_json::from_slice(&fs::read(dir.join("experiment.json"))?)?;
    ensure!(
        matches!(bundle.format_version, 1..=4),
        "unsupported experiment format version"
    );
    *code = "inventory";
    if let Some(request) = &bundle.request {
        ensure!(!bundle.objects.is_empty(), "empty experiment inventory");
        let expected: BTreeMap<_, _> = request
            .objects
            .iter()
            .map(|d| {
                (
                    d.clone().canonicalized().logical_key(),
                    d.clone().canonicalized(),
                )
            })
            .collect();
        let actual: BTreeMap<_, _> = bundle
            .objects
            .values()
            .map(|d| {
                (
                    d.clone().canonicalized().logical_key(),
                    d.clone().canonicalized(),
                )
            })
            .collect();
        ensure!(
            expected.len() == request.objects.len()
                && actual.len() == bundle.objects.len()
                && expected == actual,
            "experiment input and object inventory mismatch"
        );
    }
    let repository = LocalRepository::new(dir);
    let names: BTreeSet<_> = repository.list()?.into_iter().collect();
    ensure!(
        names == bundle.repository_sha256.keys().cloned().collect(),
        "repository inventory mismatch"
    );
    let object_names: BTreeSet<_> = names
        .iter()
        .filter(|name| {
            name.rsplit_once('.')
                .is_some_and(|(_, ext)| ObjectKind::from_extension(ext).is_some())
        })
        .cloned()
        .collect();
    ensure!(
        object_names == bundle.objects.keys().cloned().collect(),
        "signed object inventory mismatch"
    );
    for (name, hash) in &bundle.repository_sha256 {
        *code = "sha256";
        *object = Some(name.clone());
        ensure!(
            digest(&repository.read(name)?) == *hash,
            "SHA-256 mismatch for {name}"
        );
    }
    *object = None;
    // Derive time bounds from DER, never from the unsigned JSON inventory.
    for name in &names {
        *object = Some(name.clone());
        *code = "decode";
        let info = metadata(name, &repository.read(name)?, "", "")?;
        let now = Utc::now().timestamp();
        *code = "not_yet_valid";
        ensure!(
            info.valid_from <= now && info.ee_not_before.is_none_or(|v| v <= now),
            "{name} is not valid yet"
        );
        *code = "expired";
        ensure!(
            info.valid_until >= now && info.ee_not_after.is_none_or(|v| v >= now),
            "{name} has expired"
        );
    }
    *object = None;
    *code = "trust_path";
    let tal = fs::read(
        trusted_tal
            .map(Path::to_path_buf)
            .unwrap_or_else(|| dir.join("trust-anchor.tal")),
    )?;
    let context = match bundle.parent_context.clone() {
        Some(ParentValidationContext::Imported {
            chain_base64,
            crls_base64,
            manifests_base64,
            ..
        }) => ParentValidationContext::Imported {
            tal_base64: STANDARD.encode(&tal),
            chain_base64,
            crls_base64,
            manifests_base64,
        },
        None => ParentValidationContext::imported(&[], &[], &[], &tal),
        _ => anyhow::bail!("bundle context must use a pinned TAL"),
    };
    // Validate the path independently to report trust failures separately.
    let ca_name = names
        .iter()
        .find(|n| n.ends_with(".cer"))
        .context("missing CA")?;
    let cert = Cert::decode(repository.read(ca_name)?.as_slice())?;
    context.validate(&cert)?;
    *code = "publication_set";
    let publication = PublicationSet::load(&repository, &context)?;
    let mut checks = BTreeMap::new();
    for (name, definition) in &bundle.objects {
        *code = "object_profile_payload";
        *object = Some(name.clone());
        definition.validate()?;
        let result = match definition {
            ObjectDefinition::Roa(r) => verify_roa_set(
                &publication,
                name,
                r.asn,
                &r.prefixes
                    .iter()
                    .map(|p| {
                        format!(
                            "{}-{}",
                            p.prefix,
                            p.max_length.unwrap_or(p.prefix.prefix_len())
                        )
                    })
                    .collect::<Vec<_>>(),
            ),
            ObjectDefinition::Aspa(r) => {
                verify_aspa_set(&publication, name, r.customer_asn, &r.provider_asns)
            }
            ObjectDefinition::Toa(r) => verify_toa_set(&publication, name, &r.asns, &r.prefixes),
            ObjectDefinition::Sispi(r) => verify_sispi_set(&publication, name, r.asn, &r.addresses),
        };
        checks.insert(
            name.clone(),
            result.with_context(|| format!("invalid experiment object {name}"))?,
        );
    }
    *object = None;
    *code = "metadata";
    if bundle.format_version >= 2 {
        let ca_uri = bundle
            .files
            .get(ca_name)
            .context("missing CA metadata")?
            .uri
            .clone();
        let mut expected_files = collect_metadata(&repository, &ca_uri)?;
        if bundle.format_version < 4 {
            for (name, expected) in &mut expected_files {
                if bundle
                    .files
                    .get(name)
                    .is_some_and(|file| file.decoded.is_none())
                {
                    expected.decoded = None;
                }
            }
        }
        ensure!(
            bundle.files == expected_files,
            "file metadata differs from signed material"
        );
    }
    if bundle.format_version >= 3 {
        let ca_metadata = bundle.ca_metadata.as_ref().context("missing CA metadata")?;
        ensure!(
            ca_metadata.certificate == metadata::certificate(&repository.read(ca_name)?)?,
            "CA metadata differs from certificate"
        );
        ensure!(
            bundle.parent_materials == metadata::parents(bundle.parent_context.as_ref())?,
            "parent material metadata differs from bundled DER"
        );
        ensure!(
            bundle.profiles == metadata::profiles(&bundle.objects),
            "object profile metadata mismatch"
        );
        if let Some(request) = &bundle.request {
            let mut config = experiment_config(request)?;
            config.certificate_uri = format!(
                "{}/{}",
                config.repository_uri.trim_end_matches('/'),
                ca_name
            );
            ensure!(
                ca_metadata.configuration == metadata::public_config(&config),
                "experiment configuration summary mismatch"
            );
        }
    }
    let manifest_name = names
        .iter()
        .find(|name| name.ends_with(".mft"))
        .context("missing manifest")?;
    let manifest = Manifest::decode(repository.read(manifest_name)?.as_slice(), true)?;
    Ok(ExperimentReport {
        status: "valid",
        verified_at: Utc::now().to_rfc3339(),
        trust: if trusted_tal.is_some() {
            "caller_supplied_tal"
        } else {
            "bundled_tal_not_independently_trusted"
        },
        publication_valid_until: manifest.content().next_update().timestamp(),
        objects: checks,
    })
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Resolve a not-yet-created directory through its nearest existing ancestor.
fn resolved_directory(path: &Path) -> Result<std::path::PathBuf> {
    if path.exists() {
        return Ok(fs::canonicalize(path)?);
    }
    let name = path.file_name().context("ambiguous output directory")?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(resolved_directory(parent)?.join(name))
}

/// Copy one committed publication snapshot while holding the CA's state lock.
/// Does not open the signer, renew anything, or replay pending transactions.
pub fn export(ca_dir: &Path, output: &Path) -> Result<(bool, serde_json::Value)> {
    let ca_dir = fs::canonicalize(ca_dir)?;
    ensure!(!output.exists(), "output already exists");
    let output = resolved_directory(output)?;
    ensure!(
        !output.starts_with(&ca_dir),
        "export must be outside the source CA directory"
    );
    let store = LocalStateStore::new(&ca_dir);
    let (config, state, files) = {
        let _guard = store.lock()?;
        ensure!(
            ca_dir.join("state.toml").is_file(),
            "CA state unavailable; recover the CA before export"
        );
        let state = store.load()?;
        ensure!(
            state.pending_publication().is_none(),
            "publication transaction pending; recover the CA before export"
        );
        let config: CaConfig = toml::from_str(&fs::read_to_string(ca_dir.join("ca.toml"))?)?;
        let repository = LocalRepository::new(&ca_dir);
        let files = repository
            .list()?
            .into_iter()
            .map(|name| {
                let bytes = repository.read(&name)?;
                Ok((name, bytes))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        (config, state, files)
    };
    let objects = [
        ObjectKind::Roa,
        ObjectKind::Aspa,
        ObjectKind::Toa,
        ObjectKind::Sispi,
    ]
    .into_iter()
    .flat_map(|kind| state.signed_objects(kind))
    .map(|view| {
        let definition = view
            .definition
            .with_context(|| format!("{} has no stored definition", view.object_name))?;
        Ok((view.object_name, definition))
    })
    .collect::<Result<BTreeMap<_, _>>>()?;
    let (tal, parent_context) = match state.validation_context() {
        ParentValidationContext::Imported { tal_base64, .. } => (
            STANDARD.decode(tal_base64)?,
            Some(state.validation_context().clone()),
        ),
        ParentValidationContext::DevelopmentTrustAnchor => {
            let bytes = files
                .iter()
                .find(|(n, _)| n.ends_with(".cer"))
                .context("missing CA certificate")?
                .1;
            let cert = Cert::decode(bytes.as_slice())?;
            (
                format!(
                    "{}\n\n{}\n",
                    config.certificate_uri,
                    STANDARD.encode(cert.subject_public_key_info().to_info_bytes())
                )
                .into_bytes(),
                None,
            )
        }
    };
    let parent = output
        .parent()
        .context("output requires a parent directory")?;
    fs::create_dir_all(parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".snapshot-")
        .tempdir_in(parent)?;
    fs::create_dir(staging.path().join("repository"))?;
    let mut hashes = BTreeMap::new();
    for (name, bytes) in files {
        hashes.insert(name.clone(), digest(&bytes));
        fs::write(staging.path().join("repository").join(name), bytes)?;
    }
    fs::write(staging.path().join("trust-anchor.tal"), tal)?;
    let bundle = Bundle {
        format_version: 4,
        ca_metadata: Some(metadata::ca(
            &LocalRepository::new(staging.path()),
            &config,
        )?),
        parent_materials: metadata::parents(parent_context.as_ref())?,
        generator_version: env!("CARGO_PKG_VERSION").into(),
        created_at: Utc::now().to_rfc3339(),
        request: None,
        source: "existing_ca_snapshot".into(),
        parent_context,
        profiles: metadata::profiles(&objects),
        objects,
        repository_sha256: hashes,
        files: collect_metadata(
            &LocalRepository::new(staging.path()),
            &config.certificate_uri,
        )?,
    };
    fs::write(
        staging.path().join("experiment.json"),
        serde_json::to_vec_pretty(&bundle)?,
    )?;
    let report = verification_report(staging.path(), None);
    fs::write(
        staging.path().join("verification.json"),
        serde_json::to_vec_pretty(&report.1)?,
    )?;
    ensure!(!output.exists(), "output appeared during export");
    fs::rename(staging.path(), output)?;
    Ok(report)
}

#[cfg(test)]
#[path = "../tests/unit/experiment.rs"]
mod tests;
