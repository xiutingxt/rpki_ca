use super::*;
use crate::ca::state::StateGuard;
use crate::infrastructure::{
    repository::PublicationRepository, signing::SoftwareSigner, state_store::LocalStateStore,
};
use crate::{CaManager, RoaPayload};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rpki::repository::{crl::Crl, manifest::Manifest, roa::Roa, tal::TalInfo};
use std::{fs, sync::Mutex};

fn repository_file(root: &std::path::Path, extension: &str) -> std::path::PathBuf {
    fs::read_dir(root.join("repository"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().and_then(|value| value.to_str()) == Some(extension))
        .unwrap()
}

fn memory_name(repository: &MemoryRepository, extension: &str) -> String {
    repository
        .list()
        .unwrap()
        .into_iter()
        .find(|name| name.ends_with(&format!(".{extension}")))
        .unwrap()
}

fn tal_for(cert: &Cert) -> Vec<u8> {
    format!(
        "rsync://localhost/rpki/ta.cer\n\n{}\n",
        STANDARD.encode(cert.subject_public_key_info().to_info_bytes())
    )
    .into_bytes()
}

#[derive(Default)]
struct MemoryRepository(Mutex<BTreeMap<String, Vec<u8>>>);

impl PublicationRepository for MemoryRepository {
    fn initialize(&self) -> Result<()> {
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>> {
        Ok(self.0.lock().unwrap().keys().cloned().collect())
    }

    fn read(&self, name: &str) -> Result<Vec<u8>> {
        self.0
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .context("object not found")
    }

    fn publish(&self, update: PublicationUpdate) -> Result<()> {
        let mut objects = self.0.lock().unwrap();
        for name in update.withdraw {
            objects.remove(&name);
        }
        objects.extend(update.publish);
        Ok(())
    }

    fn recover(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct MemoryStateStore(Mutex<Option<CaState>>);
struct MemoryGuard;
impl StateGuard for MemoryGuard {}

impl CaStateStore for MemoryStateStore {
    fn initialize(&self, state: &CaState) -> Result<()> {
        *self.0.lock().unwrap() = Some(state.clone());
        Ok(())
    }

    fn load(&self) -> Result<CaState> {
        self.0.lock().unwrap().clone().context("state not found")
    }

    fn save(&self, state: &CaState) -> Result<()> {
        *self.0.lock().unwrap() = Some(state.clone());
        Ok(())
    }

    fn lock(&self) -> Result<Box<dyn StateGuard>> {
        Ok(Box::new(MemoryGuard))
    }
}

fn request(prefix: &str) -> RoaRequest {
    let prefix: ipnet::IpNet = prefix.parse().unwrap();
    RoaRequest {
        asn: 64496,
        prefixes: vec![RoaPayload {
            max_length: Some(prefix.prefix_len()),
            prefix,
        }],
    }
}

#[test]
fn domain_ca_operates_without_a_filesystem() {
    let repository = Arc::new(MemoryRepository::default());
    let state = Arc::new(MemoryStateStore::default());
    let (signer, _) = SoftwareSigner::generate().unwrap();
    let ca = CertificateAuthority::init(
        CaConfig::default(),
        repository.clone(),
        state,
        Arc::new(signer),
    )
    .unwrap();

    let bytes = ca.sign_roa(&request("192.0.2.0/24"), "memory.roa").unwrap();
    Roa::decode(bytes.as_slice(), true).unwrap();
    let roa_name = memory_name(&repository, "roa");
    assert_eq!(roa_name.strip_suffix(".roa").unwrap().len(), 27);
    assert!(repository.read(&roa_name).is_ok());
    assert!(repository.read(&memory_name(&repository, "crl")).is_ok());
    assert!(repository.read(&memory_name(&repository, "mft")).is_ok());
    let cert_name = memory_name(&repository, "cer");
    let crl_name = memory_name(&repository, "crl");
    let manifest_name = memory_name(&repository, "mft");
    let cert_stem = cert_name.strip_suffix(".cer").unwrap();
    assert_eq!(cert_stem.len(), 27);
    assert_eq!(crl_name.strip_suffix(".crl"), Some(cert_stem));
    assert_eq!(manifest_name.strip_suffix(".mft"), Some(cert_stem));
}

#[test]
fn applies_per_object_validity_with_clock_skew_and_ca_cap() {
    let repository = Arc::new(MemoryRepository::default());
    let state = Arc::new(MemoryStateStore::default());
    let (signer, _) = SoftwareSigner::generate().unwrap();
    let mut config = CaConfig::default();
    config.timing.roa_valid_weeks = 1;
    config.timing.aspa_valid_weeks = 2;
    let ca = CertificateAuthority::init(config, repository, state, Arc::new(signer)).unwrap();
    let cert = ca.certificate().unwrap();
    let before = Time::now();
    let roa = ca.object_validity(&cert, ObjectKind::Roa).unwrap();
    let aspa = ca.object_validity(&cert, ObjectKind::Aspa).unwrap();

    assert!(roa.not_before() < before);
    assert!(before.timestamp() - roa.not_before().timestamp() >= 299);
    assert!(aspa.not_after() > roa.not_after());
    assert!(aspa.not_after() <= cert.validity().not_after());
}

#[test]
fn signs_only_covered_resources_and_updates_repository() {
    let dir = tempfile::tempdir().unwrap();
    let ca = CaManager::init(dir.path(), CaConfig::default()).unwrap();
    let data = ca
        .sign_roa(&request("192.0.2.0/24"), "example.roa")
        .unwrap();
    let decoded = Roa::decode(data.as_slice(), true).unwrap();
    assert_eq!(u32::from(decoded.content().as_id()), 64496);
    let state = LocalStateStore::new(dir.path()).load().unwrap();
    let roa_name = state.published_name("roa:AS64496").unwrap();
    assert_eq!(
        roa_name,
        publication::key_filename(&decoded.cert().subject_key_identifier(), "roa")
    );
    let resource_cert = Cert::decode(
        fs::read(repository_file(dir.path(), "cer"))
            .unwrap()
            .as_slice(),
    )
    .unwrap()
    .validate_ta(TalInfo::from_name("test".into()).into_arc(), true)
    .unwrap();
    assert_eq!(resource_cert.overclaim(), Overclaim::Refuse);
    assert_eq!(decoded.cert().overclaim(), Overclaim::Refuse);
    let crl_data = fs::read(repository_file(dir.path(), "crl")).unwrap();
    let crl = Crl::decode(crl_data.as_slice()).unwrap();
    crl.verify_signature(resource_cert.subject_public_key_info())
        .unwrap();
    decoded.process(&resource_cert, true, |_| Ok(())).unwrap();
    let manifest_data = fs::read(repository_file(dir.path(), "mft")).unwrap();
    let manifest = Manifest::decode(manifest_data.as_slice(), true).unwrap();
    assert_eq!(manifest.cert().overclaim(), Overclaim::Refuse);
    assert_eq!(crl.crl_number(), manifest.content().manifest_number());
    assert_eq!(
        manifest.cert().validity().not_before(),
        manifest.content().this_update()
    );
    assert_eq!(
        manifest.cert().validity().not_after(),
        manifest.content().next_update()
    );
    manifest.validate(&resource_cert, true).unwrap();
    assert!(ca.sign_roa(&request("198.51.100.0/24"), "bad.roa").is_err());
}

#[test]
fn rejects_unregistered_manifest_member_extensions() {
    assert!(CertificateAuthority::validate_manifest_member_name("valid.roa").is_ok());
    assert!(CertificateAuthority::validate_manifest_member_name("valid.toa").is_ok());
    assert!(CertificateAuthority::validate_manifest_member_name("valid.sav").is_ok());
    assert!(CertificateAuthority::validate_manifest_member_name("invalid.xyz").is_err());
}

#[test]
fn imports_matching_resource_certificate() {
    let source = tempfile::tempdir().unwrap();
    CaManager::init(source.path(), CaConfig::default()).unwrap();
    let imported = tempfile::tempdir().unwrap();
    let certificate_path = repository_file(source.path(), "cer");
    let certificate_name = certificate_path.file_name().unwrap().to_str().unwrap();
    let import_config = CaConfig {
        certificate_uri: format!("rsync://localhost/rpki/{certificate_name}"),
        ..CaConfig::default()
    };
    let imported_cert = Cert::decode(fs::read(certificate_path).unwrap().as_slice()).unwrap();
    let ca = CaManager::import(
        imported.path(),
        import_config,
        crate::CaImportRequest {
            certificate: imported_cert.to_captured().into_bytes().to_vec(),
            private_key_pem: fs::read_to_string(source.path().join("ca.key")).unwrap(),
            serial_start: 50_000,
            publication_number_start: 1,
            chain: vec![],
            crls: vec![],
            manifests: vec![],
            tal: tal_for(&imported_cert),
        },
    )
    .unwrap();
    ca.sign_roa(&request("192.0.2.0/24"), "imported.roa")
        .unwrap();
    let state = LocalStateStore::new(imported.path()).load().unwrap();
    assert_eq!(state.next_certificate_serial(), 50_003);
}

#[test]
fn imported_subordinate_revalidates_the_full_path_to_its_tal() {
    let parent_repository = Arc::new(MemoryRepository::default());
    let parent_state = Arc::new(MemoryStateStore::default());
    let (parent_signer, _) = SoftwareSigner::generate().unwrap();
    let parent_signer = Arc::new(parent_signer);
    let parent = CertificateAuthority::init(
        CaConfig::default(),
        parent_repository.clone(),
        parent_state,
        parent_signer.clone(),
    )
    .unwrap();
    let parent_cert = parent.certificate().unwrap();
    let parent_cert_name = memory_name(&parent_repository, "cer");
    let parent_crl_name = memory_name(&parent_repository, "crl");
    let parent_base = uri::Rsync::from_str("rsync://localhost/rpki/").unwrap();

    let (child_signer, _) = SoftwareSigner::generate().unwrap();
    let child_public_key = child_signer.public_key().unwrap();
    let child_cert_name = publication::key_filename(&child_public_key.key_identifier(), "cer");
    let child_manifest_name = publication::key_filename(&child_public_key.key_identifier(), "mft");
    let child_base = uri::Rsync::from_str("rsync://localhost/child/").unwrap();
    let mut child_tbs = TbsCert::new(
        9_000u64.into(),
        parent_cert.subject().clone(),
        Validity::from_secs(30 * 86_400),
        None,
        child_public_key,
        KeyUsage::Ca,
        Overclaim::Trim,
    );
    child_tbs.set_basic_ca(Some(true));
    child_tbs.set_authority_key_identifier(Some(parent_cert.subject_key_identifier()));
    child_tbs.set_crl_uri(Some(parent_base.join(parent_crl_name.as_bytes()).unwrap()));
    child_tbs.set_ca_issuer(Some(parent_base.join(parent_cert_name.as_bytes()).unwrap()));
    child_tbs.set_ca_repository(Some(child_base.clone()));
    child_tbs.set_rpki_manifest(Some(
        child_base.join(child_manifest_name.as_bytes()).unwrap(),
    ));
    child_tbs.build_v4_resource_blocks(|blocks| {
        blocks.push(Prefix::new(
            "192.0.2.0".parse::<std::net::Ipv4Addr>().unwrap(),
            24,
        ));
    });
    child_tbs.build_v6_resource_blocks(|blocks| {
        blocks.push(Prefix::new(
            "2001:db8::".parse::<std::net::Ipv6Addr>().unwrap(),
            48,
        ));
    });
    child_tbs.build_as_resource_blocks(|blocks| blocks.push(AsBlock::Id(64496.into())));
    let child_cert = parent_signer.sign_ca_certificate(child_tbs).unwrap();
    parent_repository
        .publish(PublicationUpdate {
            publish: BTreeMap::from([(
                child_cert_name.clone(),
                child_cert.to_captured().into_bytes().to_vec(),
            )]),
            withdraw: BTreeSet::new(),
        })
        .unwrap();
    parent.refresh().unwrap();

    let parent_crl = parent_repository
        .read(&memory_name(&parent_repository, "crl"))
        .unwrap();
    let parent_manifest = parent_repository
        .read(&memory_name(&parent_repository, "mft"))
        .unwrap();
    let child_root = tempfile::tempdir().unwrap();
    let child_repository = Arc::new(crate::infrastructure::repository::LocalRepository::new(
        child_root.path(),
    ));
    let child_state = Arc::new(LocalStateStore::new(child_root.path()));
    let child = CertificateAuthority::import(
        CaConfig {
            name: "imported-child".into(),
            repository_uri: child_base.to_string(),
            certificate_uri: parent_base
                .join(child_cert_name.as_bytes())
                .unwrap()
                .to_string(),
            ..CaConfig::default()
        },
        ImportedCa {
            certificate: child_cert.to_captured().into_bytes().to_vec(),
            serial_start: 10_000,
            publication_number_start: 1,
            chain: vec![parent_cert.to_captured().into_bytes().to_vec()],
            crls: vec![parent_crl.clone()],
            manifests: vec![parent_manifest.clone()],
            tal: tal_for(&parent_cert),
        },
        child_repository.clone(),
        child_state,
        Arc::new(child_signer),
    )
    .unwrap();
    child
        .sign_roa(&request("192.0.2.0/24"), "child.roa")
        .unwrap();
    let roa_name = repository_file(child_root.path(), "roa")
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let report = child.validate_published_object(&roa_name).unwrap();
    assert_eq!(report.overall, crate::ValidationStatus::Valid);
    assert_eq!(
        report.scope,
        "configured_trust_anchor_to_current_publication"
    );
    assert!(report.checks[0].message.contains("配置的 TAL"));

    // This lower-level fixture bypasses CaManager's configuration persistence.
    fs::write(
        child_root.path().join("ca.toml"),
        toml::to_string(&CaConfig {
            name: "imported-child".into(),
            repository_uri: child_base.to_string(),
            certificate_uri: parent_base
                .join(child_cert_name.as_bytes())
                .unwrap()
                .to_string(),
            ..CaConfig::default()
        })
        .unwrap(),
    )
    .unwrap();
    let exported_root = tempfile::tempdir().unwrap();
    let exported = exported_root.path().join("snapshot");
    let (valid, exported_report) = crate::experiment::export(child_root.path(), &exported).unwrap();
    assert!(valid, "{exported_report}");
    assert!(crate::experiment::verify(&exported, None).is_ok());
    let inventory: serde_json::Value =
        serde_json::from_slice(&fs::read(exported.join("experiment.json")).unwrap()).unwrap();
    assert_eq!(inventory["parent_context"]["mode"], "imported");
    let materials = inventory["parent_materials"].as_array().unwrap();
    assert_eq!(materials.len(), 3);
    assert_eq!(materials[0]["source"], "parent_context.chain_base64[0]");
    assert!(
        materials[0]["details"]["not_after_utc"]
            .as_str()
            .unwrap()
            .ends_with('Z')
    );
    assert!(
        materials[1]["details"]["next_update_utc"]
            .as_str()
            .unwrap()
            .ends_with('Z')
    );
    assert!(materials[2]["details"]["ee_certificate"]["not_after_utc"].is_string());
    let mut tampered = inventory.clone();
    tampered["parent_materials"][1]["details"]["next_update"] = 0.into();
    fs::write(
        exported.join("experiment.json"),
        serde_json::to_vec_pretty(&tampered).unwrap(),
    )
    .unwrap();
    let (valid, report) = crate::experiment::verification_report(&exported, None);
    assert!(!valid);
    assert_eq!(report["error"]["code"], "metadata");
    fs::write(
        exported.join("experiment.json"),
        serde_json::to_vec_pretty(&inventory).unwrap(),
    )
    .unwrap();
    let info = crate::ca_info(child_root.path()).unwrap();
    assert_eq!(info["mode"], "imported");
    assert_eq!(
        info["certificate"]["repository_uri"],
        child_base.to_string()
    );

    let mut broken_manifest = parent_manifest;
    let last = broken_manifest.last_mut().unwrap();
    *last ^= 0x01;
    assert!(
        child
            .update_validation_context(CaValidationContextUpdate {
                chain: vec![parent_cert.to_captured().into_bytes().to_vec()],
                crls: vec![parent_crl],
                manifests: vec![broken_manifest],
                tal: tal_for(&parent_cert),
            })
            .is_err()
    );
    assert_eq!(
        child.validate_published_object(&roa_name).unwrap().overall,
        crate::ValidationStatus::Valid
    );
}

#[test]
fn replacement_revokes_old_roa_and_manifest_certificates() {
    let dir = tempfile::tempdir().unwrap();
    let ca = CaManager::init(dir.path(), CaConfig::default()).unwrap();
    ca.sign_roa(&request("192.0.2.0/24"), "example.roa")
        .unwrap();
    let before = LocalStateStore::new(dir.path()).load().unwrap();
    let old_name = before.published_name("roa:AS64496").unwrap();
    let old_roa = before.object(old_name).unwrap().serial;
    let old_manifest = before.manifest_ee().unwrap().serial;

    ca.sign_roa(&request("2001:db8::/48"), "example.roa")
        .unwrap();
    let crl = Crl::decode(
        fs::read(repository_file(dir.path(), "crl"))
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    assert!(crl.contains(old_roa.into()));
    assert!(crl.contains(old_manifest.into()));
}

#[test]
fn rejects_duplicate_roa_authorization_without_reissuing() {
    let dir = tempfile::tempdir().unwrap();
    let ca = CaManager::init(dir.path(), CaConfig::default()).unwrap();
    ca.sign_roa(&request("192.0.2.0/24"), "first.roa").unwrap();
    let before = LocalStateStore::new(dir.path()).load().unwrap();
    let before_name = before.published_name("roa:AS64496").unwrap().to_owned();

    let error = ca
        .sign_roa(&request("192.0.2.0/24"), "second.roa")
        .unwrap_err();
    let rejected = error.downcast_ref::<RoaDeltaRejected>().unwrap();
    assert_eq!(rejected.0.duplicates.len(), 1);

    let after = LocalStateStore::new(dir.path()).load().unwrap();
    assert_eq!(
        after.published_name("roa:AS64496"),
        Some(before_name.as_str())
    );
}

#[test]
fn renews_ca_certificate_and_atomically_refreshes_publication_metadata() {
    let repository = Arc::new(MemoryRepository::default());
    let state = Arc::new(MemoryStateStore::default());
    let (signer, _) = SoftwareSigner::generate().unwrap();
    let ca = CertificateAuthority::init(
        CaConfig::default(),
        repository.clone(),
        state,
        Arc::new(signer),
    )
    .unwrap();
    ca.sign_roa(&request("192.0.2.0/24"), "before-renewal.roa")
        .unwrap();
    let roa_name = memory_name(&repository, "roa");
    let old = ca.certificate().unwrap();
    let manifest_name = memory_name(&repository, "mft");
    let old_manifest = repository.read(&manifest_name).unwrap();
    let replacement = ca
        .development_ta_certificate(2, Validity::from_secs(730 * 86_400))
        .unwrap();

    ca.renew_certificate(CaCertificateRenewal {
        certificate: replacement.to_captured().into_bytes().to_vec(),
        chain: vec![],
        crls: vec![],
        manifests: vec![],
        tal: tal_for(&replacement),
    })
    .unwrap();

    let renewed = ca.certificate().unwrap();
    assert!(renewed.validity().not_after() > old.validity().not_after());
    assert_ne!(repository.read(&manifest_name).unwrap(), old_manifest);
    assert!(repository.read(&roa_name).is_ok());
    let manifest =
        Manifest::decode(repository.read(&manifest_name).unwrap().as_slice(), true).unwrap();
    manifest
        .validate(
            &renewed
                .validate_ta(TalInfo::from_name("renewed".into()).into_arc(), true)
                .unwrap(),
            true,
        )
        .unwrap();
}

#[test]
fn certificate_status_uses_configured_renewal_window() {
    let repository = Arc::new(MemoryRepository::default());
    let state = Arc::new(MemoryStateStore::default());
    let (signer, _) = SoftwareSigner::generate().unwrap();
    let config = CaConfig {
        ca_renew_before_days: 366,
        ..CaConfig::default()
    };
    let ca = CertificateAuthority::init(config, repository, state, Arc::new(signer)).unwrap();

    let status = ca.certificate_status().unwrap();
    assert!(!status.expired);
    assert!(status.renewal_required);
    assert!(status.not_before < status.not_after);
}
