use super::*;
use crate::ca::state::StateGuard;
use crate::infrastructure::{
    repository::PublicationRepository, signing::SoftwareSigner, state_store::LocalStateStore,
};
use crate::{CaManager, RoaPayload};
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
    let roa_name = state.published_name("roa:example.roa").unwrap();
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
    let crl_data = fs::read(repository_file(dir.path(), "crl")).unwrap();
    let crl = Crl::decode(crl_data.as_slice()).unwrap();
    crl.verify_signature(resource_cert.subject_public_key_info())
        .unwrap();
    decoded.process(&resource_cert, true, |_| Ok(())).unwrap();
    let manifest_data = fs::read(repository_file(dir.path(), "mft")).unwrap();
    let manifest = Manifest::decode(manifest_data.as_slice(), true).unwrap();
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
    let ca = CaManager::import(
        imported.path(),
        import_config,
        crate::CaImportRequest {
            certificate: fs::read(certificate_path).unwrap(),
            private_key_pem: fs::read_to_string(source.path().join("ca.key")).unwrap(),
            serial_start: 50_000,
            crl_number_start: 1,
            manifest_number_start: 1,
            chain: vec![],
            crls: vec![],
            manifests: vec![],
        },
    )
    .unwrap();
    ca.sign_roa(&request("192.0.2.0/24"), "imported.roa")
        .unwrap();
    let state = LocalStateStore::new(imported.path()).load().unwrap();
    assert_eq!(state.next_certificate_serial(), 50_003);
}

#[test]
fn replacement_revokes_old_roa_and_manifest_certificates() {
    let dir = tempfile::tempdir().unwrap();
    let ca = CaManager::init(dir.path(), CaConfig::default()).unwrap();
    ca.sign_roa(&request("192.0.2.0/24"), "example.roa")
        .unwrap();
    let before = LocalStateStore::new(dir.path()).load().unwrap();
    let old_name = before.published_name("roa:example.roa").unwrap();
    let old_roa = before.object(old_name).unwrap().serial;
    let old_manifest = before.manifest_ee().unwrap().serial;

    ca.sign_roa(&request("192.0.2.0/24"), "example.roa")
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
