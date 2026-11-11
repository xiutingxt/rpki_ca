use crate::ca::{ImportedCa, publication};
use crate::infrastructure::{
    repository::LocalRepository,
    signing::{SigningProvider, SoftwareSigner},
    state_store::LocalStateStore,
};
use crate::{
    AspaDelta, AspaRequest, CaCertificateRenewal, CaCertificateStatus, CaConfig, CaImportRequest,
    CaValidationContextUpdate, CertificateAuthority, ObjectDefinition, ObjectDeltaResponse,
    ObjectWithdrawal, RoaConfigurationView, RoaDelta, RoaDeltaResponse, RoaRequest, SispiDelta,
    SispiRequest, ToaDelta, ToaRequest, ToaReviewStatus,
};
use anyhow::{Context, Result, bail};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{collections::BTreeSet, fs, path::Path, sync::Arc};

const CONFIG_FILE: &str = "ca.toml";
const KEY_FILE: &str = "ca.key";

/// Application service that wires domain logic to the configured adapters.
pub struct CaManager {
    ca: CertificateAuthority,
}

impl CaManager {
    pub fn init(root: impl AsRef<Path>, mut config: CaConfig) -> Result<Self> {
        let root = root.as_ref();
        config.validate_development()?;
        create_transaction(root, move |staging| {
            let (signer, pem) = SoftwareSigner::generate().map_err(anyhow::Error::msg)?;
            let certificate_name =
                format!("{}.cer", publication::key_basename(&signer.public_key()?));
            let mut repository_uri = config.repository_uri.clone();
            if !repository_uri.ends_with('/') {
                repository_uri.push('/');
            }
            config.certificate_uri = format!("{repository_uri}{certificate_name}");
            save_config(staging, &config)?;
            save_private_key(staging, pem.as_bytes())?;
            CertificateAuthority::init(
                config,
                Arc::new(LocalRepository::new(staging)),
                Arc::new(LocalStateStore::new(staging)),
                Arc::new(signer),
            )?;
            Ok(())
        })?;
        Self::open(root)
    }

    pub fn import(
        root: impl AsRef<Path>,
        config: CaConfig,
        request: CaImportRequest,
    ) -> Result<Self> {
        let root = root.as_ref();
        validate_config(&config)?;
        if request.publication_number_start != 1 {
            bail!(
                "historical CA takeover requires object inventory and revocation-state migration; only a fresh publication point with publication number start 1 is currently accepted"
            );
        }
        create_transaction(root, move |staging| {
            let signer = SoftwareSigner::from_pem(&request.private_key_pem)
                .map_err(anyhow::Error::msg)
                .context("invalid CA private key")?;
            save_config(staging, &config)?;
            save_private_key(staging, request.private_key_pem.as_bytes())?;
            CertificateAuthority::import(
                config,
                ImportedCa {
                    certificate: request.certificate,
                    serial_start: request.serial_start,
                    publication_number_start: request.publication_number_start,
                    chain: request.chain,
                    crls: request.crls,
                    manifests: request.manifests,
                    tal: request.tal,
                },
                Arc::new(LocalRepository::new(staging)),
                Arc::new(LocalStateStore::new(staging)),
                Arc::new(signer),
            )?;
            Ok(())
        })?;
        Self::open(root)
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        let config = load_config(root)?;
        validate_config(&config)?;
        let pem = fs::read_to_string(root.join(KEY_FILE)).context("cannot read CA private key")?;
        let signer = SoftwareSigner::from_pem(&pem)
            .map_err(anyhow::Error::msg)
            .context("invalid CA private key")?;
        let ca = CertificateAuthority::open(
            config,
            Arc::new(LocalRepository::new(root)),
            Arc::new(LocalStateStore::new(root)),
            Arc::new(signer),
        )?;
        Ok(Self { ca })
    }

    pub fn sign_roa(&self, request: &RoaRequest, object_name: &str) -> Result<Vec<u8>> {
        self.ca.sign_roa(request, object_name)
    }

    pub fn update_roas(&self, delta: RoaDelta) -> Result<RoaDeltaResponse> {
        self.ca.update_roas(delta)
    }

    pub fn roa_configurations(&self) -> Result<Vec<RoaConfigurationView>> {
        self.ca.roa_configurations()
    }

    pub fn sign_aspa(&self, request: &AspaRequest, object_name: &str) -> Result<Vec<u8>> {
        self.ca.sign_aspa(request, object_name)
    }

    pub fn update_aspas(&self, delta: AspaDelta) -> Result<ObjectDeltaResponse> {
        self.ca.update_aspas(delta)
    }

    pub fn update_sispis(&self, delta: SispiDelta) -> Result<ObjectDeltaResponse> {
        self.ca.update_sispis(delta)
    }

    pub fn update_toas(&self, delta: ToaDelta) -> Result<ObjectDeltaResponse> {
        self.ca.update_toas(delta)
    }

    pub fn sign_toa(&self, request: &ToaRequest, object_name: &str) -> Result<Vec<u8>> {
        self.ca.sign_toa(request, object_name)
    }

    pub fn sign_sispi(&self, request: &SispiRequest, object_name: &str) -> Result<Vec<u8>> {
        self.ca.sign_sispi(request, object_name)
    }

    pub fn withdraw_aspa(&self, customer_asn: u32) -> Result<bool> {
        self.ca.withdraw_aspa(customer_asn)
    }

    pub fn withdraw_toa(&self, object_name: &str) -> Result<bool> {
        self.ca.withdraw_toa(object_name)
    }

    pub fn withdraw_sispi(&self, asn: u32) -> Result<bool> {
        self.ca.withdraw_sispi(asn)
    }

    pub fn withdraw_published_object(&self, object_name: &str) -> Result<Option<ObjectWithdrawal>> {
        self.ca.withdraw_published_object(object_name)
    }

    pub(crate) fn withdraw_signed_object(
        &self,
        logical_key: &str,
        kind: crate::ObjectKind,
    ) -> Result<Option<ObjectWithdrawal>> {
        self.ca.withdraw_signed_object(logical_key, kind)
    }

    pub fn list_published_signed_objects(&self) -> Result<BTreeSet<String>> {
        self.ca.list_published_signed_objects()
    }

    pub fn issue_object(
        &self,
        definition: ObjectDefinition,
        object_name: &str,
    ) -> Result<crate::SignedObjectIssuance> {
        let output = self.ca.sign_object(definition, object_name)?;
        Ok(crate::SignedObjectIssuance {
            name: output.name,
            bytes: output.bytes,
            advisories: output.advisories,
        })
    }

    pub fn published_name(&self, logical_key: &str) -> Result<Option<String>> {
        self.ca.published_name(logical_key)
    }

    pub(crate) fn signed_object(
        &self,
        logical_key: &str,
    ) -> Result<Option<crate::SignedObjectView>> {
        self.ca.signed_object(logical_key)
    }

    pub fn signed_objects(&self, kind: crate::ObjectKind) -> Result<Vec<crate::SignedObjectView>> {
        self.ca.signed_objects(kind)
    }

    pub fn refresh(&self) -> Result<()> {
        self.ca.refresh()
    }

    pub fn refresh_if_needed(&self) -> Result<bool> {
        self.ca.refresh_if_needed()
    }

    pub fn certificate_status(&self) -> Result<CaCertificateStatus> {
        self.ca.certificate_status()
    }

    pub fn certified_resources(&self) -> Result<crate::CertifiedResourcesView> {
        self.ca.certified_resources()
    }

    pub fn renew_certificate(&self, renewal: CaCertificateRenewal) -> Result<()> {
        self.ca.renew_certificate(renewal)
    }

    pub fn update_validation_context(&self, update: CaValidationContextUpdate) -> Result<()> {
        self.ca.update_validation_context(update)
    }

    pub fn toa_review_statuses(&self) -> Result<Vec<ToaReviewStatus>> {
        self.ca.toa_review_statuses()
    }

    pub fn review_toa(
        &self,
        object_name: &str,
        roa_overlap_justification: Option<String>,
    ) -> Result<ToaReviewStatus> {
        self.ca.review_toa(object_name, roa_overlap_justification)
    }

    pub fn read_published_object(&self, name: &str) -> Result<Vec<u8>> {
        self.ca.read_published_object(name)
    }

    pub fn list_published_objects(&self) -> Result<Vec<String>> {
        self.ca.list_published_objects()
    }

    pub fn validate_published_object(&self, name: &str) -> Result<crate::ValidationReport> {
        self.ca.validate_published_object(name)
    }

    pub fn has_published_object(&self, name: &str) -> Result<bool> {
        self.ca.has_published_object(name)
    }
}

fn validate_config(config: &CaConfig) -> Result<()> {
    config.validate()
}

fn save_config(root: &Path, config: &CaConfig) -> Result<()> {
    fs::write(root.join(CONFIG_FILE), toml::to_string_pretty(config)?)
        .context("cannot persist CA configuration")
}

fn save_private_key(root: &Path, value: &[u8]) -> Result<()> {
    let path = root.join(KEY_FILE);
    #[cfg(unix)]
    {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .context("cannot securely create CA private key")?;
        file.write_all(value)?;
        file.sync_all()?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    fs::write(&path, value).context("cannot persist CA private key")?;
    Ok(())
}

fn load_config(root: &Path) -> Result<CaConfig> {
    let path = root.join(CONFIG_FILE);
    let text = fs::read_to_string(&path)
        .with_context(|| format!("cannot read configuration {}", path.display()))?;
    toml::from_str(&text).context("invalid CA configuration")
}

fn ensure_uninitialized(root: &Path) -> Result<()> {
    if root.join(KEY_FILE).exists() || root.join(CONFIG_FILE).exists() {
        bail!("CA already exists at {}", root.display());
    }
    Ok(())
}

fn create_transaction(root: &Path, operation: impl FnOnce(&Path) -> Result<()>) -> Result<()> {
    ensure_uninitialized(root)?;
    if root.exists() && fs::read_dir(root)?.next().is_some() {
        bail!("CA target directory must be empty: {}", root.display());
    }
    let parent = root
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".rpki-ca-create-")
        .tempdir_in(parent)
        .context("cannot create CA staging directory")?;
    operation(staging.path()).context("CA creation transaction failed")?;

    // Recheck immediately before commit so a concurrently populated target
    // is never overwritten.
    if root.exists() {
        if fs::read_dir(root)?.next().is_some() {
            bail!(
                "CA target directory changed during creation: {}",
                root.display()
            );
        }
        fs::remove_dir(root).context("cannot remove empty CA target before commit")?;
    }
    fs::rename(staging.path(), root).context("cannot commit CA creation transaction")?;
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/application/manager.rs"]
mod tests;
