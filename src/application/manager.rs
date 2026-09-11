use crate::ca::{ImportedCa, publication};
use crate::infrastructure::{
    repository::LocalRepository,
    signing::{SignedObjectOutput, SigningProvider, SoftwareSigner},
    state_store::LocalStateStore,
};
use crate::{
    AspaRequest, CaCertificateRenewal, CaCertificateStatus, CaConfig, CaImportRequest,
    CertificateAuthority, ObjectDefinition, RoaRequest,
};
use anyhow::{Context, Result, bail};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{fs, path::Path, sync::Arc};

const CONFIG_FILE: &str = "ca.toml";
const KEY_FILE: &str = "ca.key";

/// Application service that wires domain logic to the configured adapters.
pub struct CaManager {
    ca: CertificateAuthority,
}

impl CaManager {
    pub fn init(root: impl AsRef<Path>, mut config: CaConfig) -> Result<Self> {
        let root = root.as_ref();
        validate_config(&config)?;
        ensure_uninitialized(root)?;
        fs::create_dir_all(root)?;
        let (signer, pem) = SoftwareSigner::generate().map_err(anyhow::Error::msg)?;
        let certificate_name = format!("{}.cer", publication::key_basename(&signer.public_key()?));
        let mut repository_uri = config.repository_uri.clone();
        if !repository_uri.ends_with('/') {
            repository_uri.push('/');
        }
        config.certificate_uri = format!("{repository_uri}{certificate_name}");
        save_config(root, &config)?;
        save_private_key(root, pem.as_bytes())?;
        let ca = CertificateAuthority::init(
            config,
            Arc::new(LocalRepository::new(root)),
            Arc::new(LocalStateStore::new(root)),
            Arc::new(signer),
        )?;
        Ok(Self { ca })
    }

    pub fn import(
        root: impl AsRef<Path>,
        config: CaConfig,
        request: CaImportRequest,
    ) -> Result<Self> {
        let root = root.as_ref();
        validate_config(&config)?;
        ensure_uninitialized(root)?;
        if request.crl_number_start != 1 || request.manifest_number_start != 1 {
            bail!(
                "historical CA takeover requires object inventory and revocation-state migration; only a fresh publication point with CRL and Manifest starts of 1 is currently accepted"
            );
        }
        fs::create_dir_all(root)?;
        let signer = SoftwareSigner::from_pem(&request.private_key_pem)
            .map_err(anyhow::Error::msg)
            .context("invalid CA private key")?;
        save_config(root, &config)?;
        save_private_key(root, request.private_key_pem.as_bytes())?;
        let ca = CertificateAuthority::import(
            config,
            ImportedCa {
                certificate: request.certificate,
                serial_start: request.serial_start,
                crl_number_start: request.crl_number_start,
                manifest_number_start: request.manifest_number_start,
                chain: request.chain,
                crls: request.crls,
                manifests: request.manifests,
            },
            Arc::new(LocalRepository::new(root)),
            Arc::new(LocalStateStore::new(root)),
            Arc::new(signer),
        )?;
        Ok(Self { ca })
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

    pub fn sign_aspa(&self, request: &AspaRequest, object_name: &str) -> Result<Vec<u8>> {
        self.ca.sign_aspa(request, object_name)
    }

    pub fn withdraw_roa(&self, object_name: &str) -> Result<bool> {
        self.ca.withdraw_roa(object_name)
    }

    pub fn withdraw_aspa(&self, customer_asn: u32) -> Result<bool> {
        self.ca.withdraw_aspa(customer_asn)
    }

    pub(crate) fn sign_object(
        &self,
        definition: ObjectDefinition,
        object_name: &str,
    ) -> Result<SignedObjectOutput> {
        self.ca.sign_object(definition, object_name)
    }

    pub fn published_name(&self, logical_key: &str) -> Result<Option<String>> {
        self.ca.published_name(logical_key)
    }

    pub(crate) fn withdraw_definition(
        &self,
        definition: &ObjectDefinition,
        requested_name: &str,
    ) -> Result<bool> {
        self.ca.withdraw_definition(definition, requested_name)
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

    pub fn renew_certificate(&self, renewal: CaCertificateRenewal) -> Result<()> {
        self.ca.renew_certificate(renewal)
    }

    pub fn read_published_object(&self, name: &str) -> Result<Vec<u8>> {
        self.ca.read_published_object(name)
    }

    pub fn has_published_object(&self, name: &str) -> Result<bool> {
        self.ca.has_published_object(name)
    }
}

fn validate_config(config: &CaConfig) -> Result<()> {
    config.timing.validate()?;
    if config.development_ca_validity_days == 0 {
        bail!("development_ca_validity_days must be positive");
    }
    if config.ca_renew_before_days == 0 {
        bail!("ca_renew_before_days must be positive");
    }
    Ok(())
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
