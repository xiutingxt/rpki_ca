use super::parent::validate_import_path;
use super::publication;
use super::state::{CaState, CaStateStore, IssuedEe, IssuedObject, PublicationNumbers};
use crate::infrastructure::repository::{PublicationRepository, PublicationUpdate};
use crate::infrastructure::signing::{
    CrlSigningRequest, IssuerContext, ManifestSigningRequest, ObjectSigningRequest,
    SignedObjectOutput, SigningProvider,
};
use crate::{
    AspaRequest, CaCertificateRenewal, CaCertificateStatus, CaConfig, CertifiedResources,
    ObjectDefinition, ObjectKind, RoaRequest,
};
use anyhow::{Context, Result, bail};
use chrono::{TimeDelta, Utc};
use rpki::{
    crypto::DigestAlgorithm,
    repository::{
        cert::{Cert, KeyUsage, Overclaim, TbsCert},
        crl::CrlEntry,
        manifest::{FileAndHash, Manifest},
        resources::{AsBlock, Prefix},
        x509::{Time, Validity},
    },
    uri,
};
use rsa::rand_core::{OsRng, RngCore};
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::Arc,
};

/// Authorized object definition with its stable identity and repository name.
struct ValidatedPublication {
    definition: ObjectDefinition,
    kind: ObjectKind,
    logical_key: String,
    name: String,
}

/// Concrete signed output, distinct from the desired object definition.
struct IssuedPublication {
    validated: ValidatedPublication,
    bytes: Vec<u8>,
    issued_ee: IssuedEe,
}

/// Domain service for one RPKI certification authority.
pub struct CertificateAuthority {
    config: CaConfig,
    repository: Arc<dyn PublicationRepository>,
    state_store: Arc<dyn CaStateStore>,
    signer: Arc<dyn SigningProvider>,
}

pub(crate) struct ImportedCa {
    pub certificate: Vec<u8>,
    pub serial_start: u64,
    pub crl_number_start: u64,
    pub manifest_number_start: u64,
    pub chain: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
    pub manifests: Vec<Vec<u8>>,
}

impl CertificateAuthority {
    /// Creates an isolated development trust anchor. It is not part of the
    /// public RPKI hierarchy; use `import` for an existing resource CA.
    pub(crate) fn init(
        mut config: CaConfig,
        repository: Arc<dyn PublicationRepository>,
        state_store: Arc<dyn CaStateStore>,
        signer: Arc<dyn SigningProvider>,
    ) -> Result<Self> {
        let certificate_name = format!("{}.cer", publication::key_basename(&signer.public_key()?));
        let base = Self::parse_repository_uri(&config)?;
        config.certificate_uri = base.join(certificate_name.as_bytes())?.to_string();
        repository.initialize()?;
        state_store.initialize(&CaState::new(1_000)?)?;
        let ca = Self {
            config,
            repository,
            state_store,
            signer,
        };
        ca.write_development_ta_certificate()?;
        let _lock = ca.state_store.lock()?;
        let mut state = ca.state_store.load()?;
        state.set_certified_resources(
            CertifiedResources::from_certificate(&ca.certificate()?)?
                .as_set()
                .clone(),
        );
        ca.state_store.save(&state)?;
        ca.refresh_locked(None)?;
        Ok(ca)
    }

    /// Imports a resource CA certificate. For a non-TA certificate, `chain`
    /// must contain TA..direct-parent and `crls` one issuer CRL per issued
    /// certificate (all intermediates followed by the imported certificate).
    pub(crate) fn import(
        config: CaConfig,
        imported: ImportedCa,
        repository: Arc<dyn PublicationRepository>,
        state_store: Arc<dyn CaStateStore>,
        signer: Arc<dyn SigningProvider>,
    ) -> Result<Self> {
        let cert = Cert::decode(imported.certificate.as_slice())
            .context("invalid DER resource certificate")?;
        Self::inspect_import(&cert, &config, signer.as_ref(), true)?;
        let resources =
            validate_import_path(&cert, &imported.chain, &imported.crls, &imported.manifests)?;
        repository.initialize()?;
        let mut initial_state = CaState::new_with_counters(
            imported.serial_start,
            imported.crl_number_start,
            imported.manifest_number_start,
        )?;
        initial_state.set_certified_resources(resources);
        state_store.initialize(&initial_state)?;
        let mut publish = BTreeMap::new();
        publish.insert(
            publication::uri_filename(&config.certificate_uri)?,
            imported.certificate,
        );
        repository.publish(PublicationUpdate {
            publish,
            withdraw: BTreeSet::new(),
        })?;
        let ca = Self {
            config,
            repository,
            state_store,
            signer,
        };
        let _lock = ca.state_store.lock()?;
        ca.refresh_locked(None)?;
        Ok(ca)
    }

    pub(crate) fn open(
        config: CaConfig,
        repository: Arc<dyn PublicationRepository>,
        state_store: Arc<dyn CaStateStore>,
        signer: Arc<dyn SigningProvider>,
    ) -> Result<Self> {
        repository.recover()?;
        let ca = Self {
            config,
            repository,
            state_store,
            signer,
        };
        let cert = ca.certificate()?;
        // An expired CA must remain openable so operators can inspect its
        // state and install a renewed certificate. Signing and publication
        // paths still enforce current validity.
        Self::inspect_import(&cert, &ca.config, ca.signer.as_ref(), false)?;
        ca.recover_pending_publication()?;
        ca.migrate_explicit_certified_resources(&cert)?;
        Ok(ca)
    }

    pub fn sign_roa(&self, request: &RoaRequest, object_name: &str) -> Result<Vec<u8>> {
        Ok(self
            .sign_object(ObjectDefinition::Roa(request.clone()), object_name)?
            .bytes)
    }

    pub fn sign_aspa(&self, request: &AspaRequest, object_name: &str) -> Result<Vec<u8>> {
        Ok(self
            .sign_object(ObjectDefinition::Aspa(request.clone()), object_name)?
            .bytes)
    }

    pub(crate) fn sign_object(
        &self,
        definition: ObjectDefinition,
        object_name: &str,
    ) -> Result<SignedObjectOutput> {
        definition.validate()?;
        Self::validate_signed_object_filename(object_name, definition.kind().extension())?;
        let _lock = self.state_store.lock()?;
        let cert = self.certificate()?;
        let mut state = self.state_store.load()?;
        let mut validated = Self::validate_publication(
            definition,
            object_name,
            state.certified_resources()?.clone(),
        )?;
        let numbers = state.allocate_publication()?;
        let base = self.repository_uri()?;
        let validity = self.object_validity(&cert, validated.kind)?;
        let output = self.signer.issue_object(
            IssuerContext {
                cert: &cert,
                repository_uri: base.clone(),
                certificate_uri: self.ca_certificate_uri()?,
                crl_uri: base.join(self.crl_filename(&cert).as_bytes())?,
            },
            ObjectSigningRequest {
                definition: &validated.definition,
                serial: numbers.object_ee_serial,
                validity,
            },
        )?;
        validated.name = output.name.clone();
        let issued_ee = IssuedEe {
            serial: numbers.object_ee_serial,
            not_after: validity.not_after().timestamp(),
        };
        self.publish(
            &mut state,
            numbers,
            Some(IssuedPublication {
                validated,
                bytes: output.bytes.clone(),
                issued_ee,
            }),
            BTreeSet::new(),
            None,
        )?;
        Ok(output)
    }

    fn validate_publication(
        definition: ObjectDefinition,
        object_name: &str,
        certified_resources: rpki::repository::resources::ResourceSet,
    ) -> Result<ValidatedPublication> {
        let resources = CertifiedResources::new(certified_resources);
        match &definition {
            ObjectDefinition::Roa(request) => resources.authorizes_roa(request)?,
            ObjectDefinition::Aspa(request) => resources.authorizes_aspa(request)?,
        }
        Ok(ValidatedPublication {
            kind: definition.kind(),
            logical_key: definition.logical_key(object_name),
            name: object_name.to_owned(),
            definition,
        })
    }

    /// Reissues the CRL and manifest. Run this periodically before nextUpdate.
    pub fn refresh(&self) -> Result<()> {
        let _lock = self.state_store.lock()?;
        self.refresh_locked(None)
    }

    pub fn withdraw_roa(&self, object_name: &str) -> Result<bool> {
        Self::validate_signed_object_filename(object_name, "roa")?;
        let _lock = self.state_store.lock()?;
        let mut state = self.state_store.load()?;
        let Some(logical_key) = state.logical_key_for_name(object_name).map(str::to_owned) else {
            return Ok(false);
        };
        self.withdraw_logical_locked(&logical_key, &mut state)
    }

    pub fn withdraw_aspa(&self, customer_asn: u32) -> Result<bool> {
        self.withdraw_logical(&format!("aspa:AS{customer_asn}"))
    }

    fn withdraw_logical(&self, logical_key: &str) -> Result<bool> {
        let _lock = self.state_store.lock()?;
        let mut state = self.state_store.load()?;
        self.withdraw_logical_locked(logical_key, &mut state)
    }

    fn withdraw_logical_locked(&self, logical_key: &str, state: &mut CaState) -> Result<bool> {
        let now = Utc::now().timestamp();
        let Some(name) = state.remove_object(logical_key, now) else {
            return Ok(false);
        };
        let numbers = state.allocate_refresh()?;
        self.publish(state, numbers, None, BTreeSet::from([name]), None)?;
        Ok(true)
    }

    /// Refreshes CRL and Manifest only once their configured renewal window
    /// has been reached. Returns whether a publication occurred.
    pub fn refresh_if_needed(&self) -> Result<bool> {
        let _lock = self.state_store.lock()?;
        let cert = self.certificate()?;
        let manifest_name = self.manifest_filename(&cert)?;
        let manifest = Manifest::decode(self.repository.read(&manifest_name)?.as_slice(), true)
            .context("cannot decode current manifest while checking refresh time")?;
        let threshold = Time::now()
            + TimeDelta::try_hours(i64::from(self.config.timing.publish_hours_before_next))
                .expect("u32 hours fit in chrono TimeDelta");
        if manifest.content().next_update() > threshold {
            return Ok(false);
        }
        self.refresh_locked(None)?;
        Ok(true)
    }

    pub fn read_published_object(&self, name: &str) -> Result<Vec<u8>> {
        self.repository.read(name)
    }

    pub fn has_published_object(&self, name: &str) -> Result<bool> {
        Ok(self
            .repository
            .list()?
            .iter()
            .any(|current| current == name))
    }

    pub(crate) fn published_name(&self, logical_key: &str) -> Result<Option<String>> {
        let _lock = self.state_store.lock()?;
        Ok(self
            .state_store
            .load()?
            .published_name(logical_key)
            .map(str::to_owned))
    }

    pub(crate) fn withdraw_definition(
        &self,
        definition: &ObjectDefinition,
        requested_name: &str,
    ) -> Result<bool> {
        self.withdraw_logical(&definition.logical_key(requested_name))
    }

    fn refresh_locked(&self, state: Option<CaState>) -> Result<()> {
        let mut state = match state {
            Some(state) => state,
            None => self.state_store.load()?,
        };
        let numbers = state.allocate_refresh()?;
        self.publish(&mut state, numbers, None, BTreeSet::new(), None)
    }

    /// Returns the current CA certificate lifetime and whether it has entered
    /// the configured renewal window.
    pub fn certificate_status(&self) -> Result<CaCertificateStatus> {
        let cert = self.certificate()?;
        let now = Time::now().timestamp();
        let not_before = cert.validity().not_before().timestamp();
        let not_after = cert.validity().not_after().timestamp();
        let seconds_remaining = not_after.saturating_sub(now);
        let renewal_window = i64::from(self.config.ca_renew_before_days) * 86_400;
        Ok(CaCertificateStatus {
            not_before,
            not_after,
            seconds_remaining,
            renewal_required: seconds_remaining <= renewal_window,
            expired: seconds_remaining <= 0,
        })
    }

    /// Replaces the CA certificate while retaining its current key, subject,
    /// resources and publication point. Key rollover is a separate RFC 6489
    /// lifecycle and is intentionally not performed by this operation.
    pub fn renew_certificate(&self, renewal: CaCertificateRenewal) -> Result<()> {
        let replacement = Cert::decode(renewal.certificate.as_slice())
            .context("invalid DER replacement resource certificate")?;
        Self::inspect_import(&replacement, &self.config, self.signer.as_ref(), true)?;
        let replacement_resources = validate_import_path(
            &replacement,
            &renewal.chain,
            &renewal.crls,
            &renewal.manifests,
        )?;

        let _lock = self.state_store.lock()?;
        let current = self.certificate()?;
        if replacement.subject() != current.subject() {
            bail!("replacement certificate subject differs from the current CA certificate");
        }
        if replacement.subject_public_key_info() != current.subject_public_key_info() {
            bail!("replacement certificate changes the CA key; use an RFC 6489 key rollover");
        }
        if replacement.validity().not_after() <= current.validity().not_after() {
            bail!("replacement certificate must extend the current CA certificate expiry");
        }
        let mut state = self.state_store.load()?;
        if &replacement_resources != state.certified_resources()? {
            bail!("replacement certificate changes the CA resource set");
        }
        let numbers = state.allocate_refresh()?;
        self.publish(
            &mut state,
            numbers,
            None,
            BTreeSet::new(),
            Some((replacement, renewal.certificate)),
        )
    }

    fn inspect_import(
        cert: &Cert,
        config: &CaConfig,
        signer: &dyn SigningProvider,
        require_current_validity: bool,
    ) -> Result<()> {
        if cert.is_self_signed() {
            cert.inspect_ta(true).map_err(|err| {
                anyhow::anyhow!("certificate is not a valid RPKI trust anchor: {err}")
            })?;
        } else {
            cert.inspect_ca(true).map_err(|err| {
                anyhow::anyhow!("certificate is not a valid RPKI CA certificate: {err}")
            })?;
        }
        if require_current_validity {
            cert.verify_validity(Time::now()).map_err(|err| {
                anyhow::anyhow!("resource certificate is not currently valid: {err}")
            })?;
        }
        let key = signer.public_key()?;
        if cert.subject_public_key_info() != &key {
            bail!("private key does not match the resource certificate");
        }
        let configured = Self::parse_repository_uri(config)?;
        uri::Rsync::from_str(&config.certificate_uri)
            .context("certificate_uri must be a valid rsync URI")?;
        if cert.ca_repository() != Some(&configured) {
            bail!("repository_uri does not match the certificate caRepository SIA");
        }
        let manifest = cert
            .rpki_manifest()
            .context("resource certificate has no rpkiManifest SIA")?;
        if !manifest.as_str().starts_with(configured.as_str()) {
            bail!("rpkiManifest URI is outside repository_uri");
        }
        Ok(())
    }

    fn publish(
        &self,
        state: &mut CaState,
        numbers: PublicationNumbers,
        pending_object: Option<IssuedPublication>,
        requested_withdrawals: BTreeSet<String>,
        replacement_certificate: Option<(Cert, Vec<u8>)>,
    ) -> Result<()> {
        let current_cert = self.certificate()?;
        let (cert, replacement_bytes) = match replacement_certificate {
            Some((cert, bytes)) => (cert, Some(bytes)),
            None => (current_cert, None),
        };
        let wall_clock = Utc::now().timestamp();
        let this_update_secs = state.begin_manifest(wall_clock);
        let now = Time::new(
            chrono::DateTime::from_timestamp(this_update_secs, 0)
                .context("manifest time is outside the supported range")?,
        );
        let jitter_seconds = if self.config.timing.publish_next_jitter_hours == 0 {
            0
        } else {
            OsRng.next_u32()
                % self
                    .config
                    .timing
                    .publish_next_jitter_hours
                    .saturating_mul(3_600)
        };
        let publish_seconds =
            i64::from(self.config.timing.publish_next_hours) * 3_600 + i64::from(jitter_seconds);
        let next_update = now
            + TimeDelta::try_seconds(publish_seconds)
                .expect("validated publication interval is representable");
        if cert.validity().not_after() < next_update {
            bail!("CA certificate expires before the next manifest update");
        }
        let base = self.repository_uri()?;
        let certificate_uri = self.ca_certificate_uri()?;
        let crl_name = self.crl_filename(&cert);
        let crl_uri = base.join(crl_name.as_bytes())?;

        let mut pending_files = BTreeMap::new();
        if let Some(bytes) = replacement_bytes {
            pending_files.insert(self.certificate_filename()?, bytes);
        }
        let mut replaced_objects = requested_withdrawals;
        if let Some(object) = pending_object {
            let name = object.validated.name;
            let previous_name = state.replace_object(
                IssuedObject {
                    kind: object.validated.kind,
                    logical_key: object.validated.logical_key,
                    name: name.clone(),
                    ee: object.issued_ee,
                },
                this_update_secs,
            );
            if let Some(previous_name) = previous_name
                && previous_name != name
            {
                replaced_objects.insert(previous_name);
            }
            pending_files.insert(name, object.bytes);
        }
        let mut expired_objects: BTreeSet<_> =
            state.prune_expired(this_update_secs).into_keys().collect();
        expired_objects.extend(replaced_objects);
        let revoked: Vec<_> = state
            .revocations()
            .map(|item| {
                CrlEntry::new(
                    item.serial.into(),
                    Time::new(
                        chrono::DateTime::from_timestamp(item.revoked_at, 0)
                            .expect("validated revocation timestamp"),
                    ),
                )
            })
            .collect();
        let crl_bytes = self.signer.issue_crl(
            IssuerContext {
                cert: &cert,
                repository_uri: base.clone(),
                certificate_uri: certificate_uri.clone(),
                crl_uri: crl_uri.clone(),
            },
            CrlSigningRequest {
                number: numbers.crl_number,
                this_update: now,
                next_update,
                revoked,
            },
        )?;
        pending_files.insert(crl_name, crl_bytes);

        let digest = DigestAlgorithm::sha256();
        let manifest_name = self.manifest_filename(&cert)?;
        let mut entries = Vec::new();
        let current_names: BTreeSet<_> = self.repository.list()?.into_iter().collect();
        for name in &current_names {
            if name == manifest_name.as_str() || name == &self.certificate_filename()? {
                continue;
            }
            if expired_objects.contains(name) {
                continue;
            }
            Self::validate_manifest_member_name(name)?;
            let data = pending_files
                .get(name)
                .cloned()
                .unwrap_or(self.repository.read(name)?);
            entries.push(FileAndHash::new(
                name.as_bytes().to_vec(),
                digest.digest(&data).as_ref().to_vec(),
            ));
        }
        for (name, data) in &pending_files {
            if !current_names.contains(name) {
                entries.push(FileAndHash::new(
                    name.as_bytes().to_vec(),
                    digest.digest(data).as_ref().to_vec(),
                ));
            }
        }
        entries.sort_by(|a, b| a.file().cmp(b.file()));
        let manifest_uri = cert.rpki_manifest().expect("checked certificate").clone();
        let manifest_bytes = self.signer.issue_manifest(
            IssuerContext {
                cert: &cert,
                repository_uri: base,
                certificate_uri,
                crl_uri,
            },
            ManifestSigningRequest {
                serial: numbers.manifest_ee_serial,
                manifest_number: numbers.manifest_number,
                this_update: now,
                next_update,
                entries: &entries,
                manifest_uri,
            },
        )?;
        pending_files.insert(manifest_name, manifest_bytes);

        state.complete_manifest(
            IssuedEe {
                serial: numbers.manifest_ee_serial,
                not_after: next_update.timestamp(),
            },
            this_update_secs,
        );

        let update = PublicationUpdate {
            publish: pending_files,
            withdraw: expired_objects,
        };
        // Persist the complete update before exposing it. Startup replays this
        // idempotently if either the repository switch or final state save fails.
        state.stage_publication(update.clone())?;
        self.state_store.save(state)?;
        self.repository.publish(update)?;
        state.complete_publication();
        self.state_store.save(state)
    }

    fn recover_pending_publication(&self) -> Result<()> {
        let _lock = self.state_store.lock()?;
        let mut state = self.state_store.load()?;
        if let Some(update) = state.pending_publication().cloned() {
            self.repository.publish(update)?;
            state.complete_publication();
            self.state_store.save(&state)?;
        }
        Ok(())
    }

    fn migrate_explicit_certified_resources(&self, cert: &Cert) -> Result<()> {
        let _lock = self.state_store.lock()?;
        let mut state = self.state_store.load()?;
        if !state.has_certified_resources() {
            let resources = CertifiedResources::from_certificate(cert).context(
                "legacy state with inherited resources cannot be migrated without its parent path",
            )?;
            state.set_certified_resources(resources.as_set().clone());
            self.state_store.save(&state)?;
        }
        Ok(())
    }

    fn validate_manifest_member_name(name: &str) -> Result<()> {
        let Some((stem, extension)) = name.rsplit_once('.') else {
            bail!("published object name '{name}' has no three-letter RPKI extension");
        };
        if stem.is_empty()
            || extension.len() != 3
            || !stem
                .bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == b'-' || ch == b'_')
            || !extension.bytes().all(|ch| ch.is_ascii_alphanumeric())
        {
            bail!("published object name '{name}' is not valid for an RPKI manifest");
        }
        Ok(())
    }

    fn write_development_ta_certificate(&self) -> Result<()> {
        let cert = self.development_ta_certificate(1, self.validity())?;
        let mut publish = BTreeMap::new();
        publish.insert(
            self.certificate_filename()?,
            cert.to_captured().into_bytes().to_vec(),
        );
        self.repository.publish(PublicationUpdate {
            publish,
            withdraw: BTreeSet::new(),
        })
    }

    fn development_ta_certificate(&self, serial: u64, validity: Validity) -> Result<Cert> {
        let public_key = self.signer.public_key()?;
        let manifest_name = publication::key_filename(&public_key.key_identifier(), "mft");
        let base = self.repository_uri()?;
        let mut cert = TbsCert::new(
            serial.into(),
            public_key.to_subject_name(),
            validity,
            None,
            public_key,
            KeyUsage::Ca,
            Overclaim::Trim,
        );
        cert.set_basic_ca(Some(true));
        cert.set_ca_repository(Some(base.clone()));
        cert.set_rpki_manifest(Some(base.join(manifest_name.as_bytes())?));
        let v4: Vec<_> = self
            .config
            .development_resources
            .iter()
            .filter_map(|resource| match resource {
                ipnet::IpNet::V4(net) => Some(*net),
                _ => None,
            })
            .collect();
        let v6: Vec<_> = self
            .config
            .development_resources
            .iter()
            .filter_map(|resource| match resource {
                ipnet::IpNet::V6(net) => Some(*net),
                _ => None,
            })
            .collect();
        if !v4.is_empty() {
            cert.build_v4_resource_blocks(|blocks| {
                for net in v4 {
                    blocks.push(Prefix::new(net.network(), net.prefix_len()));
                }
            });
        }
        if !v6.is_empty() {
            cert.build_v6_resource_blocks(|blocks| {
                for net in v6 {
                    blocks.push(Prefix::new(net.network(), net.prefix_len()));
                }
            });
        }
        if !self.config.development_asns.is_empty() {
            cert.build_as_resource_blocks(|blocks| {
                for asn in &self.config.development_asns {
                    blocks.push(AsBlock::Id((*asn).into()));
                }
            });
        }
        self.signer.sign_ca_certificate(cert)
    }

    fn certificate(&self) -> Result<Cert> {
        let data = self
            .repository
            .read(&self.certificate_filename()?)
            .context("cannot read CA certificate")?;
        Cert::decode(data.as_slice()).context("invalid CA certificate")
    }

    fn certificate_filename(&self) -> Result<String> {
        publication::uri_filename(&self.config.certificate_uri)
    }

    fn crl_filename(&self, cert: &Cert) -> String {
        publication::key_filename(&cert.subject_key_identifier(), "crl")
    }

    fn parse_repository_uri(config: &CaConfig) -> Result<uri::Rsync> {
        let mut value = config.repository_uri.clone();
        if !value.ends_with('/') {
            value.push('/');
        }
        uri::Rsync::from_str(&value).context("repository_uri must be a valid rsync URI")
    }

    fn repository_uri(&self) -> Result<uri::Rsync> {
        Self::parse_repository_uri(&self.config)
    }

    fn ca_certificate_uri(&self) -> Result<uri::Rsync> {
        uri::Rsync::from_str(&self.config.certificate_uri)
            .context("certificate_uri must be a valid rsync URI")
    }

    fn manifest_filename(&self, cert: &Cert) -> Result<String> {
        cert.rpki_manifest()
            .context("certificate has no manifest URI")?
            .path()
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .context("manifest URI has no filename")
    }

    fn object_validity(&self, cert: &Cert, kind: ObjectKind) -> Result<Validity> {
        cert.verify_validity(Time::now())
            .map_err(|err| anyhow::anyhow!("CA certificate is not currently valid: {err}"))?;
        let now = Utc::now();
        let weeks = match kind {
            ObjectKind::Roa => self.config.timing.roa_valid_weeks,
            ObjectKind::Aspa => self.config.timing.aspa_valid_weeks,
        };
        let not_before = Time::new(now - TimeDelta::try_minutes(5).unwrap());
        let requested_not_after = Time::new(
            now + TimeDelta::try_weeks(i64::from(weeks))
                .context("configured object validity is outside the supported range")?,
        );
        let not_after = requested_not_after.min(cert.validity().not_after());
        if not_after <= Time::now() {
            bail!("CA certificate expires too soon to issue a signed object");
        }
        Ok(Validity::new(not_before, not_after))
    }

    fn validity(&self) -> Validity {
        Validity::from_secs(i64::from(self.config.development_ca_validity_days) * 86_400)
    }

    fn validate_signed_object_filename(name: &str, extension: &str) -> Result<()> {
        let suffix = format!(".{extension}");
        let Some(stem) = name.strip_suffix(&suffix) else {
            bail!("signed object filename must end in .{extension}");
        };
        if stem.is_empty()
            || !stem
                .bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == b'-' || ch == b'_')
        {
            bail!("signed object filename must contain only ASCII letters, digits, '-' or '_'");
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/unit/ca/authority.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/unit/ca/aspa_signing.rs"]
mod aspa_signing_tests;
