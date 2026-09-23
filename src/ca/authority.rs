use super::parent::{ParentValidationContext, validate_import_path};
use super::publication;
use super::state::{CaState, CaStateStore, IssuedEe, IssuedObject, PublicationNumbers, ToaReview};
use crate::infrastructure::repository::{PublicationRepository, PublicationUpdate};
use crate::infrastructure::signing::{
    CrlSigningRequest, IssuerContext, ManifestSigningRequest, ObjectSigningRequest,
    SignedObjectOutput, SigningProvider,
};
use crate::{
    AspaDelta, AspaRequest, CaCertificateRenewal, CaCertificateStatus, CaConfig,
    CaValidationContextUpdate, CertifiedResources, CertifiedResourcesView, ObjectDefinition,
    ObjectDeltaResponse, ObjectKind, ObjectWithdrawal, RoaConfiguration, RoaConfigurationView,
    RoaDelta, RoaDeltaError, RoaDeltaRejected, RoaDeltaResponse, RoaPayload, RoaRequest,
    SispiDelta, SispiRequest, ToaRequest, ToaReviewStatus,
};
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use chrono::{TimeDelta, Utc};
use rpki::{
    crypto::DigestAlgorithm,
    repository::{
        cert::{Cert, KeyUsage, Overclaim, ResourceCert, TbsCert},
        crl::CrlEntry,
        manifest::{FileAndHash, Manifest},
        resources::{AsBlock, Prefix, ResourceSet},
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
    toa_review: Option<ToaReview>,
}

/// Domain service for one RPKI certification authority.
pub struct CertificateAuthority {
    config: CaConfig,
    repository: Arc<dyn PublicationRepository>,
    state_store: Arc<dyn CaStateStore>,
    signer: Arc<dyn SigningProvider>,
}

pub struct ImportedCa {
    pub certificate: Vec<u8>,
    pub serial_start: u64,
    pub publication_number_start: u64,
    pub chain: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
    pub manifests: Vec<Vec<u8>>,
    pub tal: Vec<u8>,
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
        let validated = validate_import_path(
            &cert,
            &imported.chain,
            &imported.crls,
            &imported.manifests,
            &imported.tal,
        )?;
        let validation_context = ParentValidationContext::imported(
            &imported.chain,
            &imported.crls,
            &imported.manifests,
            &imported.tal,
        );
        repository.initialize()?;
        let mut initial_state =
            CaState::new_with_counters(imported.serial_start, imported.publication_number_start)?;
        initial_state.set_certified_resources(resource_set(&validated));
        initial_state.set_validation_context(validation_context);
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
        ca.migrate_roa_configurations()?;
        Ok(ca)
    }

    pub fn sign_roa(&self, request: &RoaRequest, _object_name: &str) -> Result<Vec<u8>> {
        let added = request
            .prefixes
            .iter()
            .map(|prefix| RoaConfiguration {
                asn: request.asn,
                prefix: prefix.prefix,
                max_length: prefix.max_length,
                comment: None,
            })
            .collect();
        self.update_roas(RoaDelta {
            added,
            removed: Vec::new(),
        })?;
        let state = self.state_store.load()?;
        let name = state
            .published_name(&format!("roa:AS{}", request.asn))
            .context("ROA authorization update did not produce a published object")?;
        self.repository.read(name)
    }

    /// Applies an operator authorization delta and reconciles derived ROA files.
    /// The complete delta is validated before any state or publication change.
    pub fn update_roas(&self, delta: RoaDelta) -> Result<RoaDeltaResponse> {
        let _lock = self.state_store.lock()?;
        let cert = self.certificate()?;
        let mut state = self.state_store.load()?;
        let current =
            crate::objects::roa::configurations_by_key(state.roa_configurations().cloned());
        let added: Vec<_> = delta
            .added
            .into_iter()
            .map(RoaConfiguration::canonicalized)
            .collect();
        let removed: Vec<_> = delta
            .removed
            .into_iter()
            .map(RoaConfiguration::canonicalized)
            .collect();
        let removed_keys: BTreeSet<_> = removed.iter().map(RoaConfiguration::key).collect();
        let mut errors = RoaDeltaError::default();
        let mut seen_added = BTreeSet::new();
        let mut seen_removed = BTreeSet::new();

        for configuration in &added {
            let key = configuration.key();
            if !seen_added.insert(key.clone())
                || (current.contains_key(&key) && !removed_keys.contains(&key))
            {
                errors.duplicates.push(configuration.clone());
                continue;
            }
            if configuration.validate().is_err() {
                errors.invalid_length.push(configuration.clone());
                continue;
            }
            if CertifiedResources::new(state.certified_resources()?.clone())
                .authorizes_roa(&configuration.to_request())
                .is_err()
            {
                errors.notheld.push(configuration.clone());
            }
        }
        for configuration in &removed {
            let key = configuration.key();
            if !seen_removed.insert(key.clone()) || !current.contains_key(&key) {
                errors.unknowns.push(configuration.clone());
            }
        }
        if !errors.is_empty() {
            return Err(RoaDeltaRejected(errors).into());
        }

        let mut candidate = current.clone();
        for configuration in &removed {
            candidate.remove(&configuration.key());
        }
        for configuration in &added {
            candidate.insert(configuration.key(), configuration.clone());
        }

        let current_by_asn = Self::roa_keys_by_asn(&current);
        let candidate_by_asn = Self::roa_keys_by_asn(&candidate);
        let affected_asns: BTreeSet<_> = current_by_asn
            .keys()
            .chain(candidate_by_asn.keys())
            .copied()
            .filter(|asn| current_by_asn.get(asn) != candidate_by_asn.get(asn))
            .collect();
        state.replace_roa_configurations(candidate.clone());

        if affected_asns.is_empty() {
            self.state_store.save(&state)?;
            return Ok(RoaDeltaResponse {
                added,
                removed,
                configurations: self.roa_configuration_views_locked(&state)?,
            });
        }

        let now = Utc::now().timestamp();
        let mut withdrawals = BTreeSet::new();
        for (logical_key, name) in state.published_entries(ObjectKind::Roa) {
            let roa =
                rpki::repository::roa::Roa::decode(self.repository.read(&name)?.as_slice(), true)
                    .with_context(|| format!("cannot decode published ROA '{name}'"))?;
            if affected_asns.contains(&u32::from(roa.content().as_id())) {
                if let Some(object) = state.remove_object(&logical_key, now) {
                    withdrawals.insert(object.name);
                }
            }
        }

        let mut requests = Vec::new();
        for asn in &affected_asns {
            let prefixes: Vec<_> = candidate
                .values()
                .filter(|configuration| configuration.asn == *asn)
                .map(|configuration| RoaPayload {
                    prefix: configuration.prefix,
                    max_length: configuration.max_length,
                })
                .collect();
            if !prefixes.is_empty() {
                requests.push(RoaRequest {
                    asn: *asn,
                    prefixes,
                });
            }
        }
        let numbers = if requests.is_empty() {
            state.allocate_refresh()?
        } else {
            state.allocate_publication_batch(requests.len())?
        };
        let base = self.repository_uri()?;
        let certificate_uri = self.ca_certificate_uri()?;
        let crl_uri = base.join(self.crl_filename(&cert).as_bytes())?;
        let validity = self.object_validity(&cert, ObjectKind::Roa)?;
        let mut pending = Vec::new();
        for (request, serial) in requests.iter().zip(&numbers.object_ee_serials) {
            let mut validated = Self::validate_publication(
                ObjectDefinition::Roa(request.clone()),
                "derived.roa",
                state.certified_resources()?.clone(),
            )?;
            let output = self.signer.issue_object(
                IssuerContext {
                    cert: &cert,
                    repository_uri: base.clone(),
                    certificate_uri: certificate_uri.clone(),
                    crl_uri: crl_uri.clone(),
                },
                ObjectSigningRequest {
                    definition: &validated.definition,
                    serial: *serial,
                    validity,
                },
            )?;
            validated.name = output.name.clone();
            pending.push(IssuedPublication {
                validated,
                bytes: output.bytes,
                issued_ee: IssuedEe {
                    serial: *serial,
                    not_after: validity.not_after().timestamp(),
                },
                toa_review: None,
            });
        }
        self.publish(&mut state, numbers, pending, withdrawals, None)?;
        Ok(RoaDeltaResponse {
            added,
            removed,
            configurations: self.roa_configuration_views_locked(&state)?,
        })
    }

    pub fn roa_configurations(&self) -> Result<Vec<RoaConfigurationView>> {
        let _lock = self.state_store.lock()?;
        let state = self.state_store.load()?;
        self.roa_configuration_views_locked(&state)
    }

    pub fn sign_aspa(&self, request: &AspaRequest, object_name: &str) -> Result<Vec<u8>> {
        Ok(self
            .sign_object(ObjectDefinition::Aspa(request.clone()), object_name)?
            .bytes)
    }

    /// Atomically applies a naturally idempotent batch of ASPA definitions.
    pub fn update_aspas(&self, delta: AspaDelta) -> Result<ObjectDeltaResponse> {
        self.update_stable_objects(
            ObjectKind::Aspa,
            delta
                .added
                .into_iter()
                .map(ObjectDefinition::Aspa)
                .collect(),
            delta
                .removed
                .into_iter()
                .map(|asn| format!("aspa:AS{asn}"))
                .collect(),
        )
    }

    /// Atomically applies a naturally idempotent batch of SiSPI definitions.
    pub fn update_sispis(&self, delta: SispiDelta) -> Result<ObjectDeltaResponse> {
        self.update_stable_objects(
            ObjectKind::Sispi,
            delta
                .added
                .into_iter()
                .map(ObjectDefinition::Sispi)
                .collect(),
            delta
                .removed
                .into_iter()
                .map(|asn| format!("sispi:AS{asn}"))
                .collect(),
        )
    }

    fn update_stable_objects(
        &self,
        kind: ObjectKind,
        added: Vec<ObjectDefinition>,
        removed: Vec<String>,
    ) -> Result<ObjectDeltaResponse> {
        let mut additions = BTreeMap::new();
        for definition in added {
            if definition.kind() != kind {
                bail!("batch definition kind does not match {kind}");
            }
            definition.validate()?;
            let definition = definition.canonicalized();
            let key = definition.logical_key();
            if additions.insert(key.clone(), definition).is_some() {
                bail!("batch contains more than one definition for {key}");
            }
        }
        let removals: BTreeSet<_> = removed.into_iter().collect();
        if let Some(key) = additions.keys().find(|key| removals.contains(*key)) {
            bail!("batch cannot add and remove {key} at the same time");
        }

        let _lock = self.state_store.lock()?;
        let cert = self.certificate()?;
        let mut state = self.state_store.load()?;
        let resources = state.certified_resources()?.clone();
        let mut result = ObjectDeltaResponse::default();
        let mut pending_validated = Vec::new();

        // Validate the complete batch before allocating serials or changing state.
        for (key, definition) in additions {
            let current = state.signed_object(&key);
            if current.as_ref().and_then(|item| item.definition.as_ref()) == Some(&definition) {
                result.unchanged.push(key);
                continue;
            }
            let requested_name = match &definition {
                ObjectDefinition::Aspa(value) => format!("aspa-AS{}.asa", value.customer_asn),
                ObjectDefinition::Sispi(value) => format!("sispi-AS{}.sav", value.as_id),
                _ => unreachable!("kind checked above"),
            };
            Self::validate_signed_object_filename(&requested_name, kind.extension())?;
            let validated =
                Self::validate_publication(definition, &requested_name, resources.clone())?;
            if current.is_some() {
                result.updated.push(key);
            } else {
                result.created.push(key);
            }
            pending_validated.push(validated);
        }

        let now = Utc::now().timestamp();
        let mut withdrawal_names = BTreeSet::new();
        for key in removals {
            match state.signed_object(&key) {
                Some(current) if current.kind == kind => {
                    let removed = state
                        .remove_object(&key, now)
                        .expect("object checked immediately before removal");
                    withdrawal_names.insert(removed.name);
                    result.removed.push(key);
                }
                Some(_) => bail!("signed object {key} belongs to another collection"),
                None => result.unchanged.push(key),
            }
        }

        if pending_validated.is_empty() && withdrawal_names.is_empty() {
            result.objects = state.signed_objects(kind);
            result.unchanged.sort();
            return Ok(result);
        }

        let numbers = if pending_validated.is_empty() {
            state.allocate_refresh()?
        } else {
            state.allocate_publication_batch(pending_validated.len())?
        };
        let base = self.repository_uri()?;
        let certificate_uri = self.ca_certificate_uri()?;
        let crl_uri = base.join(self.crl_filename(&cert).as_bytes())?;
        let validity = self.object_validity(&cert, kind)?;
        let mut pending = Vec::new();
        for (mut validated, serial) in pending_validated
            .into_iter()
            .zip(&numbers.object_ee_serials)
        {
            let output = self.signer.issue_object(
                IssuerContext {
                    cert: &cert,
                    repository_uri: base.clone(),
                    certificate_uri: certificate_uri.clone(),
                    crl_uri: crl_uri.clone(),
                },
                ObjectSigningRequest {
                    definition: &validated.definition,
                    serial: *serial,
                    validity,
                },
            )?;
            validated.name = output.name.clone();
            pending.push(IssuedPublication {
                validated,
                bytes: output.bytes,
                issued_ee: IssuedEe {
                    serial: *serial,
                    not_after: validity.not_after().timestamp(),
                },
                toa_review: None,
            });
        }
        self.publish(&mut state, numbers, pending, withdrawal_names, None)?;
        result.objects = state.signed_objects(kind);
        result.created.sort();
        result.updated.sort();
        result.removed.sort();
        result.unchanged.sort();
        Ok(result)
    }

    pub fn sign_toa(&self, request: &ToaRequest, object_name: &str) -> Result<Vec<u8>> {
        Ok(self
            .sign_object(ObjectDefinition::Toa(request.clone()), object_name)?
            .bytes)
    }

    pub fn sign_sispi(&self, request: &SispiRequest, object_name: &str) -> Result<Vec<u8>> {
        Ok(self
            .sign_object(ObjectDefinition::Sispi(request.clone()), object_name)?
            .bytes)
    }

    pub(crate) fn sign_object(
        &self,
        definition: ObjectDefinition,
        object_name: &str,
    ) -> Result<SignedObjectOutput> {
        if matches!(&definition, ObjectDefinition::Roa(_)) {
            bail!("ROAs are derived from the authorization collection; use update_roas");
        }
        definition.validate()?;
        let definition = definition.canonicalized();
        Self::validate_signed_object_filename(object_name, definition.kind().extension())?;
        let _lock = self.state_store.lock()?;
        let cert = self.certificate()?;
        let mut state = self.state_store.load()?;
        let mut validated = Self::validate_publication(
            definition,
            object_name,
            state.certified_resources()?.clone(),
        )?;
        let (advisories, toa_review) = match &validated.definition {
            ObjectDefinition::Toa(request) => {
                let roa_names = state.published_names(ObjectKind::Roa);
                let assessment = super::toa_policy::ToaRoaAssessment::evaluate(
                    self.repository.as_ref(),
                    &roa_names,
                    request,
                )?;
                let advisories = assessment.enforce(request)?;
                let review = self.toa_review(&assessment, request, &advisories)?;
                (advisories, Some(review))
            }
            _ => (Vec::new(), None),
        };
        let numbers = state.allocate_publication()?;
        let base = self.repository_uri()?;
        let validity = self.object_validity(&cert, validated.kind)?;
        let mut output = self.signer.issue_object(
            IssuerContext {
                cert: &cert,
                repository_uri: base.clone(),
                certificate_uri: self.ca_certificate_uri()?,
                crl_uri: base.join(self.crl_filename(&cert).as_bytes())?,
            },
            ObjectSigningRequest {
                definition: &validated.definition,
                serial: numbers.single_object_serial(),
                validity,
            },
        )?;
        output.advisories = advisories;
        validated.name = output.name.clone();
        let issued_ee = IssuedEe {
            serial: numbers.single_object_serial(),
            not_after: validity.not_after().timestamp(),
        };
        self.publish(
            &mut state,
            numbers,
            vec![IssuedPublication {
                validated,
                bytes: output.bytes.clone(),
                issued_ee,
                toa_review,
            }],
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
            ObjectDefinition::Sispi(request) => resources.authorizes_sispi(request)?,
            ObjectDefinition::Toa(request) => resources.authorizes_toa(request)?,
        }
        Ok(ValidatedPublication {
            kind: definition.kind(),
            logical_key: definition.logical_key(),
            name: object_name.to_owned(),
            definition,
        })
    }

    /// Reissues the CRL and manifest. Run this periodically before nextUpdate.
    pub fn refresh(&self) -> Result<()> {
        let _lock = self.state_store.lock()?;
        self.refresh_locked(None)
    }

    pub fn withdraw_toa(&self, object_name: &str) -> Result<bool> {
        self.withdraw_by_published_name(object_name, "toa")
    }

    pub fn withdraw_sispi(&self, as_id: u32) -> Result<bool> {
        self.withdraw_logical(&format!("sispi:AS{as_id}"))
    }

    fn withdraw_by_published_name(&self, object_name: &str, extension: &str) -> Result<bool> {
        Self::validate_signed_object_filename(object_name, extension)?;
        let _lock = self.state_store.lock()?;
        let mut state = self.state_store.load()?;
        let Some(logical_key) = state.logical_key_for_name(object_name).map(str::to_owned) else {
            return Ok(false);
        };
        Ok(self
            .withdraw_logical_locked(&logical_key, &mut state)?
            .is_some())
    }

    pub fn withdraw_published_object(&self, object_name: &str) -> Result<Option<ObjectWithdrawal>> {
        let extension = object_name
            .rsplit_once('.')
            .map(|(_, extension)| extension)
            .context("signed object filename has no extension")?;
        let expected_kind = ObjectKind::from_extension(extension)
            .context("repository file is not a withdrawable signed object")?;
        if expected_kind == ObjectKind::Roa {
            bail!("ROA files are derived; remove their authorization configurations instead");
        }
        Self::validate_signed_object_filename(object_name, extension)?;

        let _lock = self.state_store.lock()?;
        let mut state = self.state_store.load()?;
        let Some(logical_key) = state.logical_key_for_name(object_name).map(str::to_owned) else {
            return Ok(None);
        };
        if state.object_kind_for_name(object_name) != Some(expected_kind) {
            bail!("published object kind does not match its filename extension");
        }
        self.withdraw_logical_locked(&logical_key, &mut state)
    }

    pub(crate) fn withdraw_signed_object(
        &self,
        logical_key: &str,
        expected_kind: ObjectKind,
    ) -> Result<Option<ObjectWithdrawal>> {
        let _lock = self.state_store.lock()?;
        let mut state = self.state_store.load()?;
        let Some(current) = state.signed_object(logical_key) else {
            return Ok(None);
        };
        if current.kind != expected_kind {
            bail!("signed object kind does not match the requested collection");
        }
        self.withdraw_logical_locked(logical_key, &mut state)
    }

    pub fn withdraw_aspa(&self, customer_asn: u32) -> Result<bool> {
        self.withdraw_logical(&format!("aspa:AS{customer_asn}"))
    }

    fn withdraw_logical(&self, logical_key: &str) -> Result<bool> {
        let _lock = self.state_store.lock()?;
        let mut state = self.state_store.load()?;
        Ok(self
            .withdraw_logical_locked(logical_key, &mut state)?
            .is_some())
    }

    fn withdraw_logical_locked(
        &self,
        logical_key: &str,
        state: &mut CaState,
    ) -> Result<Option<ObjectWithdrawal>> {
        let now = Utc::now().timestamp();
        let Some(object) = state.remove_object(logical_key, now) else {
            return Ok(None);
        };
        let ee_certificate_revoked = object.ee.not_after > now;
        let numbers = state.allocate_refresh()?;
        let publication_number = numbers.publication_number;
        self.publish(
            state,
            numbers,
            Vec::new(),
            BTreeSet::from([object.name.clone()]),
            None,
        )?;
        Ok(Some(ObjectWithdrawal {
            object_name: object.name,
            kind: object.kind,
            ee_certificate_serial: object.ee.serial,
            ee_certificate_revoked,
            revocation_time: ee_certificate_revoked.then_some(now),
            crl_number: publication_number,
            manifest_number: publication_number,
        }))
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

    pub fn list_published_objects(&self) -> Result<Vec<String>> {
        self.repository.list()
    }

    pub fn list_published_signed_objects(&self) -> Result<BTreeSet<String>> {
        let _lock = self.state_store.lock()?;
        Ok(self.state_store.load()?.published_object_names())
    }

    pub fn validate_published_object(&self, name: &str) -> Result<crate::ValidationReport> {
        let _lock = self.state_store.lock()?;
        let state = self.state_store.load()?;
        Ok(crate::validation::validate_repository_object(
            self.repository.as_ref(),
            state.validation_context(),
            name,
        ))
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

    pub(crate) fn signed_object(
        &self,
        logical_key: &str,
    ) -> Result<Option<crate::SignedObjectView>> {
        let _lock = self.state_store.lock()?;
        Ok(self.state_store.load()?.signed_object(logical_key))
    }

    pub(crate) fn signed_objects(&self, kind: ObjectKind) -> Result<Vec<crate::SignedObjectView>> {
        let _lock = self.state_store.lock()?;
        Ok(self.state_store.load()?.signed_objects(kind))
    }

    fn refresh_locked(&self, state: Option<CaState>) -> Result<()> {
        let mut state = match state {
            Some(state) => state,
            None => self.state_store.load()?,
        };
        let numbers = state.allocate_refresh()?;
        self.publish(&mut state, numbers, Vec::new(), BTreeSet::new(), None)
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

    /// Returns the effective resource set resolved when the current CA
    /// certificate was imported or issued.
    pub fn certified_resources(&self) -> Result<CertifiedResourcesView> {
        let _lock = self.state_store.lock()?;
        let state = self.state_store.load()?;
        Ok(CertifiedResources::new(state.certified_resources()?.clone()).view())
    }

    /// Replaces the CA certificate while retaining its current key, subject,
    /// resources and publication point. Key rollover is a separate RFC 6489
    /// lifecycle and is intentionally not performed by this operation.
    pub fn renew_certificate(&self, renewal: CaCertificateRenewal) -> Result<()> {
        let replacement = Cert::decode(renewal.certificate.as_slice())
            .context("invalid DER replacement resource certificate")?;
        Self::inspect_import(&replacement, &self.config, self.signer.as_ref(), true)?;
        let validated_replacement = validate_import_path(
            &replacement,
            &renewal.chain,
            &renewal.crls,
            &renewal.manifests,
            &renewal.tal,
        )?;
        let replacement_resources = resource_set(&validated_replacement);
        let replacement_context = ParentValidationContext::imported(
            &renewal.chain,
            &renewal.crls,
            &renewal.manifests,
            &renewal.tal,
        );

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
        state.set_validation_context(replacement_context);
        let numbers = state.allocate_refresh()?;
        self.publish(
            &mut state,
            numbers,
            Vec::new(),
            BTreeSet::new(),
            Some((replacement, renewal.certificate)),
        )
    }

    /// Replaces only the persisted parent-publication snapshot after proving
    /// that it still validates the current imported RC to the configured TAL.
    pub fn update_validation_context(&self, update: CaValidationContextUpdate) -> Result<()> {
        let _lock = self.state_store.lock()?;
        let cert = self.certificate()?;
        let validated = validate_import_path(
            &cert,
            &update.chain,
            &update.crls,
            &update.manifests,
            &update.tal,
        )?;
        let mut state = self.state_store.load()?;
        if !state.validation_context().is_imported() {
            bail!("parent validation context can only be updated for an imported CA");
        }
        if &resource_set(&validated) != state.certified_resources()? {
            bail!("updated certification path changes the CA resource set");
        }
        state.set_validation_context(ParentValidationContext::imported(
            &update.chain,
            &update.crls,
            &update.manifests,
            &update.tal,
        ));
        self.state_store.save(&state)
    }

    pub fn toa_review_statuses(&self) -> Result<Vec<ToaReviewStatus>> {
        let _lock = self.state_store.lock()?;
        let state = self.state_store.load()?;
        let now = Utc::now().timestamp();
        Ok(state
            .toa_reviews()
            .map(|(name, review)| Self::toa_review_status(name, review, now))
            .collect())
    }

    pub fn review_toa(
        &self,
        object_name: &str,
        roa_overlap_justification: Option<String>,
    ) -> Result<ToaReviewStatus> {
        Self::validate_signed_object_filename(object_name, "toa")?;
        let _lock = self.state_store.lock()?;
        let mut state = self.state_store.load()?;
        let toa = super::signed_objects::toa::object::Toa::decode(Bytes::from(
            self.repository.read(object_name)?,
        ))
        .context("cannot decode TOA during periodic review")?;
        let request = ToaRequest {
            asns: toa
                .content()
                .asns()
                .iter()
                .copied()
                .map(u32::from)
                .collect(),
            prefixes: toa
                .content()
                .v4_prefixes()
                .iter()
                .copied()
                .map(|prefix| {
                    ipnet::IpNet::new(prefix.to_v4().into(), prefix.addr_len())
                        .expect("decoded TOA IPv4 prefix length is valid")
                })
                .chain(toa.content().v6_prefixes().iter().copied().map(|prefix| {
                    ipnet::IpNet::new(prefix.to_v6().into(), prefix.addr_len())
                        .expect("decoded TOA IPv6 prefix length is valid")
                }))
                .collect(),
            roa_overlap_justification,
        };
        request.validate()?;
        let roa_names = state.published_names(ObjectKind::Roa);
        let assessment = super::toa_policy::ToaRoaAssessment::evaluate(
            self.repository.as_ref(),
            &roa_names,
            &request,
        )?;
        let advisories = assessment.enforce(&request)?;
        let review = self.toa_review(&assessment, &request, &advisories)?;
        let status = Self::toa_review_status(object_name, &review, Utc::now().timestamp());
        state.update_toa_review(object_name, review)?;
        self.state_store.save(&state)?;
        Ok(status)
    }

    fn toa_review(
        &self,
        assessment: &super::toa_policy::ToaRoaAssessment,
        request: &ToaRequest,
        advisories: &[String],
    ) -> Result<ToaReview> {
        let now = Utc::now().timestamp();
        let interval = i64::from(self.config.timing.toa_review_days)
            .checked_mul(86_400)
            .context("configured TOA review interval is outside the supported range")?;
        Ok(ToaReview {
            last_reviewed_at: now,
            review_due_at: now
                .checked_add(interval)
                .context("TOA review due date is outside the supported range")?,
            total_pairs: assessment.total_pairs,
            roa_covered_pairs: assessment.covered_pairs,
            roa_overlap_justification: request.roa_overlap_justification.clone(),
            advisories: advisories.to_vec(),
        })
    }

    fn toa_review_status(name: &str, review: &ToaReview, now: i64) -> ToaReviewStatus {
        ToaReviewStatus {
            object_name: name.to_owned(),
            last_reviewed_at: review.last_reviewed_at,
            review_due_at: review.review_due_at,
            overdue: now >= review.review_due_at,
            total_pairs: review.total_pairs,
            roa_covered_pairs: review.roa_covered_pairs,
            roa_overlap_justification: review.roa_overlap_justification.clone(),
            advisories: review.advisories.clone(),
        }
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
        pending_objects: Vec<IssuedPublication>,
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
            return Err(crate::CaIssuanceUnavailable(
                "CA certificate expires before the next manifest update".into(),
            )
            .into());
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
        for object in pending_objects {
            let name = object.validated.name;
            let previous_name = state.replace_object(
                IssuedObject {
                    kind: object.validated.kind,
                    logical_key: object.validated.logical_key,
                    name: name.clone(),
                    definition: Some(object.validated.definition),
                    ee: object.issued_ee,
                    toa_review: object.toa_review,
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
                number: numbers.publication_number,
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
                manifest_number: numbers.publication_number,
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

    fn migrate_roa_configurations(&self) -> Result<()> {
        let _lock = self.state_store.lock()?;
        let mut state = self.state_store.load()?;
        if state.has_roa_configurations() {
            return Ok(());
        }
        let mut configurations = BTreeMap::new();
        for name in state.published_names(ObjectKind::Roa) {
            let roa =
                rpki::repository::roa::Roa::decode(self.repository.read(&name)?.as_slice(), true)
                    .with_context(|| format!("cannot migrate published ROA '{name}'"))?;
            let asn = u32::from(roa.content().as_id());
            for address in roa.content().iter() {
                let configuration = RoaConfiguration {
                    asn,
                    prefix: ipnet::IpNet::new(address.address(), address.address_length())?,
                    max_length: Some(address.max_length()),
                    comment: None,
                }
                .canonicalized();
                configurations.insert(configuration.key(), configuration);
            }
        }
        if !configurations.is_empty() {
            state.replace_roa_configurations(configurations);
            self.state_store.save(&state)?;
        }
        Ok(())
    }

    fn roa_keys_by_asn(
        configurations: &BTreeMap<String, RoaConfiguration>,
    ) -> BTreeMap<u32, BTreeSet<String>> {
        let mut result: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
        for (key, configuration) in configurations {
            result
                .entry(configuration.asn)
                .or_default()
                .insert(key.clone());
        }
        result
    }

    fn roa_configuration_views_locked(&self, state: &CaState) -> Result<Vec<RoaConfigurationView>> {
        let mut names_by_asn: BTreeMap<u32, Vec<String>> = BTreeMap::new();
        for name in state.published_names(ObjectKind::Roa) {
            let roa =
                rpki::repository::roa::Roa::decode(self.repository.read(&name)?.as_slice(), true)
                    .with_context(|| format!("cannot decode published ROA '{name}'"))?;
            names_by_asn
                .entry(u32::from(roa.content().as_id()))
                .or_default()
                .push(name);
        }
        for names in names_by_asn.values_mut() {
            names.sort();
        }
        Ok(state
            .roa_configurations()
            .cloned()
            .map(|configuration| RoaConfigurationView {
                roa_objects: names_by_asn
                    .get(&configuration.asn)
                    .cloned()
                    .unwrap_or_default(),
                configuration,
            })
            .collect())
    }

    pub(crate) fn validate_manifest_member_name(name: &str) -> Result<()> {
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
        // Only object types supported by the repository profile may become
        // members of this CA's manifest.
        match extension {
            "asa" | "ccr" | "cdr" | "cer" | "crl" | "gbr" | "mft" | "roa" | "sig" | "tak"
            | "sav" | "toa" => {}
            _ => bail!("published object name '{name}' does not use a supported RPKI extension"),
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

    pub(crate) fn development_ta_certificate(
        &self,
        serial: u64,
        validity: Validity,
    ) -> Result<Cert> {
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
            // Krill's issuance strategy uses the strict RFC 6487 profile
            // and proactively re-issues certificates when resources shrink.
            // A trust anchor cannot overclaim relative to an issuer, so the
            // RFC 8360 trimming profile provides no benefit here.
            Overclaim::Refuse,
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

    pub(crate) fn certificate(&self) -> Result<Cert> {
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

    pub(crate) fn object_validity(&self, cert: &Cert, kind: ObjectKind) -> Result<Validity> {
        cert.verify_validity(Time::now())
            .map_err(|err| anyhow::anyhow!("CA certificate is not currently valid: {err}"))?;
        let now = Utc::now();
        let weeks = match kind {
            ObjectKind::Roa => self.config.timing.roa_valid_weeks,
            ObjectKind::Aspa => self.config.timing.aspa_valid_weeks,
            ObjectKind::Sispi => self.config.timing.sispi_valid_weeks,
            ObjectKind::Toa => self.config.timing.toa_valid_weeks,
        };
        let not_before = Time::new(now - TimeDelta::try_minutes(5).unwrap());
        let requested_not_after = Time::new(
            now + TimeDelta::try_weeks(i64::from(weeks))
                .context("configured object validity is outside the supported range")?,
        );
        let not_after = requested_not_after.min(cert.validity().not_after());
        if not_after <= Time::now() {
            return Err(crate::CaIssuanceUnavailable(
                "CA certificate expires too soon to issue a signed object".into(),
            )
            .into());
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

fn resource_set(cert: &ResourceCert) -> ResourceSet {
    ResourceSet::new(
        cert.as_resources().clone(),
        cert.v4_resources().clone().into(),
        cert.v6_resources().clone().into(),
    )
}
