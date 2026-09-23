use crate::ca::parent::ParentValidationContext;
use crate::infrastructure::repository::PublicationUpdate;
use crate::{ObjectDefinition, ObjectKind, RoaConfiguration, SignedObjectView};
use anyhow::{Context, Result, bail};
use rpki::repository::resources::ResourceSet;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) trait StateGuard: Send {}

pub(crate) trait CaStateStore: Send + Sync {
    fn initialize(&self, state: &CaState) -> Result<()>;
    fn load(&self) -> Result<CaState>;
    fn save(&self, state: &CaState) -> Result<()>;
    fn lock(&self) -> Result<Box<dyn StateGuard>>;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct IssuedEe {
    pub serial: u64,
    pub not_after: i64,
}

/// Durable metadata for an object that has actually been signed and published.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct IssuedObject {
    #[serde(default)]
    pub kind: ObjectKind,
    #[serde(default)]
    pub logical_key: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub definition: Option<ObjectDefinition>,
    #[serde(flatten)]
    pub ee: IssuedEe,
    pub toa_review: Option<ToaReview>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ToaReview {
    pub last_reviewed_at: i64,
    pub review_due_at: i64,
    pub total_pairs: usize,
    pub roa_covered_pairs: usize,
    pub roa_overlap_justification: Option<String>,
    pub advisories: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Revocation {
    pub serial: u64,
    pub revoked_at: i64,
    pub not_after: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct CaState {
    #[serde(flatten)]
    serials: SerialAllocator,
    #[serde(default)]
    objects: ObjectInventory,
    #[serde(flatten)]
    manifest: ManifestState,
    #[serde(default)]
    revocations: RevocationSet,
    /// Durable two-phase publication journal. Replayed on startup.
    #[serde(default)]
    pending_publication: Option<PublicationUpdate>,
    #[serde(default)]
    certified_resources: Option<ResourceSet>,
    /// Operator-configured ROA intent. Published ROA files are derived from it.
    #[serde(default)]
    roa_configurations: BTreeMap<String, RoaConfiguration>,
    validation_context: ParentValidationContext,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct SerialAllocator {
    pub next_certificate_serial: u64,
    pub next_publication_number: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(transparent)]
pub(crate) struct ObjectInventory(BTreeMap<String, IssuedObject>);

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct ManifestState {
    #[serde(default, alias = "manifest_ee")]
    current_ee: Option<IssuedEe>,
    #[serde(default)]
    last_manifest_this_update: Option<i64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(transparent)]
pub(crate) struct RevocationSet(Vec<Revocation>);

impl CaState {
    /// Fills metadata omitted by state files written before typed inventory.
    pub(crate) fn normalize_object_inventory(&mut self) {
        let previous = std::mem::take(&mut self.objects.0);
        for (stored_key, mut object) in previous {
            if object.name.is_empty() {
                object.name = stored_key;
            }
            if object.name.ends_with(".asa") {
                object.kind = ObjectKind::Aspa;
            }
            if object.name.ends_with(".toa") {
                object.kind = ObjectKind::Toa;
            }
            if object.name.ends_with(".sav") {
                object.kind = ObjectKind::Sispi;
            }
            if object.logical_key.is_empty() {
                object.logical_key = format!("{}:{}", object.kind, object.name);
            }
            self.objects.0.insert(object.logical_key.clone(), object);
        }
    }

    pub fn new(serial_start: u64) -> Result<Self> {
        Self::new_with_counters(serial_start, 1)
    }

    pub fn new_with_counters(serial_start: u64, publication_number_start: u64) -> Result<Self> {
        if serial_start == 0 || serial_start > i64::MAX as u64 {
            bail!("serial_start must be in 1..={}", i64::MAX);
        }
        if publication_number_start == 0 {
            bail!("publication_number_start must be positive");
        }
        Ok(Self {
            serials: SerialAllocator {
                next_certificate_serial: serial_start,
                next_publication_number: publication_number_start,
            },
            objects: ObjectInventory::default(),
            manifest: ManifestState::default(),
            revocations: RevocationSet::default(),
            pending_publication: None,
            certified_resources: None,
            roa_configurations: BTreeMap::new(),
            validation_context: ParentValidationContext::DevelopmentTrustAnchor,
        })
    }

    pub fn allocate_publication(&mut self) -> Result<PublicationNumbers> {
        self.serials.allocate_publication(1)
    }

    pub fn allocate_publication_batch(
        &mut self,
        object_count: usize,
    ) -> Result<PublicationNumbers> {
        self.serials.allocate_publication(object_count)
    }

    pub fn allocate_refresh(&mut self) -> Result<PublicationNumbers> {
        self.serials.allocate_refresh()
    }

    pub fn replace_object(&mut self, object: IssuedObject, now: i64) -> Option<String> {
        let key = object.logical_key.clone();
        if let Some(previous) = self.objects.0.insert(key, object) {
            let previous_name = previous.name;
            self.revocations.revoke(previous.ee, now);
            return Some(previous_name);
        }
        None
    }

    pub fn remove_object(&mut self, logical_key: &str, now: i64) -> Option<IssuedObject> {
        let object = self.objects.0.remove(logical_key)?;
        self.revocations.revoke(object.ee.clone(), now);
        Some(object)
    }

    pub fn begin_manifest(&mut self, wall_clock: i64) -> i64 {
        let now = self
            .manifest
            .last_manifest_this_update
            .map_or(wall_clock, |previous| wall_clock.max(previous + 1));
        if let Some(previous) = self.manifest.current_ee.take() {
            self.revocations.revoke(previous, now);
        }
        now
    }

    pub fn complete_manifest(&mut self, issued: IssuedEe, this_update: i64) {
        self.manifest.current_ee = Some(issued);
        self.manifest.last_manifest_this_update = Some(this_update);
    }

    pub fn prune_expired(&mut self, now: i64) -> BTreeMap<String, IssuedEe> {
        let mut expired = BTreeMap::new();
        self.objects.0.retain(|_, object| {
            if object.ee.not_after <= now {
                expired.insert(object.name.clone(), object.ee.clone());
                false
            } else {
                true
            }
        });
        self.revocations.0.retain(|item| item.not_after > now);
        expired
    }

    pub fn revocations(&self) -> impl Iterator<Item = &Revocation> {
        self.revocations.0.iter()
    }

    pub fn stage_publication(&mut self, update: PublicationUpdate) -> Result<()> {
        if self.pending_publication.is_some() {
            bail!("a publication transaction is already pending");
        }
        self.pending_publication = Some(update);
        Ok(())
    }

    pub fn pending_publication(&self) -> Option<&PublicationUpdate> {
        self.pending_publication.as_ref()
    }

    pub fn complete_publication(&mut self) {
        self.pending_publication = None;
    }

    pub fn set_certified_resources(&mut self, resources: ResourceSet) {
        self.certified_resources = Some(resources);
    }

    pub fn certified_resources(&self) -> Result<&ResourceSet> {
        self.certified_resources
            .as_ref()
            .context("CA state has no resolved certified resources; re-import is required")
    }

    pub fn has_certified_resources(&self) -> bool {
        self.certified_resources.is_some()
    }

    pub fn set_validation_context(&mut self, context: ParentValidationContext) {
        self.validation_context = context;
    }

    pub fn validation_context(&self) -> &ParentValidationContext {
        &self.validation_context
    }

    pub fn published_name(&self, logical_key: &str) -> Option<&str> {
        self.objects
            .0
            .get(logical_key)
            .map(|object| object.name.as_str())
    }

    pub fn logical_key_for_name(&self, name: &str) -> Option<&str> {
        self.objects
            .0
            .values()
            .find(|object| object.name == name)
            .map(|object| object.logical_key.as_str())
    }

    pub fn object_kind_for_name(&self, name: &str) -> Option<ObjectKind> {
        self.objects
            .0
            .values()
            .find(|object| object.name == name)
            .map(|object| object.kind)
    }

    pub fn toa_reviews(&self) -> impl Iterator<Item = (&str, &ToaReview)> {
        self.objects.0.values().filter_map(|object| {
            object
                .toa_review
                .as_ref()
                .map(|review| (object.name.as_str(), review))
        })
    }

    pub fn published_names(&self, kind: ObjectKind) -> Vec<String> {
        self.objects
            .0
            .values()
            .filter(|object| object.kind == kind)
            .map(|object| object.name.clone())
            .collect()
    }

    pub fn published_entries(&self, kind: ObjectKind) -> Vec<(String, String)> {
        self.objects
            .0
            .iter()
            .filter(|(_, object)| object.kind == kind)
            .map(|(key, object)| (key.clone(), object.name.clone()))
            .collect()
    }

    pub fn signed_object(&self, logical_key: &str) -> Option<SignedObjectView> {
        self.objects
            .0
            .get(logical_key)
            .map(|object| SignedObjectView {
                kind: object.kind,
                logical_key: object.logical_key.clone(),
                object_name: object.name.clone(),
                definition: object.definition.clone(),
                ee_certificate_serial: object.ee.serial,
                ee_not_after: object.ee.not_after,
            })
    }

    pub fn signed_objects(&self, kind: ObjectKind) -> Vec<SignedObjectView> {
        let mut values = self
            .objects
            .0
            .values()
            .filter(|object| object.kind == kind)
            .map(|object| SignedObjectView {
                kind: object.kind,
                logical_key: object.logical_key.clone(),
                object_name: object.name.clone(),
                definition: object.definition.clone(),
                ee_certificate_serial: object.ee.serial,
                ee_not_after: object.ee.not_after,
            })
            .collect::<Vec<_>>();
        values.sort_by(|left, right| left.logical_key.cmp(&right.logical_key));
        values
    }

    pub fn roa_configurations(&self) -> impl Iterator<Item = &RoaConfiguration> {
        self.roa_configurations.values()
    }

    pub fn has_roa_configurations(&self) -> bool {
        !self.roa_configurations.is_empty()
    }

    pub fn replace_roa_configurations(
        &mut self,
        configurations: BTreeMap<String, RoaConfiguration>,
    ) {
        self.roa_configurations = configurations;
    }

    pub fn published_object_names(&self) -> BTreeSet<String> {
        self.objects
            .0
            .values()
            .map(|object| object.name.clone())
            .collect()
    }

    pub fn update_toa_review(&mut self, name: &str, review: ToaReview) -> Result<()> {
        let object = self
            .objects
            .0
            .values_mut()
            .find(|object| object.name == name)
            .with_context(|| format!("TOA object '{name}' is not in the issued inventory"))?;
        if object.kind != ObjectKind::Toa {
            bail!("published object '{name}' is not a TOA");
        }
        object.toa_review = Some(review);
        Ok(())
    }

    #[cfg(test)]
    pub fn next_certificate_serial(&self) -> u64 {
        self.serials.next_certificate_serial
    }

    #[cfg(test)]
    pub fn object(&self, name: &str) -> Option<&IssuedEe> {
        self.objects
            .0
            .values()
            .find(|object| object.name == name)
            .map(|object| &object.ee)
    }

    #[cfg(test)]
    pub fn manifest_ee(&self) -> Option<&IssuedEe> {
        self.manifest.current_ee.as_ref()
    }
}

impl SerialAllocator {
    fn allocate_publication(&mut self, object_count: usize) -> Result<PublicationNumbers> {
        if object_count == 0 {
            bail!("publication batch must contain at least one signed object");
        }
        let object_count =
            u64::try_from(object_count).context("too many objects in publication")?;
        let first_object_serial = self.next_certificate_serial;
        let manifest_ee_serial = first_object_serial
            .checked_add(object_count)
            .context("certificate serial space exhausted")?;
        self.next_certificate_serial = manifest_ee_serial
            .checked_add(1)
            .context("certificate serial space exhausted")?;
        let publication_number = self.next_publication_number;
        self.next_publication_number = publication_number
            .checked_add(1)
            .context("publication number exhausted")?;
        Ok(PublicationNumbers {
            object_ee_serials: (first_object_serial..manifest_ee_serial).collect(),
            manifest_ee_serial,
            publication_number,
        })
    }

    fn allocate_refresh(&mut self) -> Result<PublicationNumbers> {
        let manifest_ee_serial = self.next_certificate_serial;
        self.next_certificate_serial = manifest_ee_serial
            .checked_add(1)
            .context("certificate serial space exhausted")?;
        let publication_number = self.next_publication_number;
        self.next_publication_number = publication_number
            .checked_add(1)
            .context("publication number exhausted")?;
        Ok(PublicationNumbers {
            object_ee_serials: Vec::new(),
            manifest_ee_serial,
            publication_number,
        })
    }
}

impl RevocationSet {
    fn revoke(&mut self, issued: IssuedEe, now: i64) {
        if issued.not_after > now && !self.0.iter().any(|item| item.serial == issued.serial) {
            self.0.push(Revocation {
                serial: issued.serial,
                revoked_at: now,
                not_after: issued.not_after,
            });
        }
    }
}

pub(crate) struct PublicationNumbers {
    pub object_ee_serials: Vec<u64>,
    pub manifest_ee_serial: u64,
    pub publication_number: u64,
}

impl PublicationNumbers {
    pub fn single_object_serial(&self) -> u64 {
        *self
            .object_ee_serials
            .first()
            .expect("single-object publication has an object serial")
    }
}

#[cfg(test)]
#[path = "../../tests/unit/ca/state.rs"]
mod tests;
