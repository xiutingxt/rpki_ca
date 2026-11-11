use crate::ca::parent::ParentValidationContext;
use crate::ca::publication;
use crate::infrastructure::repository::PublicationRepository;
use anyhow::{Context, Result, ensure};
use rpki::{
    crypto::DigestAlgorithm,
    repository::{
        cert::{Cert, ResourceCert},
        crl::Crl,
        manifest::{Manifest, ManifestContent},
        x509::Time,
    },
};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct PublicationSet {
    objects: BTreeMap<String, Vec<u8>>,
    pub ca: ResourceCert,
    pub crl: Crl,
    manifest: ManifestContent,
    crl_name: String,
}

impl PublicationSet {
    pub fn load(
        repository: &dyn PublicationRepository,
        validation_context: &ParentValidationContext,
    ) -> Result<Self> {
        let objects = repository
            .list()?
            .into_iter()
            .map(|name| repository.read(&name).map(|bytes| (name, bytes)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        let ca_name = find_one(&objects, "cer")?;
        let crl_name = find_one(&objects, "crl")?;
        let manifest_name = find_one(&objects, "mft")?;
        let ca_cert = Cert::decode(read(&objects, &ca_name)?.as_slice())?;
        let ca = validation_context.validate(&ca_cert).map_err(|error| {
            anyhow::anyhow!("CA certification path validation failed: {error:#}")
        })?;
        ensure_recommended_name(&ca_name, &ca.subject_key_identifier(), "cer")?;
        ensure_recommended_name(&crl_name, &ca.subject_key_identifier(), "crl")?;
        ensure_recommended_name(&manifest_name, &ca.subject_key_identifier(), "mft")?;

        let crl_bytes = read(&objects, &crl_name)?;
        let crl = Crl::decode(crl_bytes.as_slice())?;
        crl.verify_signature(ca.subject_public_key_info())
            .map_err(|error| anyhow::anyhow!("CRL signature validation failed: {error}"))?;
        ensure!(crl.issuer() == ca.subject(), "CRL issuer does not match CA");
        ensure!(
            crl.authority_key_identifier() == &ca.subject_key_identifier(),
            "CRL authority key identifier does not match CA"
        );
        let now = Time::now();
        ensure!(crl.this_update() <= now, "CRL is not valid yet");
        ensure!(crl.next_update() >= now, "CRL is stale");

        let manifest = Manifest::decode(read(&objects, &manifest_name)?.as_slice(), true)?;
        ensure!(
            manifest.cert().signed_object() == ca.rpki_manifest(),
            "Manifest EE SIA does not match CA manifest URI"
        );
        ensure!(
            !crl.contains(manifest.cert().serial_number()),
            "Manifest EE certificate is revoked"
        );
        let (_, manifest) = manifest
            .validate(&ca, true)
            .map_err(|error| anyhow::anyhow!("Manifest validation failed: {error}"))?;
        ensure!(manifest.this_update() <= now, "Manifest is not valid yet");
        ensure!(manifest.next_update() >= now, "Manifest is stale");
        ensure!(
            manifest.file_hash_alg() == DigestAlgorithm::sha256(),
            "Manifest is not SHA-256"
        );

        let mut names = BTreeSet::new();
        let mut listed_crls = 0usize;
        for entry in manifest.iter() {
            let name = std::str::from_utf8(entry.file())
                .context("Manifest contains a non-ASCII filename")?;
            ensure!(
                names.insert(name.to_owned()),
                "Manifest contains duplicate filename {name}"
            );
            ensure!(name != manifest_name, "Manifest must not list itself");
            if name.ends_with(".crl") {
                listed_crls += 1;
            }
            let bytes = read(&objects, name)?;
            ensure!(
                manifest.file_hash_alg().digest(&bytes).as_ref() == entry.hash().as_ref(),
                "Manifest hash mismatch for {name}"
            );
        }
        ensure!(listed_crls == 1, "Manifest must list exactly one CRL");
        ensure!(
            names.contains(&crl_name),
            "Manifest does not list current CRL"
        );
        let crl_entry = manifest
            .iter()
            .find(|entry| entry.file().as_ref() == crl_name.as_bytes())
            .context("Manifest does not identify the CRL targeted by the CA")?;
        ensure!(
            manifest.file_hash_alg().digest(&crl_bytes).as_ref() == crl_entry.hash().as_ref(),
            "Current CRL hash does not match Manifest"
        );

        Ok(Self {
            objects,
            ca,
            crl,
            manifest,
            crl_name,
        })
    }

    pub fn validate_object(&self, name: &str, cert: &Cert, extension: &str) -> Result<Vec<u8>> {
        ensure_recommended_name(name, &cert.subject_key_identifier(), extension)?;
        ensure!(
            !self.crl.contains(cert.serial_number()),
            "object EE certificate is revoked"
        );
        let object_crl = cert
            .crl_uri()
            .context("object EE certificate has no CRLDP")?;
        ensure!(
            publication::uri_filename(object_crl.as_str())? == self.crl_name,
            "object EE certificate does not reference the Manifest-selected CRL"
        );
        let entry = self
            .manifest
            .iter()
            .find(|entry| entry.file().as_ref() == name.as_bytes())
            .context("Manifest does not list signed object")?;
        let bytes = read(&self.objects, name)?;
        ensure!(
            self.manifest.file_hash_alg().digest(&bytes).as_ref() == entry.hash().as_ref(),
            "Manifest hash mismatch for {name}"
        );
        Ok(bytes)
    }

    pub fn object_bytes(&self, name: &str) -> Result<Vec<u8>> {
        read(&self.objects, name)
    }

    /// Return only a complete validated publication inventory. The issuing CA
    /// certificate and Manifest are the two files not required as manifest members.
    pub fn publication_files(&self) -> Result<BTreeMap<String, Vec<u8>>> {
        let mut expected = self
            .manifest
            .iter()
            .map(|entry| std::str::from_utf8(entry.file()).map(str::to_owned))
            .collect::<std::result::Result<BTreeSet<_>, _>>()?;
        expected.insert(publication::key_filename(
            &self.ca.subject_key_identifier(),
            "cer",
        ));
        expected.insert(publication::key_filename(
            &self.ca.subject_key_identifier(),
            "mft",
        ));
        let actual = self.objects.keys().cloned().collect::<BTreeSet<_>>();
        ensure!(
            expected == actual,
            "repository contains files not listed by current Manifest"
        );
        Ok(self.objects.clone())
    }
}

fn read(repository: &BTreeMap<String, Vec<u8>>, name: &str) -> Result<Vec<u8>> {
    repository
        .get(name)
        .cloned()
        .with_context(|| format!("cannot read repository object {name}"))
}

fn ensure_recommended_name(
    actual: &str,
    key: &rpki::crypto::KeyIdentifier,
    extension: &str,
) -> Result<()> {
    let expected = publication::key_filename(key, extension);
    ensure!(
        actual == expected,
        "object name {actual} is not the RFC 6481 recommended name {expected}"
    );
    Ok(())
}

fn find_one(repository: &BTreeMap<String, Vec<u8>>, extension: &str) -> Result<String> {
    let suffix = format!(".{extension}");
    let mut matches = repository
        .keys()
        .filter(|name| name.ends_with(&suffix))
        .cloned();
    let name = matches
        .next()
        .with_context(|| format!("repository contains no {suffix} object"))?;
    ensure!(
        matches.next().is_none(),
        "repository contains multiple {suffix} objects"
    );
    Ok(name)
}
