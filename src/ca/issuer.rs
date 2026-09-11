use crate::{
    AspaRequest, RoaRequest,
    ca::publication,
    infrastructure::signing::{SignedObjectOutput, SoftwareSigner},
};
use anyhow::{Context, Result};
use rpki::{
    crypto::{DigestAlgorithm, RpkiSignatureAlgorithm},
    repository::{
        cert::Cert,
        crl::{Crl, CrlEntry, TbsCertList},
        manifest::Manifest,
        manifest::{FileAndHash, ManifestContent},
        sigobj::SignedObjectBuilder,
        x509::{Time, Validity},
    },
    uri,
};

pub(crate) struct ObjectIssuer<'a> {
    cert: &'a Cert,
    signer: &'a SoftwareSigner,
    repository_uri: uri::Rsync,
    certificate_uri: uri::Rsync,
    crl_uri: uri::Rsync,
}

impl<'a> ObjectIssuer<'a> {
    pub fn new(
        cert: &'a Cert,
        signer: &'a SoftwareSigner,
        repository_uri: uri::Rsync,
        certificate_uri: uri::Rsync,
        crl_uri: uri::Rsync,
    ) -> Self {
        Self {
            cert,
            signer,
            repository_uri,
            certificate_uri,
            crl_uri,
        }
    }

    pub fn issue_roa(
        &self,
        request: &RoaRequest,
        serial: u64,
        validity: Validity,
    ) -> Result<SignedObjectOutput> {
        let signer = self.signer.prepare_one_off().map_err(anyhow::Error::msg)?;
        let name = format!(
            "{}.roa",
            publication::key_basename(signer.one_off_public_key())
        );
        let bytes = super::signed_objects::roa::issue(
            request,
            super::signed_objects::Params {
                name: &name,
                serial,
                validity,
                repository_uri: &self.repository_uri,
                certificate_uri: &self.certificate_uri,
                crl_uri: &self.crl_uri,
                signer: &signer,
            },
        )?;
        Ok(SignedObjectOutput { name, bytes })
    }

    pub fn issue_aspa(
        &self,
        request: &AspaRequest,
        serial: u64,
        validity: Validity,
    ) -> Result<SignedObjectOutput> {
        let signer = self.signer.prepare_one_off().map_err(anyhow::Error::msg)?;
        let name = format!(
            "{}.asa",
            publication::key_basename(signer.one_off_public_key())
        );
        let bytes = super::signed_objects::aspa::issue(
            request,
            super::signed_objects::Params {
                name: &name,
                serial,
                validity,
                repository_uri: &self.repository_uri,
                certificate_uri: &self.certificate_uri,
                crl_uri: &self.crl_uri,
                signer: &signer,
            },
        )?;
        Ok(SignedObjectOutput { name, bytes })
    }

    pub fn issue_crl(
        &self,
        serial: u64,
        this_update: Time,
        next_update: Time,
        revoked: Vec<CrlEntry>,
    ) -> Result<Vec<u8>> {
        let crl = TbsCertList::new(
            RpkiSignatureAlgorithm::default(),
            self.cert.subject().clone(),
            this_update,
            next_update,
            revoked,
            self.cert.subject_key_identifier(),
            serial.into(),
        )
        .into_crl(self.signer, self.signer.primary_key_id())
        .map_err(|err| anyhow::anyhow!("CRL signing failed: {err}"))?;
        let bytes = crl.to_captured().into_bytes();
        Crl::decode(bytes.clone()).context("generated CRL failed strict decoding")?;
        Ok(bytes.to_vec())
    }

    pub fn issue_manifest(
        &self,
        serial: u64,
        manifest_number: u64,
        this_update: Time,
        next_update: Time,
        entries: &[FileAndHash<Vec<u8>, Vec<u8>>],
        manifest_uri: uri::Rsync,
    ) -> Result<Vec<u8>> {
        let digest = DigestAlgorithm::sha256();
        let content = ManifestContent::new(
            manifest_number.into(),
            this_update,
            next_update,
            digest,
            entries.iter(),
        );
        let signed = SignedObjectBuilder::new(
            serial.into(),
            Validity::new(this_update, next_update),
            self.crl_uri.clone(),
            self.certificate_uri.clone(),
            manifest_uri,
        );
        let manifest = content
            .into_manifest(signed, self.signer, self.signer.primary_key_id())
            .map_err(|err| anyhow::anyhow!("manifest signing failed: {err}"))?;
        let bytes = manifest.to_captured().into_bytes();
        Manifest::decode(bytes.clone(), true)
            .context("generated manifest failed strict decoding")?;
        Ok(bytes.to_vec())
    }
}
