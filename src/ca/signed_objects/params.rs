use crate::infrastructure::signing::PreparedSoftwareSigner;
use anyhow::Result;
use rpki::{
    repository::{sigobj::SignedObjectBuilder, x509::Validity},
    uri,
};

pub struct Params<'a> {
    pub name: &'a str,
    pub serial: u64,
    pub validity: Validity,
    pub repository_uri: &'a uri::Rsync,
    pub certificate_uri: &'a uri::Rsync,
    pub crl_uri: &'a uri::Rsync,
    pub signer: &'a PreparedSoftwareSigner<'a>,
}

impl Params<'_> {
    /// Creates the RFC 6488 builder shared by every supported signed object.
    pub fn signed_object_builder(&self) -> Result<SignedObjectBuilder> {
        Ok(SignedObjectBuilder::new(
            self.serial.into(),
            self.validity,
            self.crl_uri.clone(),
            self.certificate_uri.clone(),
            self.repository_uri.join(self.name.as_bytes())?,
        ))
    }
}
