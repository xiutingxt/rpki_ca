use super::content::SispiContent;
use crate::{
    ca::signed_objects::profiled_object::ProfiledSignedObject,
    constants::SISPI_CONTENT_TYPE_OID_BYTES,
};
use anyhow::Result as AnyResult;
use bcder::Oid;
use bytes::Bytes;
use rpki::repository::{
    cert::{Cert, ResourceCert},
    error::ValidationError,
    sigobj::SignedObject,
};

#[derive(Clone, Debug)]
pub(crate) struct Sispi {
    inner: ProfiledSignedObject<SispiContent>,
}

impl Sispi {
    pub(super) fn from_parts(signed: SignedObject, content: SispiContent) -> Self {
        Self {
            inner: ProfiledSignedObject::new(signed, content),
        }
    }

    pub fn decode(source: Bytes) -> AnyResult<Self> {
        let oid = Oid(Bytes::from_static(SISPI_CONTENT_TYPE_OID_BYTES));
        let signed = SignedObject::decode_if_type(source, &oid, true)?;
        let content = signed.decode_content(SispiContent::take_from)?;
        Ok(Self::from_parts(signed, content))
    }

    pub fn cert(&self) -> &Cert {
        self.inner.cert()
    }

    pub fn content(&self) -> &SispiContent {
        self.inner.content()
    }

    pub fn to_captured(&self) -> bcder::Captured {
        self.inner.to_captured()
    }

    pub fn process<F>(
        self,
        issuer: &ResourceCert,
        check_crl: F,
    ) -> Result<(ResourceCert, SispiContent), ValidationError>
    where
        F: FnOnce(&Cert) -> Result<(), ValidationError>,
    {
        self.inner.process(
            issuer,
            check_crl,
            SispiContent::verify_ee_profile,
            SispiContent::verify_resources,
        )
    }
}
