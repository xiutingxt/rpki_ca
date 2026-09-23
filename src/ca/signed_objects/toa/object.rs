use super::content::ToaContent;
use crate::{
    ca::signed_objects::profiled_object::ProfiledSignedObject,
    constants::TOA_CONTENT_TYPE_OID_BYTES,
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
pub(crate) struct Toa {
    inner: ProfiledSignedObject<ToaContent>,
}

impl Toa {
    pub(super) fn from_parts(signed: SignedObject, content: ToaContent) -> Self {
        Self {
            inner: ProfiledSignedObject::new(signed, content),
        }
    }

    pub fn decode(source: Bytes) -> AnyResult<Self> {
        let oid = Oid(Bytes::from_static(TOA_CONTENT_TYPE_OID_BYTES));
        let signed = SignedObject::decode_if_type(source, &oid, true)?;
        let content = signed.decode_content(ToaContent::take_from)?;
        Ok(Self::from_parts(signed, content))
    }

    pub fn cert(&self) -> &Cert {
        self.inner.cert()
    }

    pub fn content(&self) -> &ToaContent {
        self.inner.content()
    }

    pub fn to_captured(&self) -> bcder::Captured {
        self.inner.to_captured()
    }

    pub fn process<F>(
        self,
        issuer: &ResourceCert,
        check_crl: F,
    ) -> Result<(ResourceCert, ToaContent), ValidationError>
    where
        F: FnOnce(&Cert) -> Result<(), ValidationError>,
    {
        self.inner.process(
            issuer,
            check_crl,
            ToaContent::verify_ee_profile,
            ToaContent::verify_resources,
        )
    }
}
