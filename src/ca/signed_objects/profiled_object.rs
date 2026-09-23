//! Shared signed-object mechanics for locally implemented RPKI profiles.

use bcder::{Captured, Mode, encode, encode::Values};
use rpki::repository::{
    cert::{Cert, ResourceCert},
    error::{ValidationError, VerificationError},
    sigobj::SignedObject,
};

/// A signed-object wrapper paired with its already decoded profile content.
///
/// Profile modules retain ownership of ASN.1 and resource rules. This type
/// only centralises encoding and the common RFC 6488 validate/check-CRL flow.
#[derive(Clone, Debug)]
pub(crate) struct ProfiledSignedObject<C> {
    signed: SignedObject,
    content: C,
}

impl<C> ProfiledSignedObject<C> {
    pub fn new(signed: SignedObject, content: C) -> Self {
        Self { signed, content }
    }

    pub fn cert(&self) -> &Cert {
        self.signed.cert()
    }

    pub fn content(&self) -> &C {
        &self.content
    }

    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        self.signed.encode_ref()
    }

    pub fn to_captured(&self) -> Captured {
        self.encode_ref().to_captured(Mode::Der)
    }

    pub fn process<F, I, V>(
        self,
        issuer: &ResourceCert,
        check_crl: F,
        inspect_profile: I,
        verify_resources: V,
    ) -> Result<(ResourceCert, C), ValidationError>
    where
        F: FnOnce(&Cert) -> Result<(), ValidationError>,
        I: FnOnce(&C, &Cert) -> Result<(), VerificationError>,
        V: FnOnce(&C, &ResourceCert) -> Result<(), VerificationError>,
    {
        let (ee, _) = self.signed.process(issuer, true, check_crl)?;
        inspect_profile(&self.content, ee.as_ref())?;
        verify_resources(&self.content, &ee)?;
        Ok((ee, self.content))
    }
}
