use super::{content::ToaContent, object::Toa};
use crate::constants::TOA_CONTENT_TYPE_OID_BYTES;
use bcder::{Mode, Oid, encode::Values};
use bytes::Bytes;
use rpki::{
    crypto::{Signer, SigningError},
    repository::{
        resources::{Asn, Prefix},
        sigobj::SignedObjectBuilder,
    },
};

/// Builds TOA content and its EE certificate resources from one source of truth.
pub(super) struct ToaBuilder {
    content: ToaContent,
}

impl ToaBuilder {
    pub fn new(asns: Vec<Asn>, v4_prefixes: Vec<Prefix>, v6_prefixes: Vec<Prefix>) -> Self {
        Self {
            content: ToaContent::new(asns, v4_prefixes, v6_prefixes),
        }
    }

    pub fn finalize<S: Signer>(
        self,
        mut signed: SignedObjectBuilder,
        signer: &S,
        issuer_key: &S::KeyId,
    ) -> Result<Toa, SigningError<S::Error>> {
        signed.set_v4_resources(self.content.v4_resources());
        signed.set_v6_resources(self.content.v6_resources());
        let encoded = self
            .content
            .encode_ref()
            .to_captured(Mode::Der)
            .into_bytes();
        let oid = Oid(Bytes::from_static(TOA_CONTENT_TYPE_OID_BYTES));
        let object = signed.finalize(oid, encoded, signer, issuer_key)?;
        Ok(Toa::from_parts(object, self.content))
    }
}
