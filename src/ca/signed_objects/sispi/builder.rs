use super::{content::SispiContent, object::Sispi};
use crate::constants::SISPI_CONTENT_TYPE_OID_BYTES;
use bcder::{Mode, Oid, encode::Values};
use bytes::Bytes;
use rpki::{
    crypto::{Signer, SigningError},
    repository::{
        resources::{Asn, Prefix},
        sigobj::SignedObjectBuilder,
    },
};

/// Builds SiSPI content and its EE AS resources from one source of truth.
pub(super) struct SispiBuilder {
    content: SispiContent,
}

impl SispiBuilder {
    pub fn new(asn: Asn, v4_addresses: Vec<Prefix>, v6_addresses: Vec<Prefix>) -> Self {
        Self {
            content: SispiContent::new(asn, v4_addresses, v6_addresses),
        }
    }

    pub fn finalize<S: Signer>(
        self,
        mut signed: SignedObjectBuilder,
        signer: &S,
        issuer_key: &S::KeyId,
    ) -> Result<Sispi, SigningError<S::Error>> {
        signed.set_as_resources(self.content.as_resources());
        let encoded = self
            .content
            .encode_ref()
            .to_captured(Mode::Der)
            .into_bytes();
        let oid = Oid(Bytes::from_static(SISPI_CONTENT_TYPE_OID_BYTES));
        let object = signed.finalize(oid, encoded, signer, issuer_key)?;
        Ok(Sispi::from_parts(object, self.content))
    }
}
