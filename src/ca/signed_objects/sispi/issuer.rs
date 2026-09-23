use super::{builder::SispiBuilder, object::Sispi};
use crate::{SispiRequest, ca::signed_objects::Params, constants::SISPI_CONTENT_TYPE_OID};
use anyhow::{Context, Result};
use rpki::repository::resources::{Asn, Prefix};

pub(crate) fn issue(request: &SispiRequest, params: Params<'_>) -> Result<Vec<u8>> {
    let mut v4_addresses = Vec::new();
    let mut v6_addresses = Vec::new();
    for address in request.canonical_addresses() {
        if address.is_ipv4() {
            v4_addresses.push(Prefix::new(address, 32));
        } else {
            v6_addresses.push(Prefix::new(address, 128));
        }
    }
    let builder = SispiBuilder::new(Asn::from(request.as_id), v4_addresses, v6_addresses);
    let signed = params.signed_object_builder()?;
    let object = builder
        .finalize(signed, params.signer, params.signer.primary_key_id())
        .map_err(|error| anyhow::anyhow!("SiSPI signing failed: {error}"))?;
    let bytes = object.to_captured().into_bytes();
    Sispi::decode(bytes.clone()).with_context(|| {
        format!("generated SiSPI ({SISPI_CONTENT_TYPE_OID}) failed strict profile decoding")
    })?;
    Ok(bytes.to_vec())
}
