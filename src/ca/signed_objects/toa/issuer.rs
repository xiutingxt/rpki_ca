use super::{builder::ToaBuilder, object::Toa};
use crate::{ToaRequest, ca::signed_objects::Params, constants::TOA_CONTENT_TYPE_OID};
use anyhow::{Context, Result};
use rpki::repository::resources::{Asn, Prefix};

pub(crate) fn issue(request: &ToaRequest, params: Params<'_>) -> Result<Vec<u8>> {
    let asns = request
        .canonical_asns()
        .into_iter()
        .map(Asn::from)
        .collect();
    let mut v4_prefixes = Vec::new();
    let mut v6_prefixes = Vec::new();
    for prefix in request.canonical_prefixes() {
        let value = Prefix::new(prefix.addr(), prefix.prefix_len());
        if prefix.addr().is_ipv4() {
            v4_prefixes.push(value);
        } else {
            v6_prefixes.push(value);
        }
    }
    let builder = ToaBuilder::new(asns, v4_prefixes, v6_prefixes);
    let signed = params.signed_object_builder()?;
    let object = builder
        .finalize(signed, params.signer, params.signer.primary_key_id())
        .map_err(|error| anyhow::anyhow!("TOA signing failed: {error}"))?;
    let bytes = object.to_captured().into_bytes();
    Toa::decode(bytes.clone()).with_context(|| {
        format!("generated TOA ({TOA_CONTENT_TYPE_OID}) failed strict profile decoding")
    })?;
    Ok(bytes.to_vec())
}
