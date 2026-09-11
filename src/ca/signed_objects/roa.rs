use super::Params;
use crate::RoaRequest;
use anyhow::{Context, Result};
use rpki::repository::{
    roa::{Roa, RoaBuilder},
    sigobj::SignedObjectBuilder,
};

pub(crate) fn issue(request: &RoaRequest, params: Params<'_>) -> Result<Vec<u8>> {
    let mut builder = RoaBuilder::new(request.asn.into());
    for item in request.canonical_prefixes() {
        builder.push_addr(
            item.prefix.addr(),
            item.prefix.prefix_len(),
            item.max_length,
        );
    }
    let signed = SignedObjectBuilder::new(
        params.serial.into(),
        params.validity,
        params.crl_uri.clone(),
        params.certificate_uri.clone(),
        params.repository_uri.join(params.name.as_bytes())?,
    );
    let object = builder
        .finalize(signed, params.signer, params.signer.primary_key_id())
        .map_err(|e| anyhow::anyhow!("ROA signing failed: {e}"))?;
    let bytes = object.to_captured().into_bytes();
    Roa::decode(bytes.clone(), true).context("generated ROA failed strict decoding")?;
    Ok(bytes.to_vec())
}
