use super::Params;
use crate::AspaRequest;
use anyhow::{Context, Result};
use rpki::repository::aspa::{Aspa, AspaBuilder};

pub(crate) fn issue(request: &AspaRequest, params: Params<'_>) -> Result<Vec<u8>> {
    let providers = request
        .canonical_providers()
        .into_iter()
        .map(Into::into)
        .collect::<Vec<_>>();
    let builder = AspaBuilder::new(request.customer_asn.into(), providers)?;
    let signed = params.signed_object_builder()?;
    let object = builder
        .finalize(signed, params.signer, params.signer.primary_key_id())
        .map_err(|e| anyhow::anyhow!("ASPA signing failed: {e}"))?;
    let bytes = object.to_captured().into_bytes();
    Aspa::decode(bytes.clone(), true).context("generated ASPA failed strict decoding")?;
    Ok(bytes.to_vec())
}
