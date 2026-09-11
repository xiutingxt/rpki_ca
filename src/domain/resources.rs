use crate::{AspaRequest, RoaRequest};
use anyhow::{Context, Result, bail};
use rpki::repository::{cert::Cert, resources::ResourceSet, roa::RoaIpAddress};

/// The explicit resources certified for this CA.
///
/// Keeping this as a domain value prevents callers from repeatedly decoding
/// certificate extensions and centralises all resource-authorization rules.
#[derive(Clone, Debug)]
pub struct CertifiedResources {
    resources: ResourceSet,
}

impl CertifiedResources {
    pub(crate) fn new(resources: ResourceSet) -> Self {
        Self { resources }
    }

    pub fn from_certificate(cert: &Cert) -> Result<Self> {
        let resources = ResourceSet::try_from(cert).context(
            "certificate uses inherited resources; a resolved parent context is required",
        )?;
        Ok(Self { resources })
    }

    pub fn as_set(&self) -> &ResourceSet {
        &self.resources
    }

    pub fn authorizes_roa(&self, request: &RoaRequest) -> Result<()> {
        for payload in &request.prefixes {
            let address = RoaIpAddress::new_addr(
                payload.prefix.addr(),
                payload.prefix.prefix_len(),
                payload.max_length,
            );
            if !self.resources.contains_roa_address(&address) {
                bail!(
                    "ROA prefix {} is not covered by the CA resource certificate",
                    payload.prefix
                );
            }
        }
        Ok(())
    }

    pub fn authorizes_aspa(&self, request: &AspaRequest) -> Result<()> {
        if !self.resources.contains_asn(request.customer_asn.into()) {
            bail!(
                "ASPA customer ASN {} is not covered by the CA resource certificate",
                request.customer_asn
            );
        }
        Ok(())
    }
}
