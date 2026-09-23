use crate::{AspaRequest, RoaRequest, SispiRequest, ToaRequest};
use anyhow::{Context, Result};
use rpki::repository::{cert::Cert, resources::ResourceSet, roa::RoaIpAddress};
use serde::Serialize;

#[derive(Debug)]
pub struct ResourceAuthorizationError(pub String);

impl std::fmt::Display for ResourceAuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ResourceAuthorizationError {}

/// API-friendly view of the resources currently certified to this CA.
///
/// The compact strings deliberately match the representation used by Krill's
/// CA details API: comma-separated canonical resource blocks per family.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CertifiedResourcesView {
    pub asn: String,
    pub ipv4: String,
    pub ipv6: String,
}

impl From<&ResourceSet> for CertifiedResourcesView {
    fn from(resources: &ResourceSet) -> Self {
        Self {
            asn: resources.asn().to_string(),
            ipv4: resources.ipv4().to_string(),
            ipv6: resources.ipv6().to_string(),
        }
    }
}

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

    pub fn view(&self) -> CertifiedResourcesView {
        CertifiedResourcesView::from(&self.resources)
    }

    pub fn authorizes_roa(&self, request: &RoaRequest) -> Result<()> {
        for payload in &request.prefixes {
            let address = RoaIpAddress::new_addr(
                payload.prefix.addr(),
                payload.prefix.prefix_len(),
                payload.max_length,
            );
            if !self.resources.contains_roa_address(&address) {
                return Err(ResourceAuthorizationError(format!(
                    "无法签发 ROA：前缀 {} 不在当前 CA 证书授权的 IP 资源范围内",
                    payload.prefix
                ))
                .into());
            }
        }
        Ok(())
    }

    pub fn authorizes_aspa(&self, request: &AspaRequest) -> Result<()> {
        if !self.resources.contains_asn(request.customer_asn.into()) {
            return Err(ResourceAuthorizationError(format!(
                "无法签发 ASPA：Customer ASN AS{} 不在当前 CA 证书授权的 ASN 资源范围内",
                request.customer_asn
            ))
            .into());
        }
        Ok(())
    }

    pub fn authorizes_sispi(&self, request: &SispiRequest) -> Result<()> {
        if !self.resources.contains_asn(request.as_id.into()) {
            return Err(ResourceAuthorizationError(format!(
                "无法签发 SiSPI：AS{} 不在当前 CA 证书授权的 ASN 资源范围内",
                request.as_id
            ))
            .into());
        }
        Ok(())
    }

    pub fn authorizes_toa(&self, request: &ToaRequest) -> Result<()> {
        for prefix in &request.prefixes {
            let address = RoaIpAddress::new_addr(prefix.addr(), prefix.prefix_len(), None);
            if !self.resources.contains_roa_address(&address) {
                return Err(ResourceAuthorizationError(format!(
                    "无法签发 TOA：源地址前缀 {prefix} 不在当前 CA 证书授权的 IP 资源范围内"
                ))
                .into());
            }
        }
        Ok(())
    }
}
