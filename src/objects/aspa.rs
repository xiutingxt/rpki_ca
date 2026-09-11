//! IETF SIDROPS ASPA profile definitions.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AspaRequest {
    pub customer_asn: u32,
    pub provider_asns: Vec<u32>,
}

impl AspaRequest {
    pub fn validate(&self) -> Result<()> {
        if self.customer_asn == 0 {
            bail!("an ASPA customer ASN cannot be AS0");
        }
        if self.provider_asns.is_empty() {
            bail!("an ASPA needs at least one provider ASN");
        }
        if self.provider_asns.contains(&self.customer_asn) {
            bail!("customer ASN cannot also be a provider ASN");
        }
        let providers = self.canonical_providers();
        if providers.contains(&0) && providers.len() != 1 {
            bail!("provider ASN 0 must be the only provider");
        }
        Ok(())
    }

    pub(crate) fn canonical_providers(&self) -> Vec<u32> {
        let mut values = self.provider_asns.clone();
        values.sort_unstable();
        values.dedup();
        values
    }
}

#[cfg(test)]
#[path = "../../tests/unit/objects/aspa.rs"]
mod tests;
