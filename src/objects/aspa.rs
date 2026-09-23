//! IETF SIDROPS ASPA profile definitions.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AspaRequest {
    pub customer_asn: u32,
    pub provider_asns: Vec<u32>,
}

/// A batch update of ASPA definitions. Entries in `added` create or replace
/// the definition identified by their Customer ASN. Unknown removals and
/// definitions that already have the requested content are harmless no-ops.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AspaDelta {
    #[serde(default)]
    pub added: Vec<AspaRequest>,
    #[serde(default)]
    pub removed: Vec<u32>,
}

impl AspaRequest {
    pub fn validate(&self) -> Result<()> {
        if self.customer_asn == 0 {
            bail!("ASPA 的 Customer ASN 不能为 AS0");
        }
        if self.provider_asns.is_empty() {
            bail!("ASPA 的 Provider ASN 集合不能为空");
        }
        if self.provider_asns.contains(&self.customer_asn) {
            bail!(
                "ASPA 的 Customer ASN AS{} 不能同时出现在 Provider ASN 集合中",
                self.customer_asn
            );
        }
        let providers = self.canonical_providers();
        if providers.contains(&0) && providers.len() != 1 {
            bail!("AS0 表示没有 Transit Provider，因此作为 Provider ASN 时必须单独出现");
        }
        Ok(())
    }

    pub(crate) fn canonical_providers(&self) -> Vec<u32> {
        let mut values = self.provider_asns.clone();
        values.sort_unstable();
        values.dedup();
        values
    }

    pub(crate) fn canonicalized(mut self) -> Self {
        self.provider_asns = self.canonical_providers();
        self
    }
}

#[cfg(test)]
#[path = "../../tests/unit/objects/aspa.rs"]
mod tests;
