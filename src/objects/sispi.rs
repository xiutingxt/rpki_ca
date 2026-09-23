//! Signed SAVNET-Peering Information from draft-chen-sidrops-sispi-06.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SispiRequest {
    pub as_id: u32,
    pub addresses: Vec<IpAddr>,
}

/// A batch update of SiSPI definitions. Entries in `added` create or replace
/// the definition identified by their AS ID. Unknown removals and definitions
/// that already have the requested content are harmless no-ops.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SispiDelta {
    #[serde(default)]
    pub added: Vec<SispiRequest>,
    #[serde(default)]
    pub removed: Vec<u32>,
}

impl SispiRequest {
    pub fn validate(&self) -> Result<()> {
        if self.addresses.is_empty() {
            bail!("SiSPI 的 SAVNET Agent 地址列表不能为空");
        }
        Ok(())
    }

    pub(crate) fn canonical_addresses(&self) -> Vec<IpAddr> {
        let mut values = self.addresses.clone();
        values.sort_by_key(|address| match address {
            IpAddr::V4(value) => (1, u32::from(*value) as u128),
            IpAddr::V6(value) => (2, u128::from(*value)),
        });
        values.dedup();
        values
    }

    pub(crate) fn canonicalized(mut self) -> Self {
        self.addresses = self.canonical_addresses();
        self
    }
}

#[cfg(test)]
#[path = "../../tests/unit/objects/sispi.rs"]
mod tests;
