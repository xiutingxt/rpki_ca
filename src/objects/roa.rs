//! RFC 9582 Route Origin Authorization definitions.

use anyhow::{Result, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RoaRequest {
    pub asn: u32,
    pub prefixes: Vec<RoaPayload>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RoaPayload {
    pub prefix: IpNet,
    pub max_length: Option<u8>,
}

impl RoaRequest {
    pub fn validate(&self) -> Result<()> {
        if self.prefixes.is_empty() {
            bail!("a ROA needs at least one prefix");
        }
        for item in &self.prefixes {
            let plen = item.prefix.prefix_len();
            let family_max = if item.prefix.addr().is_ipv4() {
                32
            } else {
                128
            };
            if let Some(max) = item.max_length
                && (max < plen || max > family_max)
            {
                bail!(
                    "invalid max-length {max} for prefix {} (expected {plen}..={family_max})",
                    item.prefix
                );
            }
            if item.prefix.trunc() != item.prefix {
                bail!("prefix {} has host bits set", item.prefix);
            }
        }
        Ok(())
    }

    pub(crate) fn canonical_prefixes(&self) -> Vec<RoaPayload> {
        let mut values = self.prefixes.clone();
        for item in &mut values {
            if item.max_length == Some(item.prefix.prefix_len()) {
                item.max_length = None;
            }
        }
        values.sort_by_key(sort_key);
        values.dedup_by(|a, b| sort_key(a) == sort_key(b));
        values
    }
}

fn sort_key(item: &RoaPayload) -> (u8, u128, u8, u8) {
    let (afi, addr) = match item.prefix.addr() {
        std::net::IpAddr::V4(v) => (1, u32::from(v).into()),
        std::net::IpAddr::V6(v) => (2, u128::from(v)),
    };
    (
        afi,
        addr,
        item.prefix.prefix_len(),
        item.max_length.unwrap_or(item.prefix.prefix_len()),
    )
}

#[cfg(test)]
#[path = "../../tests/unit/objects/roa.rs"]
mod tests;
