//! Traffic Origin Authorization from draft-qin-savnet-toa-02.

use anyhow::{Result, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToaRequest {
    pub asns: Vec<u32>,
    pub prefixes: Vec<IpNet>,
    /// Operational reason for creating a TOA that is entirely covered by
    /// existing ROAs. This metadata is audited by the CA and is not encoded
    /// into the TOA eContent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roa_overlap_justification: Option<String>,
}

#[cfg(test)]
#[path = "../../tests/unit/objects/toa.rs"]
mod tests;

impl ToaRequest {
    pub fn validate(&self) -> Result<()> {
        if let Some(reason) = &self.roa_overlap_justification {
            if reason.trim().is_empty() {
                bail!("TOA 的 ROA 重叠例外理由不能为空");
            }
            if reason.chars().count() > 1000 {
                bail!("TOA 的 ROA 重叠例外理由不能超过 1000 个字符");
            }
        }
        if self.asns.is_empty() {
            bail!("TOA 的授权 ASN 集合不能为空");
        }
        let canonical_asns = self.canonical_asns();
        if canonical_asns.len() > 10_000 {
            bail!(
                "TOA 的授权 ASN 集合最多包含 10000 个 ASN，当前为 {} 个",
                canonical_asns.len()
            );
        }
        if self.prefixes.is_empty() {
            bail!("TOA 的源地址前缀不能为空");
        }
        for prefix in &self.prefixes {
            if prefix.trunc() != *prefix {
                bail!(
                    "TOA 源地址前缀 {prefix} 不是规范网络前缀；该前缀长度对应的网络地址应为 {}（主机位必须全部为 0）",
                    prefix.trunc()
                );
            }
        }
        Ok(())
    }

    pub(crate) fn canonical_asns(&self) -> Vec<u32> {
        let mut values = self.asns.clone();
        values.sort_unstable();
        values.dedup();
        values
    }

    pub(crate) fn canonical_prefixes(&self) -> Vec<IpNet> {
        let mut values = self.prefixes.clone();
        values.sort_by_key(|prefix| match prefix.addr() {
            std::net::IpAddr::V4(addr) => (1, u32::from(addr) as u128, prefix.prefix_len()),
            std::net::IpAddr::V6(addr) => (2, u128::from(addr), prefix.prefix_len()),
        });
        values.dedup();
        values
    }

    pub(crate) fn canonicalized(mut self) -> Self {
        self.asns = self.canonical_asns();
        self.prefixes = self.canonical_prefixes();
        self.roa_overlap_justification = self
            .roa_overlap_justification
            .take()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        self
    }
}
