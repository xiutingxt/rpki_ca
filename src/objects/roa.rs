//! RFC 9582 Route Origin Authorization definitions.

use anyhow::{Result, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoaRequest {
    pub asn: u32,
    pub prefixes: Vec<RoaPayload>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoaPayload {
    pub prefix: IpNet,
    pub max_length: Option<u8>,
}

/// Operator intent. Actual ROA files are derived from this configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoaConfiguration {
    pub asn: u32,
    pub prefix: IpNet,
    pub max_length: Option<u8>,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoaDelta {
    #[serde(default)]
    pub added: Vec<RoaConfiguration>,
    #[serde(default)]
    pub removed: Vec<RoaConfiguration>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RoaConfigurationView {
    #[serde(flatten)]
    pub configuration: RoaConfiguration,
    pub roa_objects: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RoaDeltaResponse {
    pub added: Vec<RoaConfiguration>,
    pub removed: Vec<RoaConfiguration>,
    pub configurations: Vec<RoaConfigurationView>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RoaDeltaError {
    pub duplicates: Vec<RoaConfiguration>,
    pub notheld: Vec<RoaConfiguration>,
    pub unknowns: Vec<RoaConfiguration>,
    pub invalid_length: Vec<RoaConfiguration>,
}

impl RoaDeltaError {
    pub fn is_empty(&self) -> bool {
        self.duplicates.is_empty()
            && self.notheld.is_empty()
            && self.unknowns.is_empty()
            && self.invalid_length.is_empty()
    }
}

#[derive(Debug)]
pub struct RoaDeltaRejected(pub RoaDeltaError);

impl fmt::Display for RoaDeltaRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ROA authorization delta was rejected")
    }
}

impl std::error::Error for RoaDeltaRejected {}

impl RoaConfiguration {
    pub fn validate(&self) -> Result<()> {
        self.to_request().validate()?;
        if self.comment.as_ref().is_some_and(|value| value.len() > 500) {
            bail!("ROA configuration comment must not exceed 500 bytes");
        }
        Ok(())
    }

    pub fn effective_max_length(&self) -> u8 {
        self.max_length.unwrap_or(self.prefix.prefix_len())
    }

    pub(crate) fn key(&self) -> String {
        format!(
            "AS{}|{}|{}",
            self.asn,
            self.prefix,
            self.effective_max_length()
        )
    }

    pub(crate) fn canonicalized(mut self) -> Self {
        if self.max_length == Some(self.prefix.prefix_len()) {
            self.max_length = None;
        }
        self.comment = self
            .comment
            .take()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        self
    }

    pub(crate) fn to_request(&self) -> RoaRequest {
        RoaRequest {
            asn: self.asn,
            prefixes: vec![RoaPayload {
                prefix: self.prefix,
                max_length: self.max_length,
            }],
        }
    }
}

pub(crate) fn configurations_by_key(
    values: impl IntoIterator<Item = RoaConfiguration>,
) -> BTreeMap<String, RoaConfiguration> {
    values
        .into_iter()
        .map(RoaConfiguration::canonicalized)
        .map(|value| (value.key(), value))
        .collect()
}

impl RoaRequest {
    pub fn validate(&self) -> Result<()> {
        if self.prefixes.is_empty() {
            bail!("ROA 的授权前缀不能为空");
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
                    "ROA 前缀 {} 的 maxLength={max} 无效；允许范围为 {plen}..={family_max}",
                    item.prefix
                );
            }
            if item.prefix.trunc() != item.prefix {
                bail!(
                    "ROA 授权前缀 {} 不是规范网络前缀；该前缀长度对应的网络地址应为 {}（主机位必须全部为 0）",
                    item.prefix,
                    item.prefix.trunc()
                );
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
