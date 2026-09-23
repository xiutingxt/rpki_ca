//! Operational TOA policy from draft-qin-savnet-toa-02, Section 7.1.

use crate::{ToaRequest, infrastructure::repository::PublicationRepository};
use anyhow::{Context, Result};
use ipnet::IpNet;
use rpki::repository::roa::Roa;
use std::{collections::BTreeSet, error::Error, fmt};

#[derive(Debug)]
pub(crate) struct ToaRoaOverlapJustificationRequired {
    total_pairs: usize,
    covering_roas: String,
}

impl fmt::Display for ToaRoaOverlapJustificationRequired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "TOA 的全部 {} 个 (ASN, 前缀) 对已被现有 ROA 覆盖（{}）；草案建议不要重复注册。若确有运行原因，请提供 roa_overlap_justification",
            self.total_pairs, self.covering_roas
        )
    }
}

impl Error for ToaRoaOverlapJustificationRequired {}

#[derive(Clone, Debug)]
pub(crate) struct ToaRoaAssessment {
    pub total_pairs: usize,
    pub covered_pairs: usize,
    pub covering_roas: BTreeSet<String>,
}

impl ToaRoaAssessment {
    pub fn evaluate(
        repository: &dyn PublicationRepository,
        roa_names: &[String],
        request: &ToaRequest,
    ) -> Result<Self> {
        let mut authorizations = Vec::new();
        for name in roa_names {
            let bytes = repository
                .read(name)
                .with_context(|| format!("cannot read existing ROA {name}"))?;
            let roa = Roa::decode(bytes.as_slice(), true)
                .with_context(|| format!("cannot decode existing ROA {name}"))?;
            let asn = u32::from(roa.content().as_id());
            for prefix in roa.content().iter() {
                authorizations.push(RoaAuthorization {
                    asn,
                    prefix: IpNet::new(prefix.address(), prefix.address_length())
                        .expect("strictly decoded ROA prefix is valid"),
                    max_length: prefix.max_length(),
                    name: name.to_owned(),
                });
            }
        }

        let asns = request.canonical_asns();
        let prefixes = request.canonical_prefixes();
        let total_pairs = asns.len().saturating_mul(prefixes.len());
        let mut covered_pairs = 0;
        let mut covering_roas = BTreeSet::new();
        for asn in asns {
            for prefix in &prefixes {
                let mut covered = false;
                for authorization in &authorizations {
                    if authorization.covers(asn, prefix) {
                        covered = true;
                        covering_roas.insert(authorization.name.clone());
                    }
                }
                covered_pairs += usize::from(covered);
            }
        }
        Ok(Self {
            total_pairs,
            covered_pairs,
            covering_roas,
        })
    }

    pub fn enforce(&self, request: &ToaRequest) -> Result<Vec<String>> {
        if self.total_pairs == 0 || self.covered_pairs == 0 {
            return Ok(Vec::new());
        }
        let sources = self
            .covering_roas
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if self.covered_pairs == self.total_pairs {
            let Some(reason) = request
                .roa_overlap_justification
                .as_deref()
                .map(str::trim)
                .filter(|reason| !reason.is_empty())
            else {
                return Err(ToaRoaOverlapJustificationRequired {
                    total_pairs: self.total_pairs,
                    covering_roas: sources,
                }
                .into());
            };
            return Ok(vec![format!(
                "TOA 的全部 {} 个 (ASN, 前缀) 对已被 ROA 覆盖；已记录运行例外理由：{}",
                self.total_pairs, reason
            )]);
        }
        Ok(vec![format!(
            "TOA 中 {} / {} 个 (ASN, 前缀) 对与现有 ROA 重叠（{}）；按草案建议保留单个合并 TOA，未拆分对象",
            self.covered_pairs, self.total_pairs, sources
        )])
    }
}

struct RoaAuthorization {
    asn: u32,
    prefix: IpNet,
    max_length: u8,
    name: String,
}

impl RoaAuthorization {
    fn covers(&self, asn: u32, prefix: &IpNet) -> bool {
        self.asn == asn
            && self.prefix.addr().is_ipv4() == prefix.addr().is_ipv4()
            && self.prefix.prefix_len() <= prefix.prefix_len()
            && prefix.prefix_len() <= self.max_length
            && self.prefix.contains(&prefix.addr())
    }
}

#[cfg(test)]
#[path = "../../tests/unit/ca/toa_policy.rs"]
mod tests;
