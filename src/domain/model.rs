use crate::{AspaRequest, RoaRequest};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ObjectKind {
    #[default]
    Roa,
    Aspa,
}

impl ObjectKind {
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Roa => "roa",
            Self::Aspa => "asa",
        }
    }
}

impl fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Roa => "roa",
            Self::Aspa => "aspa",
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", content = "definition", rename_all = "lowercase")]
pub enum ObjectDefinition {
    Roa(RoaRequest),
    Aspa(AspaRequest),
}

impl ObjectDefinition {
    pub const fn kind(&self) -> ObjectKind {
        match self {
            Self::Roa(_) => ObjectKind::Roa,
            Self::Aspa(_) => ObjectKind::Aspa,
        }
    }
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Roa(v) => v.validate(),
            Self::Aspa(v) => v.validate(),
        }
    }
    pub fn logical_key(&self, requested_name: &str) -> String {
        match self {
            Self::Roa(_) => format!("roa:{requested_name}"),
            Self::Aspa(v) => format!("aspa:AS{}", v.customer_asn),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CaImportRequest {
    pub certificate: Vec<u8>,
    pub private_key_pem: String,
    pub serial_start: u64,
    pub crl_number_start: u64,
    pub manifest_number_start: u64,
    pub chain: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
    pub manifests: Vec<Vec<u8>>,
}

/// A replacement certificate for the current CA key, plus the material
/// needed to validate its path to the configured trust anchor.
#[derive(Clone, Debug)]
pub struct CaCertificateRenewal {
    pub certificate: Vec<u8>,
    pub chain: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
    pub manifests: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CaCertificateStatus {
    pub not_before: i64,
    pub not_after: i64,
    pub seconds_remaining: i64,
    pub renewal_required: bool,
    pub expired: bool,
}
