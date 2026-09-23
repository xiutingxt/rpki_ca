use crate::{AspaRequest, RoaRequest, SispiRequest, ToaRequest};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ObjectKind {
    #[default]
    Roa,
    Aspa,
    Sispi,
    Toa,
}

impl ObjectKind {
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Roa => "roa",
            Self::Aspa => "asa",
            Self::Sispi => "sav",
            Self::Toa => "toa",
        }
    }

    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension {
            "roa" => Some(Self::Roa),
            "asa" => Some(Self::Aspa),
            "sav" => Some(Self::Sispi),
            "toa" => Some(Self::Toa),
            _ => None,
        }
    }
}

impl fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Roa => "roa",
            Self::Aspa => "aspa",
            Self::Sispi => "sispi",
            Self::Toa => "toa",
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", content = "definition", rename_all = "lowercase")]
pub enum ObjectDefinition {
    Roa(RoaRequest),
    Aspa(AspaRequest),
    Sispi(SispiRequest),
    Toa(ToaRequest),
}

impl ObjectDefinition {
    pub const fn kind(&self) -> ObjectKind {
        match self {
            Self::Roa(_) => ObjectKind::Roa,
            Self::Aspa(_) => ObjectKind::Aspa,
            Self::Sispi(_) => ObjectKind::Sispi,
            Self::Toa(_) => ObjectKind::Toa,
        }
    }
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Roa(v) => v.validate(),
            Self::Aspa(v) => v.validate(),
            Self::Sispi(v) => v.validate(),
            Self::Toa(v) => v.validate(),
        }
    }

    pub fn canonicalized(self) -> Self {
        match self {
            Self::Roa(value) => Self::Roa(value),
            Self::Aspa(value) => Self::Aspa(value.canonicalized()),
            Self::Sispi(value) => Self::Sispi(value.canonicalized()),
            Self::Toa(value) => Self::Toa(value.canonicalized()),
        }
    }

    pub fn logical_key(&self) -> String {
        match self {
            Self::Roa(request) => format!("roa:AS{}", request.asn),
            Self::Aspa(v) => format!("aspa:AS{}", v.customer_asn),
            Self::Sispi(v) => format!("sispi:AS{}", v.as_id),
            Self::Toa(request) => {
                // Operational review metadata is not part of the TOA eContent
                // and therefore must not create a second logical object.
                let mut content = request.clone().canonicalized();
                content.roa_overlap_justification = None;
                let encoded = serde_json::to_vec(&content)
                    .expect("serializing a validated TOA definition cannot fail");
                format!("toa:{:x}", Sha256::digest(encoded))
            }
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SignedObjectView {
    pub kind: ObjectKind,
    pub logical_key: String,
    pub object_name: String,
    pub definition: Option<ObjectDefinition>,
    pub ee_certificate_serial: u64,
    pub ee_not_after: i64,
}

/// Result of an idempotent batch update of stable logical objects.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ObjectDeltaResponse {
    pub created: Vec<String>,
    pub updated: Vec<String>,
    pub removed: Vec<String>,
    pub unchanged: Vec<String>,
    pub objects: Vec<SignedObjectView>,
}

#[derive(Clone, Debug)]
pub struct SignedObjectIssuance {
    pub name: String,
    pub bytes: Vec<u8>,
    pub advisories: Vec<String>,
}

#[derive(Debug)]
pub struct CaIssuanceUnavailable(pub String);

impl fmt::Display for CaIssuanceUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CaIssuanceUnavailable {}

#[cfg(test)]
#[path = "../../tests/unit/domain/model.rs"]
mod tests;

#[derive(Clone, Debug)]
pub struct CaImportRequest {
    pub certificate: Vec<u8>,
    pub private_key_pem: String,
    pub serial_start: u64,
    pub publication_number_start: u64,
    pub chain: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
    pub manifests: Vec<Vec<u8>>,
    pub tal: Vec<u8>,
}

/// A replacement certificate for the current CA key, plus the material
/// needed to validate its path to the configured trust anchor.
#[derive(Clone, Debug)]
pub struct CaCertificateRenewal {
    pub certificate: Vec<u8>,
    pub chain: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
    pub manifests: Vec<Vec<u8>>,
    pub tal: Vec<u8>,
}

/// A refreshed snapshot of the parent publication path for an imported RC.
/// This does not replace the current CA certificate or private key.
#[derive(Clone, Debug)]
pub struct CaValidationContextUpdate {
    pub chain: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
    pub manifests: Vec<Vec<u8>>,
    pub tal: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CaCertificateStatus {
    pub not_before: i64,
    pub not_after: i64,
    pub seconds_remaining: i64,
    pub renewal_required: bool,
    pub expired: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToaReviewStatus {
    pub object_name: String,
    pub last_reviewed_at: i64,
    pub review_due_at: i64,
    pub overdue: bool,
    pub total_pairs: usize,
    pub roa_covered_pairs: usize,
    pub roa_overlap_justification: Option<String>,
    pub advisories: Vec<String>,
}

/// Audit result for withdrawing a currently published RPKI signed object.
#[derive(Clone, Debug, Serialize)]
pub struct ObjectWithdrawal {
    pub object_name: String,
    pub kind: ObjectKind,
    pub ee_certificate_serial: u64,
    pub ee_certificate_revoked: bool,
    pub revocation_time: Option<i64>,
    pub crl_number: u64,
    pub manifest_number: u64,
}
