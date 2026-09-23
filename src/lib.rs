pub mod api;
mod application;
mod ca;
mod constants;
mod domain;
mod infrastructure;
mod objects;
mod validation;

pub use application::{
    config::{CaConfig, IssuanceTimingConfig},
    manager::CaManager,
};
pub use ca::CertificateAuthority;
pub use domain::{
    model::{
        CaCertificateRenewal, CaCertificateStatus, CaImportRequest, CaIssuanceUnavailable,
        CaValidationContextUpdate, ObjectDefinition, ObjectDeltaResponse, ObjectKind,
        ObjectWithdrawal, SignedObjectIssuance, SignedObjectView, ToaReviewStatus,
    },
    resources::{CertifiedResources, CertifiedResourcesView, ResourceAuthorizationError},
};
pub use objects::{
    AspaDelta, AspaRequest, RoaConfiguration, RoaConfigurationView, RoaDelta, RoaDeltaError,
    RoaDeltaRejected, RoaDeltaResponse, RoaPayload, RoaRequest, SispiDelta, SispiRequest,
    ToaRequest,
};
pub use validation::{
    ValidationCheck, ValidationReport, ValidationStatus, verify_aspa_publication,
    verify_roa_publication, verify_sispi_publication, verify_toa_publication,
};

#[cfg(test)]
#[path = "../tests/unit/ca/authority_tests.rs"]
mod authority_tests;
