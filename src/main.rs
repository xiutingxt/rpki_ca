pub mod api;
mod application;
mod ca;
mod constants;
mod domain;
pub mod experiment;
mod infrastructure;
mod objects;
mod publisher;
mod validation;

pub use application::{
    config::{CaConfig, IssuanceTimingConfig},
    info::ca_info,
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
    RoaDeltaRejected, RoaDeltaResponse, RoaPayload, RoaRequest, SispiDelta, SispiRequest, ToaDelta,
    ToaRequest,
};
pub use validation::{
    ValidationCheck, ValidationReport, ValidationStatus, verify_aspa_publication,
    verify_roa_publication, verify_sispi_publication, verify_toa_publication,
};

#[cfg(test)]
#[path = "../tests/unit/ca/authority_tests.rs"]
mod authority_tests;

mod cli;

fn main() {
    if let Err(error) = cli::run() {
        eprintln!("rpki-ca: {error:#}");
        std::process::exit(1);
    }
}
