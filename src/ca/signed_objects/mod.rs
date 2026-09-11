//! RFC-specific signed-object encoders.

pub(crate) mod aspa;
pub(crate) mod roa;

use crate::infrastructure::signing::PreparedSoftwareSigner;
use rpki::{repository::x509::Validity, uri};

pub(crate) struct Params<'a> {
    pub name: &'a str,
    pub serial: u64,
    pub validity: Validity,
    pub repository_uri: &'a uri::Rsync,
    pub certificate_uri: &'a uri::Rsync,
    pub crl_uri: &'a uri::Rsync,
    pub signer: &'a PreparedSoftwareSigner<'a>,
}
