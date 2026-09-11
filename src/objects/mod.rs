//! Definitions and RFC-specific normalization for supported signed objects.

pub mod aspa;
pub mod roa;

pub use aspa::AspaRequest;
pub use roa::{RoaPayload, RoaRequest};
