//! HTTP API adapter.

mod repository;
mod server;

pub(crate) use repository::decode;
pub use server::serve;
