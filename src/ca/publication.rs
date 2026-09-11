//! RFC 6481 repository object naming.

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rpki::crypto::{KeyIdentifier, PublicKey};

/// RFC 6481's recommended basename: the 160-bit public-key identifier encoded
/// with the URL- and filename-safe Base64 alphabet, without padding.
pub(crate) fn key_basename(key: &PublicKey) -> String {
    key_identifier_basename(&key.key_identifier())
}

pub(crate) fn key_identifier_basename(key: &KeyIdentifier) -> String {
    URL_SAFE_NO_PAD.encode(key.as_ref())
}

pub(crate) fn key_filename(key: &KeyIdentifier, extension: &str) -> String {
    format!("{}.{}", key_identifier_basename(key), extension)
}

pub(crate) fn uri_filename(uri: &str) -> Result<String> {
    uri.rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .context("object URI has no filename")
}

#[cfg(test)]
#[path = "../../tests/unit/ca/publication.rs"]
mod tests;
