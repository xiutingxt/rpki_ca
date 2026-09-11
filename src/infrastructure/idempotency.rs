use anyhow::{Context, Result};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

pub(crate) trait IdempotencyStore: Send + Sync {
    fn get(&self, id: &str) -> Result<Option<Vec<u8>>>;
    fn put_if_absent(&self, id: &str, value: &[u8]) -> Result<bool>;
    fn replace(&self, id: &str, value: &[u8]) -> Result<()>;
}

#[derive(Clone, Debug)]
pub(crate) struct LocalIdempotencyStore {
    directory: PathBuf,
}

impl LocalIdempotencyStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            directory: root.into().join("api-idempotency"),
        }
    }

    fn path(&self, id: &str) -> PathBuf {
        self.directory.join(format!("{id}.json"))
    }
}

impl IdempotencyStore for LocalIdempotencyStore {
    fn get(&self, id: &str) -> Result<Option<Vec<u8>>> {
        let path = self.path(id);
        if !path.exists() {
            return Ok(None);
        }
        fs::read(&path)
            .with_context(|| format!("cannot read idempotency record {}", path.display()))
            .map(Some)
    }

    fn put_if_absent(&self, id: &str, value: &[u8]) -> Result<bool> {
        fs::create_dir_all(&self.directory)?;
        let path = self.path(id);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                file.write_all(value)?;
                file.sync_all()?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn replace(&self, id: &str, value: &[u8]) -> Result<()> {
        let path = self.path(id);
        fs::write(&path, value)
            .with_context(|| format!("cannot update idempotency record {}", path.display()))
    }
}
