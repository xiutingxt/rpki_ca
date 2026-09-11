use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

const STAGE_DIR: &str = ".publication-stage";
const BACKUP_DIR: &str = ".repository-backup";

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PublicationUpdate {
    pub publish: BTreeMap<String, Vec<u8>>,
    pub withdraw: BTreeSet<String>,
}

pub trait PublicationRepository: Send + Sync {
    fn initialize(&self) -> Result<()>;
    fn list(&self) -> Result<Vec<String>>;
    fn read(&self, name: &str) -> Result<Vec<u8>>;
    fn publish(&self, update: PublicationUpdate) -> Result<()>;
    fn recover(&self) -> Result<()>;
}

#[derive(Clone, Debug)]
pub struct LocalRepository {
    root: PathBuf,
}

impl LocalRepository {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn path(&self) -> PathBuf {
        self.root.join("repository")
    }

    fn stage_path(&self) -> PathBuf {
        self.root.join(STAGE_DIR)
    }

    fn backup_path(&self) -> PathBuf {
        self.root.join(BACKUP_DIR)
    }

    fn copy_current_to_stage(&self, stage: &Path, update: &PublicationUpdate) -> Result<()> {
        for entry in fs::read_dir(self.path())? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name();
            let name_str = name.to_str().context("repository filename is not UTF-8")?;
            if !update.publish.contains_key(name_str) && !update.withdraw.contains(name_str) {
                fs::copy(entry.path(), stage.join(name))?;
            }
        }
        Ok(())
    }
}

impl PublicationRepository for LocalRepository {
    fn initialize(&self) -> Result<()> {
        fs::create_dir_all(self.path()).context("cannot initialize local publication repository")
    }

    fn list(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in fs::read_dir(self.path())? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                names.push(
                    entry
                        .file_name()
                        .to_str()
                        .context("repository filename is not UTF-8")?
                        .to_owned(),
                );
            }
        }
        Ok(names)
    }

    fn read(&self, name: &str) -> Result<Vec<u8>> {
        fs::read(self.path().join(name))
            .with_context(|| format!("cannot read repository object {name}"))
    }

    fn publish(&self, update: PublicationUpdate) -> Result<()> {
        let repository = self.path();
        let stage = self.stage_path();
        let backup = self.backup_path();
        if stage.exists() {
            fs::remove_dir_all(&stage)?;
        }
        if backup.exists() {
            fs::remove_dir_all(&backup)?;
        }
        fs::create_dir(&stage)?;
        self.copy_current_to_stage(&stage, &update)?;
        for (name, data) in update.publish {
            fs::write(stage.join(name), data)?;
        }

        fs::rename(&repository, &backup)?;
        if let Err(err) = fs::rename(&stage, &repository) {
            let _ = fs::rename(&backup, &repository);
            return Err(err.into());
        }
        fs::remove_dir_all(backup)?;
        sync_directory(&self.root)?;
        Ok(())
    }

    fn recover(&self) -> Result<()> {
        let repository = self.path();
        let backup = self.backup_path();
        if !repository.exists() && backup.exists() {
            fs::rename(&backup, &repository).context("cannot recover repository backup")?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_: &Path) -> Result<()> {
    Ok(())
}
