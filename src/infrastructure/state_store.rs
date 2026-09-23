use crate::ca::state::{CaState, CaStateStore, StateGuard};
use anyhow::{Context, Result, bail};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

/// File-system adapter for durable CA state and its process lock.
#[derive(Clone, Debug)]
pub(crate) struct LocalStateStore {
    root: PathBuf,
}

impl LocalStateStore {
    pub(crate) fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn state_path(&self) -> PathBuf {
        self.root.join("state.toml")
    }
}

struct LocalStateGuard {
    _file: File,
}

impl StateGuard for LocalStateGuard {}

impl CaStateStore for LocalStateStore {
    fn initialize(&self, state: &CaState) -> Result<()> {
        if self.state_path().exists() {
            bail!("CA state already exists");
        }
        self.save(state)
    }

    fn load(&self) -> Result<CaState> {
        load_state(&self.state_path())
    }

    fn save(&self, state: &CaState) -> Result<()> {
        save_state(state, &self.state_path())
    }

    fn lock(&self) -> Result<Box<dyn StateGuard>> {
        let path = self.root.join("state.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .context("cannot open CA state lock")?;
        // Concurrent API reads and writes must be serialized rather than
        // failing nondeterministically. In particular, the web UI loads
        // several state-backed views in parallel when a page opens.
        file.lock().context("cannot lock CA state")?;
        Ok(Box::new(LocalStateGuard { _file: file }))
    }
}

fn load_state(path: &Path) -> Result<CaState> {
    let backup = path.with_extension("toml.bak");
    if !path.exists() && backup.exists() {
        fs::rename(&backup, path).context("cannot recover CA state backup")?;
    }
    let data =
        fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let mut state: CaState = toml::from_str(&data).context("invalid CA state")?;
    state.normalize_object_inventory();
    Ok(state)
}

/// Persists state using a same-directory temporary and a durable replace.
fn save_state(state: &CaState, path: &Path) -> Result<()> {
    let data = toml::to_string_pretty(state)?;
    let temporary = path.with_extension("toml.new");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(data.as_bytes())?;
    file.sync_all()?;
    drop(file);

    let backup = path.with_extension("toml.bak");
    if backup.exists() {
        fs::remove_file(&backup)?;
    }
    if path.exists() {
        fs::rename(path, &backup)?;
    }
    if let Err(err) = fs::rename(&temporary, path) {
        if backup.exists() {
            let _ = fs::rename(&backup, path);
        }
        return Err(err.into());
    }
    if backup.exists() {
        fs::remove_file(backup)?;
    }
    sync_parent(path)?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<()> {
    File::open(path.parent().context("state path has no parent")?)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/infrastructure/state_store.rs"]
mod tests;
