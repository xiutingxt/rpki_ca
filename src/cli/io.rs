use anyhow::{Context, Result};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub(super) fn read_file(path: &std::path::Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("cannot read {}", path.display()))
}

pub(super) fn read_files(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
    paths.iter().map(|path| read_file(path)).collect()
}

pub(super) fn ensure_external_export(ca_root: &Path, output: &Path) -> Result<()> {
    let repository = fs::canonicalize(ca_root.join("repository"))
        .context("CA publication repository does not exist")?;
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let export_parent = fs::canonicalize(parent)
        .with_context(|| format!("cannot resolve export directory {}", parent.display()))?;
    if export_parent.starts_with(&repository) {
        anyhow::bail!(
            "--output is an external export path and must not be inside {}; the CA manages RFC 6481 repository filenames",
            repository.display()
        );
    }
    Ok(())
}
