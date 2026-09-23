use super::*;

#[test]
fn failed_creation_leaves_no_partial_ca() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("ca");
    let result = create_transaction(&root, |staging| {
        fs::write(staging.join(CONFIG_FILE), b"partial configuration")?;
        fs::write(staging.join(KEY_FILE), b"partial private key")?;
        anyhow::bail!("simulated validation failure")
    });

    assert!(result.is_err());
    assert!(!root.exists());
    assert!(fs::read_dir(parent.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".rpki-ca-create-")
    }));
}

#[test]
fn successful_creation_commits_complete_directory() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("ca");
    create_transaction(&root, |staging| {
        fs::write(staging.join(CONFIG_FILE), b"complete configuration")?;
        fs::write(staging.join(KEY_FILE), b"complete private key")?;
        Ok(())
    })
    .unwrap();

    assert_eq!(
        fs::read(root.join(CONFIG_FILE)).unwrap(),
        b"complete configuration"
    );
    assert_eq!(
        fs::read(root.join(KEY_FILE)).unwrap(),
        b"complete private key"
    );
}
