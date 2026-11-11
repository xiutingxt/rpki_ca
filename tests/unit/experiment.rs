use super::*;
use crate::ca::signed_objects::{sispi::object::Sispi, toa::object::Toa};
use crate::{AspaRequest, RoaPayload, RoaRequest, SispiRequest, ToaRequest};
use rpki::repository::tal::TalInfo;

fn request() -> ExperimentRequest {
    serde_json::from_str(include_str!("../../examples/experiment.json")).unwrap()
}

fn save_bundle(dir: &Path, bundle: &Bundle) {
    fs::write(
        dir.join("experiment.json"),
        serde_json::to_vec_pretty(bundle).unwrap(),
    )
    .unwrap();
}

#[test]
fn portable_bundle_checks_trust_payload_inventory_and_tampering() {
    let temporary = tempfile::tempdir().unwrap();
    let output = temporary.path().join("bundle");
    let mut input = request();
    input.ca.name = "custom-experiment".into();
    input.ca.repository_uri = "rsync://example.test/custom/".into();
    input.objects.extend([
        ObjectDefinition::Roa(RoaRequest {
            asn: 64498,
            prefixes: vec![RoaPayload {
                prefix: "192.0.2.0/24".parse().unwrap(),
                max_length: Some(26),
            }],
        }),
        ObjectDefinition::Aspa(AspaRequest {
            customer_asn: 64496,
            provider_asns: vec![64497],
        }),
    ]);
    assert_eq!(create(&input, &output).unwrap().objects.len(), 4);
    assert!(!output.join("ca.key").exists());
    assert!(!output.join("state.toml").exists());
    let top: BTreeSet<_> = fs::read_dir(&output)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        top,
        BTreeSet::from([
            "repository".into(),
            "experiment.json".into(),
            "trust-anchor.tal".into(),
            "verification.json".into()
        ])
    );
    assert!(
        create(&input, &output)
            .unwrap_err()
            .to_string()
            .contains("already exists")
    );
    let moved = temporary.path().join("moved");
    fs::rename(&output, &moved).unwrap();
    assert_eq!(
        verify(&moved, Some(&moved.join("trust-anchor.tal")))
            .unwrap()
            .status,
        "valid"
    );
    let original: Bundle =
        serde_json::from_slice(&fs::read(moved.join("experiment.json")).unwrap()).unwrap();
    assert_eq!(original.request.as_ref().unwrap().valid_days, 30);
    assert_eq!(
        original.request.as_ref().unwrap().ca.name,
        "custom-experiment"
    );
    assert!(
        original
            .files
            .values()
            .all(|f| f.uri.starts_with("rsync://example.test/custom/"))
    );
    assert!(
        fs::read_to_string(moved.join("trust-anchor.tal"))
            .unwrap()
            .starts_with("rsync://example.test/custom/")
    );
    assert_eq!(original.format_version, 4);
    assert_eq!(original.profiles.len(), 4);
    assert!(original.profiles["aspa"].contains("profile-29"));
    let ca_metadata = original.ca_metadata.as_ref().unwrap();
    assert_eq!(ca_metadata.configuration["name"], "custom-experiment");
    assert_eq!(
        ca_metadata.configuration["timing"]["publish_next_hours"],
        720
    );
    assert_eq!(
        ca_metadata.certificate["repository_uri"],
        "rsync://example.test/custom/"
    );
    assert!(
        ca_metadata.certificate["not_after_utc"]
            .as_str()
            .unwrap()
            .ends_with('Z')
    );
    assert!(original.parent_materials.is_empty());
    assert_eq!(original.files.len(), original.repository_sha256.len());
    let mut legacy = original.clone();
    legacy.format_version = 1;
    legacy.ca_metadata = None;
    legacy.parent_materials.clear();
    legacy.files.clear();
    save_bundle(&moved, &legacy);
    assert!(verify(&moved, None).is_ok());
    legacy.format_version = 2;
    legacy.files = original.files.clone();
    for file in legacy.files.values_mut() {
        file.decoded = None;
    }
    save_bundle(&moved, &legacy);
    assert!(verify(&moved, None).is_ok());
    let mut version_three = original.clone();
    version_three.format_version = 3;
    for file in version_three.files.values_mut() {
        file.decoded = None;
    }
    save_bundle(&moved, &version_three);
    assert!(verify(&moved, None).is_ok());
    for (name, file) in &original.files {
        let bytes = fs::read(moved.join("repository").join(name)).unwrap();
        assert_eq!(
            file.decoded.as_ref().unwrap(),
            &crate::api::decode(name, &bytes).unwrap()
        );
        let decoded = file.decoded.as_ref().unwrap();
        match name.rsplit_once('.').unwrap().1 {
            "roa" => assert_eq!(decoded["eContent"]["asID"], 64498),
            "asa" => assert_eq!(decoded["eContent"]["customerASID"], 64496),
            "toa" => assert_eq!(
                decoded["eContent"]["asSet"],
                serde_json::json!([64496, 64497])
            ),
            "sav" => assert_eq!(decoded["eContent"]["asn"], 64496),
            _ => {}
        }
    }
    for replacement in [None, Some(serde_json::json!({"eContent": "fake"}))] {
        let mut altered = original.clone();
        altered.files.values_mut().next().unwrap().decoded = replacement;
        save_bundle(&moved, &altered);
        let (valid, report) = verification_report(&moved, None);
        assert!(!valid);
        assert_eq!(report["error"]["code"], "metadata");
    }
    for change in 0..4 {
        let mut altered = original.clone();
        match change {
            0 => altered.ca_metadata = None,
            1 => altered.ca_metadata.as_mut().unwrap().certificate["subject"] = "fake".into(),
            2 => altered.profiles.clear(),
            _ => altered.ca_metadata.as_mut().unwrap().configuration["name"] = "fake".into(),
        }
        save_bundle(&moved, &altered);
        let (valid, report) = verification_report(&moved, None);
        assert!(!valid);
        assert_eq!(report["error"]["code"], "metadata");
    }
    let mut wrong_metadata = original.clone();
    wrong_metadata.files.values_mut().next().unwrap().size += 1;
    save_bundle(&moved, &wrong_metadata);
    let (valid, failure) = verification_report(&moved, None);
    assert!(!valid);
    assert_eq!(failure["error"]["code"], "metadata");
    save_bundle(&moved, &original);
    let manifest_name = original
        .repository_sha256
        .keys()
        .find(|n| n.ends_with(".mft"))
        .unwrap();
    let manifest = Manifest::decode(
        fs::read(moved.join("repository").join(manifest_name))
            .unwrap()
            .as_slice(),
        true,
    )
    .unwrap();
    let content = manifest.content();
    assert_eq!(
        content.next_update().timestamp() - content.this_update().timestamp(),
        30 * 86400
    );
    let crl_name = original
        .repository_sha256
        .keys()
        .find(|n| n.ends_with(".crl"))
        .unwrap();
    let crl = rpki::repository::crl::Crl::decode(
        fs::read(moved.join("repository").join(crl_name))
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    assert_eq!(crl.next_update(), content.next_update());
    assert_eq!(
        manifest.cert().validity().not_after(),
        content.next_update()
    );
    let name = original
        .objects
        .keys()
        .find(|n| n.ends_with(".sav"))
        .unwrap();
    let path = moved.join("repository").join(name);
    let bytes = fs::read(&path).unwrap();

    let mut corrupt = bytes.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    fs::write(&path, &corrupt).unwrap();
    assert!(
        verify(&moved, None)
            .unwrap_err()
            .to_string()
            .contains("SHA-256 mismatch")
    );
    // Updating the unsigned inventory hash cannot bypass the signed Manifest.
    let mut altered = original.clone();
    altered
        .repository_sha256
        .insert(name.clone(), digest(&corrupt));
    save_bundle(&moved, &altered);
    assert!(format!("{:#}", verify(&moved, None).unwrap_err()).contains("Manifest hash mismatch"));
    fs::write(&path, &bytes).unwrap();

    // Changing both recorded input and inventory still fails actual payload checks.
    altered = original.clone();
    for definition in altered
        .request
        .as_mut()
        .unwrap()
        .objects
        .iter_mut()
        .chain(altered.objects.values_mut())
    {
        if let ObjectDefinition::Sispi(value) = definition {
            value.addresses = vec!["192.0.2.99".parse().unwrap()];
        }
    }
    save_bundle(&moved, &altered);
    assert!(format!("{:#}", verify(&moved, None).unwrap_err()).contains("SiSPI address mismatch"));
    save_bundle(&moved, &original);

    let wrong_tal = temporary.path().join("wrong.tal");
    let ee = Sispi::decode(bytes.clone().into()).unwrap();
    fs::write(
        &wrong_tal,
        format!(
            "rsync://localhost/rpki/wrong.cer\n\n{}\n",
            STANDARD.encode(ee.cert().subject_public_key_info().to_info_bytes())
        ),
    )
    .unwrap();
    let error = format!("{:#}", verify(&moved, Some(&wrong_tal)).unwrap_err());
    assert!(error.contains("does not match the TAL"), "{error}");
    fs::write(moved.join("repository/extra.toa"), [0]).unwrap();
    assert!(
        verify(&moved, None)
            .unwrap_err()
            .to_string()
            .contains("inventory mismatch")
    );
    fs::remove_file(moved.join("repository/extra.toa")).unwrap();
    fs::remove_file(&path).unwrap();
    assert!(verify(&moved, None).is_err());
    fs::write(&path, &bytes).unwrap();
    assert_eq!(verify(&moved, None).unwrap().status, "valid");
}

#[test]
fn experimental_profiles_reject_bad_signatures_oids_and_resource_overclaims() {
    let temporary = tempfile::tempdir().unwrap();
    let ca = CaManager::init(
        temporary.path().join("ca"),
        CaConfig {
            development_asns: vec![64496],
            ..CaConfig::default()
        },
    )
    .unwrap();
    let cert_name = ca
        .list_published_objects()
        .unwrap()
        .into_iter()
        .find(|n| n.ends_with(".cer"))
        .unwrap();
    let issuer = Cert::decode(ca.read_published_object(&cert_name).unwrap().as_slice())
        .unwrap()
        .validate_ta(TalInfo::from_name("test".into()).into_arc(), true)
        .unwrap();
    let input = request();
    for definition in input.objects {
        let kind = definition.kind();
        let signed = ca
            .issue_object(definition, &format!("test.{}", kind.extension()))
            .unwrap();
        let mut corrupt = signed.bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let oid = match kind {
            ObjectKind::Toa => {
                Toa::decode(signed.bytes.clone().into())
                    .unwrap()
                    .process(&issuer, |_| Ok(()))
                    .unwrap();
                assert!(
                    Toa::decode(corrupt.into())
                        .unwrap()
                        .process(&issuer, |_| Ok(()))
                        .is_err()
                );
                crate::constants::TOA_CONTENT_TYPE_OID_BYTES
            }
            ObjectKind::Sispi => {
                Sispi::decode(signed.bytes.clone().into())
                    .unwrap()
                    .process(&issuer, |_| Ok(()))
                    .unwrap();
                assert!(
                    Sispi::decode(corrupt.into())
                        .unwrap()
                        .process(&issuer, |_| Ok(()))
                        .is_err()
                );
                crate::constants::SISPI_CONTENT_TYPE_OID_BYTES
            }
            _ => unreachable!(),
        };
        let mut wrong_oid = signed.bytes;
        let index = wrong_oid.windows(oid.len()).position(|v| v == oid).unwrap();
        wrong_oid[index + oid.len() - 1] ^= 1;
        match kind {
            ObjectKind::Toa => assert!(Toa::decode(wrong_oid.into()).is_err()),
            ObjectKind::Sispi => assert!(Sispi::decode(wrong_oid.into()).is_err()),
            _ => unreachable!(),
        }
    }
    let before: BTreeMap<_, _> = ca
        .list_published_objects()
        .unwrap()
        .into_iter()
        .map(|name| {
            let bytes = ca.read_published_object(&name).unwrap();
            (name, bytes)
        })
        .collect();
    assert!(
        ca.sign_toa(
            &ToaRequest {
                asns: vec![64496],
                prefixes: vec!["198.51.100.0/24".parse().unwrap()],
                roa_overlap_justification: None
            },
            "overclaim.toa"
        )
        .is_err()
    );
    assert!(
        ca.sign_sispi(
            &SispiRequest {
                asn: 64497,
                addresses: vec!["192.0.2.1".parse().unwrap()]
            },
            "overclaim.sav"
        )
        .is_err()
    );
    for (name, bytes) in before {
        assert_eq!(ca.read_published_object(&name).unwrap(), bytes);
    }
}

#[test]
fn snapshot_is_public_read_only_and_does_not_need_a_private_key() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("ca");
    let ca = CaManager::init(&source, experiment_config(&request()).unwrap()).unwrap();
    let definition = request().objects.remove(0);
    ca.issue_object(definition, "snapshot.toa").unwrap();
    drop(ca);
    let state_before = fs::read(source.join("state.toml")).unwrap();
    let config_before = fs::read(source.join("ca.toml")).unwrap();
    fs::rename(source.join("ca.key"), source.join("hidden.key")).unwrap();
    let info = crate::ca_info(&source).unwrap();
    assert_eq!(info["configured"]["name"], "offline-experiment");
    assert_ne!(info["certificate"]["subject"], "offline-experiment");
    assert_eq!(
        info["certificate"]["repository_uri"],
        "rsync://localhost/rpki/"
    );
    assert!(info["warnings"].as_array().unwrap().is_empty());
    assert!(export(&source, &source.join("nested")).is_err());
    let output = temporary.path().join("export");
    let (valid, report) = export(&source, &output).unwrap();
    assert!(valid, "{report}");
    assert!(!output.join("ca.key").exists());
    assert!(!output.join("hidden.key").exists());
    assert_eq!(state_before, fs::read(source.join("state.toml")).unwrap());
    assert_eq!(config_before, fs::read(source.join("ca.toml")).unwrap());
    for name in LocalRepository::new(&source).list().unwrap() {
        assert_eq!(
            fs::read(source.join("repository").join(&name)).unwrap(),
            fs::read(output.join("repository").join(name)).unwrap()
        );
    }
    assert!(export(&source, &output).is_err());
    let mut changed: CaConfig =
        toml::from_str(std::str::from_utf8(&config_before).unwrap()).unwrap();
    changed.repository_uri = "rsync://example.test/changed/".into();
    changed.development_asns = vec![64500];
    fs::write(source.join("ca.toml"), toml::to_string(&changed).unwrap()).unwrap();
    let info = crate::ca_info(&source).unwrap();
    assert!(
        info["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().contains("repository_uri"))
    );
    assert!(
        info["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().contains("certified resources"))
    );
    assert_eq!(
        info["certificate"]["repository_uri"],
        "rsync://localhost/rpki/"
    );
    fs::write(source.join("ca.toml"), &config_before).unwrap();
    let bundle: Bundle =
        serde_json::from_slice(&fs::read(output.join("experiment.json")).unwrap()).unwrap();
    assert!(bundle.request.is_none());
    assert_eq!(bundle.source, "existing_ca_snapshot");
    assert_eq!(bundle.profiles.len(), 1);
    assert!(bundle.profiles["toa"].contains("toa-02"));
    assert_eq!(
        bundle.ca_metadata.as_ref().unwrap().configuration["name"],
        "offline-experiment"
    );
    let name = bundle.objects.keys().next().unwrap();
    fs::write(output.join("repository").join(name), b"tampered").unwrap();
    let (valid, failure) = verification_report(&output, None);
    assert!(!valid);
    assert_eq!(failure["error"]["code"], "sha256");
    assert_eq!(failure["error"]["object"], *name);
    let store = LocalStateStore::new(&source);
    let mut state = store.load().unwrap();
    state.stage_publication(Default::default()).unwrap();
    store.save(&state).unwrap();
    let pending_before = fs::read(source.join("state.toml")).unwrap();
    let pending_info = crate::ca_info(&source).unwrap();
    assert!(
        pending_info["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().contains("transaction pending"))
    );
    let rejected = temporary.path().join("pending-export");
    assert!(
        export(&source, &rejected)
            .unwrap_err()
            .to_string()
            .contains("pending")
    );
    assert!(!rejected.exists());
    assert_eq!(pending_before, fs::read(source.join("state.toml")).unwrap());
}

#[test]
fn invalid_requests_do_not_create_a_bundle() {
    let temporary = tempfile::tempdir().unwrap();
    let output = temporary.path().join("bundle");
    let mut input = request();
    input.objects.push(input.objects[0].clone());
    assert!(
        create(&input, &output)
            .unwrap_err()
            .to_string()
            .contains("duplicate")
    );
    input.objects.clear();
    assert!(create(&input, &output).is_err());
    assert!(!output.exists());
}

#[test]
fn experiment_validity_is_configurable_and_isolated() {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("../../examples/experiment.json")).unwrap();
    value.as_object_mut().unwrap().remove("valid_days");
    let mut input: ExperimentRequest = serde_json::from_value(value).unwrap();
    assert_eq!(input.valid_days, 30);
    for days in [1, 30, 60, 363] {
        input.valid_days = days;
        let config = experiment_config(&input).unwrap();
        assert_eq!(config.timing.publish_next_hours, days * 24);
        assert_eq!(config.timing.publish_next_jitter_hours, 0);
    }
    let temporary = tempfile::tempdir().unwrap();
    let output = temporary.path().join("invalid");
    for days in [0, 364, u32::MAX] {
        input.valid_days = days;
        assert!(
            create(&input, &output)
                .unwrap_err()
                .to_string()
                .contains("valid_days")
        );
        assert!(!output.exists());
    }
    assert_eq!(CaConfig::default().timing.publish_next_hours, 24);
    assert_eq!(CaConfig::default().timing.publish_next_jitter_hours, 4);
    input.valid_days = 30;
    input.ca.toa_valid_weeks = 4;
    assert!(experiment_config(&input).is_err());
    input.ca.toa_valid_weeks = 8;
    assert_eq!(experiment_config(&input).unwrap().timing.toa_valid_weeks, 8);
}
