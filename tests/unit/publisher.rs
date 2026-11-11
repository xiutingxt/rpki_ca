use super::*;
use rpki::ca::{
    idexchange::ServiceUri,
    publication::{
        ErrorReply, ListElement, PublishDeltaElement, Query, ReportError, ReportErrorCode,
    },
};
use rpki::rrdp::Hash;
use std::cell::{Cell, RefCell};

fn files(items: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
    items
        .iter()
        .map(|(name, bytes)| ((*name).into(), bytes.to_vec()))
        .collect()
}

#[test]
fn difference_plan_keeps_bytes_and_uses_old_hash_for_update_and_withdraw() {
    let base: uri::Rsync = "rsync://repo.example/repo/ca/".parse().unwrap();
    let remote = ListReply::new(vec![
        ListElement::new(base.join(b"same.roa").unwrap(), Hash::from_data(b"same")),
        ListElement::new(base.join(b"change.mft").unwrap(), Hash::from_data(b"old")),
        ListElement::new(base.join(b"gone.sav").unwrap(), Hash::from_data(b"gone")),
    ]);
    let local = files(&[
        ("same.roa", b"same"),
        ("change.mft", b"new"),
        ("new.toa", b"experimental"),
    ]);
    let (delta, report) = plan(&base, &local, remote).unwrap();
    assert_eq!(report.unchanged, 1);
    assert_eq!(report.update, ["change.mft"]);
    assert_eq!(report.publish, ["new.toa"]);
    assert_eq!(report.withdraw, ["gone.sav"]);
    for element in delta.into_elements() {
        match element {
            PublishDeltaElement::Update(update) => {
                assert_eq!(*update.hash(), Hash::from_data(b"old"));
                assert_eq!(update.content().to_bytes().as_ref(), b"new");
            }
            PublishDeltaElement::Publish(publish) => {
                assert_eq!(publish.content().to_bytes().as_ref(), b"experimental")
            }
            PublishDeltaElement::Withdraw(withdraw) => {
                assert_eq!(*withdraw.hash(), Hash::from_data(b"gone"))
            }
        }
    }
}

#[test]
fn refuses_remote_objects_outside_dedicated_flat_publication_point() {
    let base: uri::Rsync = "rsync://repo.example/repo/ca/".parse().unwrap();
    for uri in [
        "rsync://repo.example/repo/other/a.roa",
        "rsync://repo.example/repo/ca/child/a.roa",
        "rsync://repo.example/repo/ca2/a.roa",
    ] {
        assert!(
            plan(
                &base,
                &BTreeMap::new(),
                ListReply::new(vec![ListElement::new(
                    uri.parse().unwrap(),
                    Hash::from_data(b"x")
                )])
            )
            .is_err()
        );
    }
    let element = ListElement::new(base.join(b"a.roa").unwrap(), Hash::from_data(b"x"));
    assert!(
        plan(
            &base,
            &BTreeMap::new(),
            ListReply::new(vec![element.clone(), element])
        )
        .is_err()
    );
}

struct Server {
    signer: SoftwareSigner,
    publisher_key: rpki::crypto::PublicKey,
    objects: RefCell<BTreeMap<String, Vec<u8>>>,
    sends: Cell<usize>,
    lose_reply: Cell<bool>,
    reject: Cell<bool>,
}

impl Transport for Server {
    fn exchange(&self, bytes: Vec<u8>) -> Result<Vec<u8>> {
        let cms = PublicationCms::decode(&bytes).map_err(protocol_error)?;
        cms.validate(&self.publisher_key).map_err(protocol_error)?;
        let reply = match cms.into_message().as_query().map_err(protocol_error)? {
            Query::List => Message::list_reply(ListReply::new(
                self.objects
                    .borrow()
                    .iter()
                    .map(|(uri, bytes)| {
                        ListElement::new(uri.parse().unwrap(), Hash::from_data(bytes))
                    })
                    .collect(),
            )),
            Query::Delta(delta) => {
                self.sends.set(self.sends.get() + 1);
                if self.reject.get() {
                    Message::error(ErrorReply::for_error(ReportError::with_code(
                        ReportErrorCode::PermissionFailure,
                    )))
                } else {
                    let mut objects = self.objects.borrow_mut();
                    for element in delta.into_elements() {
                        match element {
                            PublishDeltaElement::Publish(p) => {
                                objects
                                    .insert(p.uri().to_string(), p.content().to_bytes().to_vec());
                            }
                            PublishDeltaElement::Update(p) => {
                                assert!(p.hash().matches(objects.get(p.uri().as_str()).unwrap()));
                                objects
                                    .insert(p.uri().to_string(), p.content().to_bytes().to_vec());
                            }
                            PublishDeltaElement::Withdraw(p) => {
                                assert!(p.hash().matches(objects.get(p.uri().as_str()).unwrap()));
                                objects.remove(p.uri().as_str());
                            }
                        }
                    }
                    if self.lose_reply.replace(false) {
                        bail!("simulated timeout after commit");
                    }
                    Message::success()
                }
            }
        };
        Ok(
            PublicationCms::create(reply, self.signer.primary_key_id(), &self.signer)
                .map_err(protocol_error)?
                .to_bytes()
                .to_vec(),
        )
    }
}

fn make_client() -> Client<Server> {
    let signer = SoftwareSigner::generate().unwrap().0;
    let server = SoftwareSigner::generate().unwrap().0;
    let cert = IdCert::new_ta(
        Validity::new(Time::five_minutes_ago(), Time::years_from_now(1)),
        server.primary_key_id(),
        &server,
    )
    .unwrap();
    Client {
        transport: Server {
            publisher_key: signer.public_key().unwrap(),
            signer: server,
            objects: RefCell::new(BTreeMap::new()),
            sends: Cell::new(0),
            lose_reply: Cell::new(false),
            reject: Cell::new(false),
        },
        signer,
        server: cert,
    }
}

#[test]
fn signed_exchange_reconciles_lost_reply_dry_run_idempotency_updates_and_withdrawals() {
    let client = make_client();
    let base = "rsync://repo.example/repo/ca/".parse().unwrap();
    let local = files(&[
        ("a.roa", b"roa"),
        ("b.toa", b"toa"),
        ("c.sav", b"sispi"),
        ("a.mft", b"manifest"),
    ]);
    let report = client.sync(&base, &local, true).unwrap();
    assert_eq!(report.status, "planned");
    assert_eq!(client.transport.sends.get(), 0);
    client.transport.lose_reply.set(true);
    assert!(client.sync(&base, &local, false).is_err());
    assert_eq!(client.transport.sends.get(), 1);
    let report = client.sync(&base, &local, false).unwrap();
    assert_eq!(report.unchanged, 4);
    assert_eq!(client.transport.sends.get(), 1);
    let changed = files(&[("a.roa", b"replacement"), ("a.mft", b"new manifest")]);
    let report = client.sync(&base, &changed, false).unwrap();
    assert_eq!(report.update.len(), 2);
    assert_eq!(report.withdraw, ["b.toa", "c.sav"]);
    assert_eq!(client.transport.objects.borrow().len(), 2);
    client.transport.reject.set(true);
    let error = client.sync(&base, &local, false).unwrap_err();
    assert!(error.to_string().contains("permission_failure"));
    // The response is validly signed, but by an untrusted identity.
    let other = make_client();
    let bad = Client {
        signer: client.signer,
        server: other.server,
        transport: client.transport,
    };
    assert!(
        bad.list()
            .unwrap_err()
            .to_string()
            .contains("signature invalid")
    );
}

#[test]
fn registration_round_trip_preserves_identity_and_never_overwrites_ca_configuration() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("publisher");
    init(&root, "my-ca").unwrap();
    assert!(init(&root, "my-ca").is_err());
    let request =
        PublisherRequest::parse(fs::read(root.join(REQUEST)).unwrap().as_slice()).unwrap();
    let identity = request.validate().unwrap();
    let signer = SoftwareSigner::from_pem(&fs::read_to_string(root.join(KEY)).unwrap()).unwrap();
    assert_eq!(identity.public_key(), &signer.public_key().unwrap());
    let response = RepositoryResponse::new(
        request.id_cert().clone(),
        "server-assigned".parse().unwrap(),
        "https://pub.example/rfc8181/server-assigned/"
            .parse::<ServiceUri>()
            .unwrap(),
        "rsync://repo.example/repo/server-assigned/"
            .parse()
            .unwrap(),
        Some(
            "https://repo.example/rrdp/notification.xml"
                .parse()
                .unwrap(),
        ),
        None,
    );
    let path = temp.path().join("response.xml");
    fs::write(&path, response.to_xml_vec()).unwrap();
    let config_path = temp.path().join("new-ca.toml");
    configure(&root, &path, Some(&config_path), false).unwrap();
    let config = CaConfig::from_file(&config_path).unwrap();
    assert_eq!(config.repository_uri, response.sia_base().as_str());
    assert_eq!(
        config.rrdp_notification_uri.as_deref(),
        Some("https://repo.example/rrdp/notification.xml")
    );
    let original = fs::read(&config_path).unwrap();
    assert!(configure(&root, &path, Some(&config_path), false).is_err());
    assert_eq!(fs::read(&config_path).unwrap(), original);
    let http_xml = response
        .to_xml_string()
        .replace("https://pub.example", "http://pub.example");
    assert!(response_from(http_xml.as_bytes(), false).is_err());
    assert!(response_from(http_xml.as_bytes(), true).is_ok());
    fs::write(&path, http_xml).unwrap();
    assert!(configure(&root, &path, None, true).is_err());
}

#[test]
fn snapshot_advertises_rrdp_rejects_uri_mismatch_pending_and_tampering_without_ca_key() {
    let temp = tempfile::tempdir().unwrap();
    let ca_dir = temp.path().join("ca");
    let client = make_client();
    let response = RepositoryResponse::new(
        Base64::from_content(&client.server.to_bytes()),
        "ca".parse().unwrap(),
        "https://pub.example/rfc8181/ca/".parse().unwrap(),
        "rsync://repo.example/repo/ca/".parse().unwrap(),
        Some(
            "https://repo.example/rrdp/notification.xml"
                .parse()
                .unwrap(),
        ),
        None,
    );
    let config = CaConfig {
        repository_uri: response.sia_base().to_string(),
        rrdp_notification_uri: response.rrdp_notification_uri().map(ToString::to_string),
        ..CaConfig::default()
    };
    let manager = crate::CaManager::init(&ca_dir, config).unwrap();
    manager
        .sign_aspa(
            &crate::AspaRequest {
                customer_asn: 64496,
                provider_asns: vec![64497],
            },
            "test.asa",
        )
        .unwrap_err(); // No ASN resource in default CA.
    fs::remove_file(ca_dir.join("ca.key")).unwrap();
    let PublicationSnapshot {
        base,
        rrdp_advertised,
        files,
        ..
    } = snapshot(&ca_dir, &response).unwrap();
    assert!(rrdp_advertised);
    assert_eq!(files.len(), 3);
    // A publisher's authorization covers its SIA base and child publication points.
    let parent_xml = response.to_xml_string().replace(
        "sia_base=\"rsync://repo.example/repo/ca/\"",
        "sia_base=\"rsync://repo.example/repo/\"",
    );
    let parent = response_from(parent_xml.as_bytes(), false).unwrap();
    assert_eq!(snapshot(&ca_dir, &parent).unwrap().files, files);

    // Extra files used to pass Manifest validation and get uploaded anyway.
    let extra_path = ca_dir.join("repository/unlisted.sav");
    fs::write(&extra_path, b"not a manifest member").unwrap();
    assert!(
        snapshot(&ca_dir, &response)
            .unwrap_err()
            .to_string()
            .contains("not listed")
    );
    fs::remove_file(extra_path).unwrap();

    // An edited TAL URI must never silently cause the TA certificate to be omitted.
    let config_path = ca_dir.join("ca.toml");
    let original_config = fs::read_to_string(&config_path).unwrap();
    let mut edited_config = CaConfig::from_file(&config_path).unwrap();
    let ca_name = files.keys().find(|name| name.ends_with(".cer")).unwrap();
    edited_config.certificate_uri = format!("rsync://other.example/repo/{ca_name}");
    fs::write(
        &config_path,
        toml::to_string_pretty(&edited_config).unwrap(),
    )
    .unwrap();
    assert!(
        snapshot(&ca_dir, &response)
            .unwrap_err()
            .to_string()
            .contains("trust anchor certificate_uri")
    );
    edited_config.certificate_uri = "rsync://repo.example/repo/ca/wrong.cer".into();
    fs::write(
        &config_path,
        toml::to_string_pretty(&edited_config).unwrap(),
    )
    .unwrap();
    assert!(
        snapshot(&ca_dir, &response)
            .unwrap_err()
            .to_string()
            .contains("certificate filename")
    );
    fs::write(config_path, original_config).unwrap();
    let mismatch_xml = response.to_xml_string().replace("repo/ca/", "repo/other/");
    let mismatch = response_from(mismatch_xml.as_bytes(), false).unwrap();
    assert!(snapshot(&ca_dir, &mismatch).is_err());
    let store = LocalStateStore::new(&ca_dir);
    let mut state = store.load().unwrap();
    state
        .stage_publication(crate::infrastructure::repository::PublicationUpdate::default())
        .unwrap();
    store.save(&state).unwrap();
    assert!(
        snapshot(&ca_dir, &response)
            .unwrap_err()
            .to_string()
            .contains("pending")
    );
    state.complete_publication();
    store.save(&state).unwrap();
    let crl = files.keys().find(|name| name.ends_with(".crl")).unwrap();
    fs::write(ca_dir.join("repository").join(crl), b"broken").unwrap();
    assert!(snapshot(&ca_dir, &response).is_err());
    assert_eq!(base, *response.sia_base());
}
