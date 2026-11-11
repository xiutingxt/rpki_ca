//! Explicit RFC 8181 synchronization of a committed local publication set.
//! The CA remains file-backed; no signing operation depends on this service.

use crate::CaConfig;
use crate::ca::state::CaStateStore;
use crate::infrastructure::{
    repository::LocalRepository,
    signing::{SigningProvider, SoftwareSigner},
    state_store::LocalStateStore,
};
use crate::validation::publication_set::PublicationSet;
use anyhow::{Context, Result, bail, ensure};
use rpki::{
    ca::{
        idcert::IdCert,
        idexchange::{PublisherHandle, PublisherRequest, RepositoryResponse},
        publication::{
            self, Base64, ListReply, Message, PublicationCms, Publish, PublishDelta, Reply, Update,
            Withdraw,
        },
    },
    repository::x509::{Time, Validity},
    uri,
};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::Duration,
};

const KEY: &str = "publisher.key";
const REQUEST: &str = "publisher-request.xml";
const RESPONSE: &str = "repository-response.xml";
const MAX_RESPONSE: u64 = 128 * 1024 * 1024;

fn protocol_error(error: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("{error}")
}

fn lock(root: &Path) -> Result<File> {
    ensure!(
        root.join(REQUEST).is_file(),
        "publisher not initialized; run publisher init first"
    );
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.join("publisher.lock"))?;
    file.lock().context("cannot lock publisher")?;
    Ok(file)
}

/// Create a separate identity, without touching or loading the CA signing key.
pub(crate) fn init(root: &Path, handle: &str) -> Result<()> {
    let handle: PublisherHandle = handle.parse().context("invalid publisher handle")?;
    ensure!(!root.exists(), "publisher directory already exists");
    let parent = root
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".publisher-")
        .tempdir_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))?;
    }
    let (signer, pem) = SoftwareSigner::generate().map_err(protocol_error)?;
    let cert = IdCert::new_ta(
        Validity::new(Time::five_minutes_ago(), Time::years_from_now(10)),
        signer.primary_key_id(),
        &signer,
    )
    .map_err(protocol_error)?;
    let request = PublisherRequest::new(Base64::from_content(&cert.to_bytes()), handle, None);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(staging.path().join(KEY))?;
    file.write_all(pem.as_bytes())?;
    file.sync_all()?;
    drop(file);
    let mut request_file = File::create(staging.path().join(REQUEST))?;
    request_file.write_all(&request.to_xml_vec())?;
    request_file.sync_all()?;
    drop(request_file);
    #[cfg(unix)]
    File::open(staging.path())?.sync_all()?;
    // The target must be new, so an existing identity can never be overwritten.
    fs::rename(staging.path(), root).context("cannot commit publisher identity")?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn response_from(bytes: &[u8], allow_http: bool) -> Result<RepositoryResponse> {
    let response = RepositoryResponse::parse(bytes).map_err(protocol_error)?;
    response.validate().map_err(protocol_error)?;
    let endpoint = reqwest::Url::parse(response.service_uri().as_str())?;
    ensure!(
        endpoint.host_str().is_some()
            && endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.fragment().is_none(),
        "invalid publication service URI"
    );
    ensure!(
        endpoint.scheme() == "https" || (allow_http && endpoint.scheme() == "http"),
        "publication service requires HTTPS; --allow-http is only for isolated experiments"
    );
    ensure!(
        response.sia_base().path_is_dir(),
        "sia_base must end with /"
    );
    Ok(response)
}

fn atomic_write(root: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut temporary = tempfile::NamedTempFile::new_in(root)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(root.join(name)).map_err(|e| e.error)?;
    #[cfg(unix)]
    File::open(root)?.sync_all()?;
    Ok(())
}

/// Store the trust received out of band. This does not rewrite an existing CA.
pub(crate) fn configure(
    root: &Path,
    response_path: &Path,
    ca_config_output: Option<&Path>,
    allow_http: bool,
) -> Result<serde_json::Value> {
    let _guard = lock(root)?;
    let response = response_from(&fs::read(response_path)?, allow_http)?;
    if root.join(RESPONSE).exists() {
        let old = response_from(&fs::read(root.join(RESPONSE))?, allow_http)?;
        ensure!(
            old == response,
            "publisher already configured differently; repository migration requires a new publisher directory"
        );
    }
    let config = CaConfig {
        repository_uri: response.sia_base().to_string(),
        rrdp_notification_uri: response.rrdp_notification_uri().map(ToString::to_string),
        ..CaConfig::default()
    };
    if let Some(path) = ca_config_output {
        // Never silently edit a live CA's configuration or an operator's file.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .context("CA config output must be a new file")?;
        file.write_all(toml::to_string_pretty(&config)?.as_bytes())?;
        file.sync_all()?;
    }
    atomic_write(root, RESPONSE, &response.to_xml_vec())?;
    Ok(
        serde_json::json!({"status": "configured", "publisher_handle": response.publisher_handle().as_str(), "repository_uri": config.repository_uri, "rrdp_notification_uri": config.rrdp_notification_uri, "service_uri": response.service_uri().as_str()}),
    )
}

pub(crate) struct HttpTransport {
    client: reqwest::blocking::Client,
    endpoint: String,
}

impl HttpTransport {
    fn new(response: &RepositoryResponse, tls_ca: Option<&Path>, timeout: u64) -> Result<Self> {
        ensure!(
            (1..=300).contains(&timeout),
            "timeout must be 1..=300 seconds"
        );
        let mut builder = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(timeout))
            .connect_timeout(Duration::from_secs(timeout.min(10)))
            .redirect(reqwest::redirect::Policy::none());
        if let Some(path) = tls_ca {
            for cert in reqwest::Certificate::from_pem_bundle(&fs::read(path)?)? {
                builder = builder.add_root_certificate(cert);
            }
        }
        Ok(Self {
            client: builder.build()?,
            endpoint: response.service_uri().as_str().to_owned(),
        })
    }
}

trait Transport {
    fn exchange(&self, bytes: Vec<u8>) -> Result<Vec<u8>>;
}

impl Transport for HttpTransport {
    fn exchange(&self, bytes: Vec<u8>) -> Result<Vec<u8>> {
        let response = self
            .client
            .post(&self.endpoint)
            .header(reqwest::header::CONTENT_TYPE, publication::CONTENT_TYPE)
            .header(reqwest::header::ACCEPT, publication::CONTENT_TYPE)
            .body(bytes)
            .send()
            .context("publication request failed; rerun sync to reconcile remote state")?;
        ensure!(
            response.status().is_success(),
            "publication HTTP error: {}",
            response.status()
        );
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        ensure!(
            content_type
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case(publication::CONTENT_TYPE),
            "unexpected publication response content type"
        );
        let mut bytes = Vec::new();
        response.take(MAX_RESPONSE + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_RESPONSE,
            "publication response exceeds size limit"
        );
        Ok(bytes)
    }
}

struct Client<T> {
    signer: SoftwareSigner,
    server: IdCert,
    transport: T,
}

impl<T: Transport> Client<T> {
    fn exchange(&self, message: Message) -> Result<Reply> {
        let cms = PublicationCms::create(message, self.signer.primary_key_id(), &self.signer)
            .map_err(protocol_error)?;
        let bytes = self.transport.exchange(cms.to_bytes().to_vec())?;
        let cms = PublicationCms::decode(&bytes).map_err(protocol_error)?;
        cms.validate(self.server.public_key())
            .map_err(protocol_error)
            .context("publication response signature invalid")?;
        match cms.into_message().as_reply().map_err(protocol_error)? {
            Reply::ErrorReply(error) => bail!("publication server rejected request: {error}"),
            reply => Ok(reply),
        }
    }

    fn list(&self) -> Result<ListReply> {
        match self.exchange(Message::list_query())? {
            Reply::List(list) => Ok(list),
            _ => bail!("expected publication list response"),
        }
    }

    fn sync(
        &self,
        base: &uri::Rsync,
        files: &BTreeMap<String, Vec<u8>>,
        dry_run: bool,
    ) -> Result<SyncReport> {
        let (delta, mut report) = plan(base, files, self.list()?)?;
        if !dry_run && !delta.is_empty() {
            ensure!(
                matches!(self.exchange(Message::delta(delta))?, Reply::Success),
                "expected publication success response"
            );
            // Confirm the authoritative remote state, including lost/partial updates.
            let (remaining, _) = plan(base, files, self.list()?)?;
            ensure!(
                remaining.is_empty(),
                "remote publication does not match snapshot; rerun sync"
            );
        }
        report.status = if dry_run { "planned" } else { "synchronized" }.into();
        Ok(report)
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct SyncReport {
    status: String,
    publish: Vec<String>,
    update: Vec<String>,
    withdraw: Vec<String>,
    unchanged: usize,
    pub(crate) rrdp_advertised: bool,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn plan(
    base: &uri::Rsync,
    files: &BTreeMap<String, Vec<u8>>,
    list: ListReply,
) -> Result<(PublishDelta, SyncReport)> {
    let mut remote = BTreeMap::new();
    for entry in list.into_elements() {
        let (uri, hash) = entry.unpack();
        let name = uri.relative_to(base).context(
            "remote object outside this CA publication point; dedicated publisher required",
        )?;
        ensure!(
            valid_name(name),
            "remote object is not a flat CA filename; dedicated publisher required"
        );
        ensure!(
            remote.insert(name.to_owned(), (uri, hash)).is_none(),
            "duplicate URI in publication list"
        );
    }
    let mut delta = PublishDelta::empty();
    let mut report = SyncReport {
        status: String::new(),
        publish: Vec::new(),
        update: Vec::new(),
        withdraw: Vec::new(),
        unchanged: 0,
        rrdp_advertised: false,
    };
    for (name, bytes) in files {
        ensure!(valid_name(name), "invalid local repository filename");
        let uri = base.join(name.as_bytes())?;
        match remote.remove(name) {
            Some((_, hash)) if hash.matches(bytes) => report.unchanged += 1,
            Some((_, hash)) => {
                delta.add_update(Update::with_hash_tag(
                    uri,
                    Base64::from_content(bytes),
                    hash,
                ));
                report.update.push(name.clone());
            }
            None => {
                delta.add_publish(Publish::with_hash_tag(uri, Base64::from_content(bytes)));
                report.publish.push(name.clone());
            }
        }
    }
    for (name, (uri, hash)) in remote {
        delta.add_withdraw(Withdraw::with_hash_tag(uri, hash));
        report.withdraw.push(name);
    }
    Ok((delta, report))
}

/// Hold the CA lock only for the snapshot, never across a network operation.
#[derive(Debug)]
struct PublicationSnapshot {
    base: uri::Rsync,
    key_id: String,
    rrdp_advertised: bool,
    files: BTreeMap<String, Vec<u8>>,
}

fn snapshot(ca_dir: &Path, response: &RepositoryResponse) -> Result<PublicationSnapshot> {
    let store = LocalStateStore::new(ca_dir);
    let _guard = store.lock()?;
    let config = CaConfig::from_file(&ca_dir.join("ca.toml"))?;
    let state = store.load()?;
    ensure!(
        state.pending_publication().is_none(),
        "local publication transaction pending; recover the CA before sync"
    );
    let repository = LocalRepository::new(ca_dir);
    let publication = PublicationSet::load(&repository, state.validation_context())
        .context("local publication set invalid; refresh or recover CA before sync")?;
    let mut base: uri::Rsync = config.repository_uri.parse()?;
    base.path_into_dir();
    ensure!(
        base == *response.sia_base() || response.sia_base().is_parent_of(&base),
        "CA repository URI outside assigned sia_base; create/reissue CA at an authorized address"
    );
    ensure!(
        publication.ca.ca_repository() == Some(&base),
        "CA certificate SIA does not match publication point"
    );
    let notify = publication.ca.rpki_notify();
    if notify.is_some() {
        ensure!(
            notify == response.rrdp_notification_uri(),
            "CA certificate rpkiNotify does not match repository response"
        );
    }
    let ca_name =
        crate::ca::publication::key_filename(&publication.ca.subject_key_identifier(), "cer");
    let certificate_uri: uri::Rsync = config.certificate_uri.parse()?;
    ensure!(
        crate::ca::publication::uri_filename(certificate_uri.as_str())? == ca_name,
        "certificate_uri does not match CA certificate filename"
    );
    let local_certificate_uri = base.join(ca_name.as_bytes())?;
    if publication.ca.is_self_signed() {
        ensure!(
            certificate_uri == local_certificate_uri,
            "trust anchor certificate_uri must match its published certificate URI"
        );
    }
    let mut files = publication.publication_files()?;
    for name in files.keys() {
        ensure!(valid_name(name), "invalid repository object filename");
    }
    // A subordinate CA certificate belongs at the issuer's publication point.
    // Keep it for local validation, but do not publish a relocated copy.
    if certificate_uri != local_certificate_uri {
        files.remove(&ca_name);
    }
    Ok(PublicationSnapshot {
        base,
        key_id: publication.ca.subject_key_identifier().to_string(),
        rrdp_advertised: notify.is_some(),
        files,
    })
}

pub(crate) fn sync(
    root: &Path,
    ca_dir: &Path,
    dry_run: bool,
    allow_http: bool,
    tls_ca: Option<&Path>,
    timeout: u64,
) -> Result<SyncReport> {
    let _guard = lock(root)?;
    let response = response_from(
        &fs::read(root.join(RESPONSE)).context("publisher not configured")?,
        allow_http,
    )?;
    let request = PublisherRequest::parse(fs::read(root.join(REQUEST))?.as_slice())
        .map_err(protocol_error)?;
    let identity = request.validate().map_err(protocol_error)?;
    let signer =
        SoftwareSigner::from_pem(&fs::read_to_string(root.join(KEY))?).map_err(protocol_error)?;
    ensure!(
        identity.public_key() == &signer.public_key()?,
        "publisher key does not match registered identity"
    );
    let PublicationSnapshot {
        base,
        key_id,
        rrdp_advertised,
        files,
    } = snapshot(ca_dir, &response)?;
    // Persist the binding before the first send: an ambiguous timeout must not allow
    // a different CA to reuse this publisher and withdraw its previous objects.
    let binding = format!("{base}\n{key_id}\n");
    let binding_path = root.join("ca-binding.txt");
    if binding_path.exists() {
        ensure!(
            fs::read_to_string(binding_path)? == binding,
            "publisher bound to a different CA; use a separate publisher"
        );
    } else if !dry_run {
        atomic_write(root, "ca-binding.txt", binding.as_bytes())?;
    }
    let client = Client {
        signer,
        server: response.validate().map_err(protocol_error)?,
        transport: HttpTransport::new(&response, tls_ca, timeout)?,
    };
    let mut report = client.sync(&base, &files, dry_run)?;
    report.rrdp_advertised = rrdp_advertised;
    if !dry_run {
        atomic_write(
            root,
            "last-sync.json",
            &serde_json::to_vec_pretty(
                &serde_json::json!({"completed_at": chrono::Utc::now().to_rfc3339(), "report": report}),
            )?,
        )?;
    }
    Ok(report)
}

#[cfg(test)]
#[path = "../tests/unit/publisher.rs"]
mod tests;
