//! Axum server, routes, handlers, and HTTP DTOs.

use super::repository::{RepositoryInspection, RepositoryList, inspect, summarize};
use crate::application::signed_objects;
use crate::{
    AspaDelta, CaCertificateRenewal, CaCertificateStatus, CaManager, CaValidationContextUpdate,
    ObjectDeltaResponse, ObjectKind, ObjectWithdrawal, RoaConfigurationView, RoaDelta,
    RoaDeltaRejected, RoaDeltaResponse, SispiDelta, ToaDelta,
};
use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path as AxumPath, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};
use tokio::time::{Duration, interval};
use tokio::{net::TcpListener, sync::Semaphore};
use tower_http::cors::CorsLayer;

#[derive(Clone)]
struct ApiState {
    manager: Arc<CaManager>,
    root: Arc<PathBuf>,
    token: Arc<str>,
    writer: Arc<Semaphore>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificateRenewalRequest {
    certificate_base64: String,
    tal_base64: String,
    #[serde(default)]
    chain_base64: Vec<String>,
    #[serde(default)]
    crls_base64: Vec<String>,
    #[serde(default)]
    manifests_base64: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidationContextUpdateRequest {
    tal_base64: String,
    #[serde(default)]
    chain_base64: Vec<String>,
    #[serde(default)]
    crls_base64: Vec<String>,
    #[serde(default)]
    manifests_base64: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToaReviewRequest {
    #[serde(default)]
    roa_overlap_justification: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: &'static str,
    message: String,
}

type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Debug)]
struct ApiError(StatusCode, &'static str, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.0,
            Json(ErrorResponse {
                error: self.1,
                message: self.2,
            }),
        )
            .into_response()
    }
}

pub async fn serve(
    root: PathBuf,
    bind: &str,
    token: String,
    cors_origin: Option<String>,
) -> Result<()> {
    let manager = Arc::new(CaManager::open(&root).context("cannot open CA for API server")?);
    let state = ApiState {
        manager,
        root: Arc::new(root),
        token: token.into(),
        writer: Arc::new(Semaphore::new(1)),
    };
    let refresh_manager = state.manager.clone();
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(600));
        loop {
            ticker.tick().await;
            let manager = refresh_manager.clone();
            match tokio::task::spawn_blocking(move || manager.refresh_if_needed()).await {
                Ok(Ok(true)) => println!("CRL and Manifest refreshed before nextUpdate"),
                Ok(Ok(false)) => {}
                Ok(Err(error)) => eprintln!("scheduled CRL/Manifest refresh failed: {error:#}"),
                Err(error) => eprintln!("scheduled CRL/Manifest task failed: {error}"),
            }
            match refresh_manager.certificate_status() {
                Ok(status) if status.renewal_required => eprintln!(
                    "CA certificate renewal required; {} seconds remain",
                    status.seconds_remaining
                ),
                Ok(_) => {}
                Err(error) => eprintln!("CA certificate status check failed: {error:#}"),
            }
            match refresh_manager.toa_review_statuses() {
                Ok(statuses) => {
                    for status in statuses.into_iter().filter(|status| status.overdue) {
                        eprintln!(
                            "TOA periodic review overdue for {}; due at Unix timestamp {}",
                            status.object_name, status.review_due_at
                        );
                    }
                }
                Err(error) => eprintln!("TOA review status check failed: {error:#}"),
            }
        }
    });
    let mut app = Router::new()
        .route("/healthz", get(health))
        .route("/api/v1/roas", get(list_roas).post(update_roas))
        .route("/api/v1/aspas", get(list_aspas).post(create_aspa))
        .route(
            "/api/v1/aspas/{customer_asn}",
            get(get_aspa).delete(withdraw_aspa),
        )
        .route("/api/v1/toas", get(list_toas).post(create_toa))
        .route("/api/v1/toas/reviews", get(list_toa_reviews))
        .route("/api/v1/toas/{key}", get(get_toa).delete(withdraw_toa))
        .route("/api/v1/toas/{name}/reviews", post(review_toa))
        .route("/api/v1/sispis", get(list_sispis).post(create_sispi))
        .route(
            "/api/v1/sispis/{asn}",
            get(get_sispi).delete(withdraw_sispi),
        )
        .route(
            "/api/v1/signed-objects/{name}",
            delete(withdraw_published_object),
        )
        .route("/api/v1/ca/certificate", get(certificate_status))
        .route("/api/v1/ca/resources", get(certified_resources))
        .route("/api/v1/ca/info", get(ca_information))
        .route("/api/v1/experiments/snapshot", get(experiment_snapshot))
        .route("/api/v1/ca/certificate-renewals", post(renew_certificate))
        .route(
            "/api/v1/ca/validation-context",
            post(update_validation_context),
        )
        .route("/api/v1/repository/objects", get(list_repository_objects))
        .route(
            "/api/v1/repository/objects/{name}",
            get(inspect_repository_object),
        )
        .route(
            "/api/v1/repository/objects/{name}/validation",
            get(validate_repository_object),
        )
        .route("/repository/{name}", get(download_object))
        .with_state(state);
    if let Some(origin) = cors_origin {
        let origin = HeaderValue::from_str(&origin).context("invalid CORS_ORIGIN")?;
        app = app.layer(
            CorsLayer::new()
                .allow_origin(origin)
                .allow_methods([Method::GET, Method::POST, Method::DELETE])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
                .expose_headers(["x-experiment-valid".parse::<header::HeaderName>()?]),
        );
    }
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("cannot bind {bind}"))?;
    println!("HTTP API listening on {bind}");
    axum::serve(listener, app)
        .await
        .context("HTTP server failed")
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

async fn certificate_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResult<Json<CaCertificateStatus>> {
    authorize(&state, &headers)?;
    state
        .manager
        .certificate_status()
        .map(Json)
        .map_err(internal)
}

async fn certified_resources(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResult<Json<crate::CertifiedResourcesView>> {
    authorize(&state, &headers)?;
    state
        .manager
        .certified_resources()
        .map(Json)
        .map_err(internal)
}

async fn ca_information(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    authorize(&state, &headers)?;
    let root = state.root.clone();
    tokio::task::spawn_blocking(move || crate::application::info::ca_info(&root))
        .await
        .map_err(internal)?
        .map(Json)
        .map_err(internal)
}

async fn experiment_snapshot(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    authorize(&state, &headers)?;
    let root = state.root.clone();
    let (bytes, valid) = tokio::task::spawn_blocking(move || -> Result<_> {
        let temporary = tempfile::tempdir()?;
        let output = temporary.path().join("experiment");
        let (valid, _) = crate::experiment::export(&root, &output)?;
        Ok((tar_experiment(&output)?, valid))
    })
    .await
    .map_err(internal)?
    .map_err(internal)?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-tar")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=experiment.tar",
        )
        .header("x-experiment-valid", if valid { "true" } else { "false" })
        .body(Body::from(bytes))
        .map_err(internal)
}

fn tar_experiment(root: &std::path::Path) -> Result<Vec<u8>> {
    use std::{fs, io::Write};
    let mut files = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            for child in fs::read_dir(entry.path())? {
                let child = child?;
                files.push((
                    format!("repository/{}", child.file_name().to_string_lossy()),
                    child.path(),
                ));
            }
        } else {
            files.push((
                entry.file_name().to_string_lossy().into_owned(),
                entry.path(),
            ));
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut archive = Vec::new();
    for (name, path) in files {
        let data = fs::read(path)?;
        anyhow::ensure!(
            name.is_ascii() && name.len() <= 100,
            "invalid tar entry name: {name}"
        );
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        for (offset, width, number) in [
            (100, 8, 0o644u64),
            (108, 8, 0),
            (116, 8, 0),
            (124, 12, data.len() as u64),
            (136, 12, 0),
        ] {
            let value = format!("{:0width$o}\0", number, width = width - 1);
            header[offset..offset + width].copy_from_slice(value.as_bytes());
        }
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
        let value = format!("{:06o}\0 ", checksum);
        header[148..156].copy_from_slice(value.as_bytes());
        archive.write_all(&header)?;
        archive.write_all(&data)?;
        archive.resize(archive.len().div_ceil(512) * 512, 0);
    }
    archive.resize(archive.len() + 1024, 0);
    Ok(archive)
}

async fn renew_certificate(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<CertificateRenewalRequest>,
) -> ApiResult<StatusCode> {
    authorize(&state, &headers)?;
    let renewal = CaCertificateRenewal {
        certificate: decode_base64(&request.certificate_base64)?,
        chain: decode_base64_list(&request.chain_base64)?,
        crls: decode_base64_list(&request.crls_base64)?,
        manifests: decode_base64_list(&request.manifests_base64)?,
        tal: decode_base64(&request.tal_base64)?,
    };
    let _permit = state.writer.acquire().await.map_err(internal)?;
    let manager = state.manager.clone();
    tokio::task::spawn_blocking(move || manager.renew_certificate(renewal))
        .await
        .map_err(internal)?
        .map_err(|error| {
            ApiError(
                StatusCode::UNPROCESSABLE_ENTITY,
                "certificate_renewal_failed",
                error.to_string(),
            )
        })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn update_validation_context(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<ValidationContextUpdateRequest>,
) -> ApiResult<StatusCode> {
    authorize(&state, &headers)?;
    let update = CaValidationContextUpdate {
        chain: decode_base64_list(&request.chain_base64)?,
        crls: decode_base64_list(&request.crls_base64)?,
        manifests: decode_base64_list(&request.manifests_base64)?,
        tal: decode_base64(&request.tal_base64)?,
    };
    let _permit = state.writer.acquire().await.map_err(internal)?;
    let manager = state.manager.clone();
    tokio::task::spawn_blocking(move || manager.update_validation_context(update))
        .await
        .map_err(internal)?
        .map_err(|error| {
            ApiError(
                StatusCode::UNPROCESSABLE_ENTITY,
                "validation_context_update_failed",
                error.to_string(),
            )
        })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_toa_reviews(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<crate::ToaReviewStatus>>> {
    authorize(&state, &headers)?;
    state
        .manager
        .toa_review_statuses()
        .map(Json)
        .map_err(internal)
}

async fn review_toa(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(object_name): AxumPath<String>,
    Json(request): Json<ToaReviewRequest>,
) -> ApiResult<Json<crate::ToaReviewStatus>> {
    authorize(&state, &headers)?;
    if !valid_object_name(&object_name) || !object_name.ends_with(".toa") {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid_name",
            "invalid TOA repository object name".into(),
        ));
    }
    let _permit = state.writer.acquire().await.map_err(internal)?;
    let manager = state.manager.clone();
    tokio::task::spawn_blocking(move || {
        manager.review_toa(&object_name, request.roa_overlap_justification)
    })
    .await
    .map_err(internal)?
    .map(Json)
    .map_err(|error| {
        ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "toa_review_failed",
            error.to_string(),
        )
    })
}

fn decode_base64(value: &str) -> ApiResult<Vec<u8>> {
    STANDARD
        .decode(value)
        .map_err(|error| ApiError(StatusCode::BAD_REQUEST, "invalid_base64", error.to_string()))
}

fn decode_base64_list(values: &[String]) -> ApiResult<Vec<Vec<u8>>> {
    values.iter().map(|value| decode_base64(value)).collect()
}

async fn list_roas(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<RoaConfigurationView>>> {
    authorize(&state, &headers)?;
    state
        .manager
        .roa_configurations()
        .map(Json)
        .map_err(internal)
}

async fn update_roas(
    State(state): State<ApiState>,
    headers: HeaderMap,
    payload: std::result::Result<Json<RoaDelta>, JsonRejection>,
) -> std::result::Result<Json<RoaDeltaResponse>, Response> {
    authorize(&state, &headers).map_err(IntoResponse::into_response)?;
    let Json(delta) = payload.map_err(|rejection| {
        (
            rejection.status(),
            Json(serde_json::json!({
                "error": "invalid_roa_request",
                "message": format!("ROA 请求体无法解析：{}", rejection.body_text()),
            })),
        )
            .into_response()
    })?;
    let _permit = state
        .writer
        .acquire()
        .await
        .map_err(internal)
        .map_err(IntoResponse::into_response)?;
    let manager = state.manager.clone();
    match tokio::task::spawn_blocking(move || manager.update_roas(delta)).await {
        Ok(Ok(response)) => Ok(Json(response)),
        Ok(Err(error)) => {
            if let Some(rejected) = error.downcast_ref::<RoaDeltaRejected>() {
                Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({
                        "error": "roa_delta_rejected",
                        "message": rejected.to_string(),
                        "details": rejected.0,
                    })),
                )
                    .into_response())
            } else {
                Err(internal(error).into_response())
            }
        }
        Err(error) => Err(internal(error).into_response()),
    }
}

async fn create_aspa(
    State(state): State<ApiState>,
    headers: HeaderMap,
    payload: std::result::Result<Json<AspaDelta>, JsonRejection>,
) -> std::result::Result<Json<ObjectDeltaResponse>, Response> {
    authorize(&state, &headers).map_err(IntoResponse::into_response)?;
    let Json(delta) = parse_object_json(payload, "invalid_aspa_delta")?;
    let _permit = state
        .writer
        .acquire()
        .await
        .map_err(|error| internal(error).into_response())?;
    let manager = state.manager.clone();
    tokio::task::spawn_blocking(move || manager.update_aspas(delta))
        .await
        .map_err(|error| internal(error).into_response())?
        .map(Json)
        .map_err(|error| invalid_delta("aspa_delta_rejected", error))
}

async fn create_toa(
    State(state): State<ApiState>,
    headers: HeaderMap,
    payload: std::result::Result<Json<ToaDelta>, JsonRejection>,
) -> std::result::Result<Json<ObjectDeltaResponse>, Response> {
    authorize(&state, &headers).map_err(IntoResponse::into_response)?;
    let Json(delta) = parse_object_json(payload, "invalid_toa_delta")?;
    let _permit = state
        .writer
        .acquire()
        .await
        .map_err(|error| internal(error).into_response())?;
    let manager = state.manager.clone();
    tokio::task::spawn_blocking(move || manager.update_toas(delta))
        .await
        .map_err(|error| internal(error).into_response())?
        .map(Json)
        .map_err(toa_delta_error)
}

async fn create_sispi(
    State(state): State<ApiState>,
    headers: HeaderMap,
    payload: std::result::Result<Json<SispiDelta>, JsonRejection>,
) -> std::result::Result<Json<ObjectDeltaResponse>, Response> {
    authorize(&state, &headers).map_err(IntoResponse::into_response)?;
    let Json(delta) = parse_object_json(payload, "invalid_sispi_delta")?;
    let _permit = state
        .writer
        .acquire()
        .await
        .map_err(|error| internal(error).into_response())?;
    let manager = state.manager.clone();
    tokio::task::spawn_blocking(move || manager.update_sispis(delta))
        .await
        .map_err(|error| internal(error).into_response())?
        .map(Json)
        .map_err(|error| invalid_delta("sispi_delta_rejected", error))
}

fn invalid_delta(code: &'static str, error: anyhow::Error) -> Response {
    ApiError(StatusCode::UNPROCESSABLE_ENTITY, code, error.to_string()).into_response()
}

fn toa_delta_error(error: anyhow::Error) -> Response {
    let code = if error.is::<crate::ca::toa_policy::ToaRoaOverlapJustificationRequired>() {
        "toa_roa_overlap_justification_required"
    } else if error.is::<crate::ResourceAuthorizationError>() {
        "resource_not_held"
    } else {
        "toa_delta_rejected"
    };
    ApiError(StatusCode::UNPROCESSABLE_ENTITY, code, error.to_string()).into_response()
}

fn parse_object_json<T>(
    payload: std::result::Result<Json<T>, JsonRejection>,
    code: &'static str,
) -> std::result::Result<Json<T>, Response> {
    payload.map_err(|rejection| {
        ApiError(rejection.status(), code, rejection.body_text()).into_response()
    })
}

async fn list_aspas(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<crate::SignedObjectView>>> {
    list_signed_objects(state, headers, ObjectKind::Aspa).await
}

async fn list_toas(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<crate::SignedObjectView>>> {
    list_signed_objects(state, headers, ObjectKind::Toa).await
}

async fn list_sispis(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<crate::SignedObjectView>>> {
    list_signed_objects(state, headers, ObjectKind::Sispi).await
}

async fn list_signed_objects(
    state: ApiState,
    headers: HeaderMap,
    kind: ObjectKind,
) -> ApiResult<Json<Vec<crate::SignedObjectView>>> {
    authorize(&state, &headers)?;
    let manager = state.manager.clone();
    tokio::task::spawn_blocking(move || manager.signed_objects(kind))
        .await
        .map_err(internal)?
        .map(Json)
        .map_err(internal)
}

async fn get_aspa(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(customer_asn): AxumPath<String>,
) -> ApiResult<Json<crate::SignedObjectView>> {
    let customer_asn = parse_asn_identifier(&customer_asn)?;
    get_signed_object(
        state,
        headers,
        ObjectKind::Aspa,
        format!("aspa:AS{customer_asn}"),
    )
    .await
}

async fn get_toa(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(key): AxumPath<String>,
) -> ApiResult<Json<crate::SignedObjectView>> {
    validate_content_key(&key)?;
    get_signed_object(state, headers, ObjectKind::Toa, format!("toa:{key}")).await
}

async fn get_sispi(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(asn): AxumPath<String>,
) -> ApiResult<Json<crate::SignedObjectView>> {
    let asn = parse_asn_identifier(&asn)?;
    get_signed_object(state, headers, ObjectKind::Sispi, format!("sispi:AS{asn}")).await
}

async fn withdraw_aspa(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(customer_asn): AxumPath<String>,
) -> ApiResult<Json<ObjectWithdrawal>> {
    let customer_asn = parse_asn_identifier(&customer_asn)?;
    withdraw_logical_object(
        state,
        headers,
        ObjectKind::Aspa,
        format!("aspa:AS{customer_asn}"),
    )
    .await
}

async fn withdraw_toa(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(key): AxumPath<String>,
) -> ApiResult<Json<ObjectWithdrawal>> {
    validate_content_key(&key)?;
    withdraw_logical_object(state, headers, ObjectKind::Toa, format!("toa:{key}")).await
}

async fn withdraw_sispi(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(asn): AxumPath<String>,
) -> ApiResult<Json<ObjectWithdrawal>> {
    let asn = parse_asn_identifier(&asn)?;
    withdraw_logical_object(state, headers, ObjectKind::Sispi, format!("sispi:AS{asn}")).await
}

async fn withdraw_logical_object(
    state: ApiState,
    headers: HeaderMap,
    kind: ObjectKind,
    logical_key: String,
) -> ApiResult<Json<ObjectWithdrawal>> {
    authorize(&state, &headers)?;
    let _permit = state.writer.acquire().await.map_err(internal)?;
    let manager = state.manager.clone();
    tokio::task::spawn_blocking(move || {
        signed_objects::withdraw(manager.as_ref(), kind, &logical_key)
    })
    .await
    .map_err(internal)?
    .map_err(internal)?
    .map(Json)
    .ok_or_else(|| {
        ApiError(
            StatusCode::NOT_FOUND,
            "signed_object_not_found",
            "signed object is not in the current CA inventory".into(),
        )
    })
}

async fn withdraw_published_object(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> ApiResult<Json<ObjectWithdrawal>> {
    authorize(&state, &headers)?;
    withdrawable_object_kind(&name)?;
    let _permit = state.writer.acquire().await.map_err(internal)?;
    let manager = state.manager.clone();
    let withdrawn = tokio::task::spawn_blocking(move || manager.withdraw_published_object(&name))
        .await
        .map_err(internal)?
        .map_err(internal)?
        .ok_or_else(|| {
            ApiError(
                StatusCode::NOT_FOUND,
                "signed_object_not_found",
                "signed object is not in the current CA inventory".into(),
            )
        })?;
    Ok(Json(withdrawn))
}

async fn get_signed_object(
    state: ApiState,
    headers: HeaderMap,
    kind: ObjectKind,
    logical_key: String,
) -> ApiResult<Json<crate::SignedObjectView>> {
    authorize(&state, &headers)?;
    let manager = state.manager.clone();
    tokio::task::spawn_blocking(move || signed_objects::get(manager.as_ref(), kind, &logical_key))
        .await
        .map_err(internal)?
        .map_err(internal)?
        .map(Json)
        .ok_or_else(|| not_found("signed object is not in the current CA inventory"))
}

async fn download_object(
    State(state): State<ApiState>,
    AxumPath(name): AxumPath<String>,
) -> ApiResult<Response> {
    if !valid_object_name(&name) {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid_name",
            "invalid repository object name".into(),
        ));
    }
    let bytes = state
        .manager
        .read_published_object(&name)
        .map_err(not_found)?;
    let content_type = repository_content_type(&name);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(bytes))
        .map_err(internal)
}

fn repository_content_type(name: &str) -> &'static str {
    match name.rsplit_once('.').map(|(_, extension)| extension) {
        Some("cer") => "application/pkix-cert",
        Some("crl") => "application/pkix-crl",
        Some("mft") => "application/rpki-manifest",
        Some("roa") => "application/rpki-roa",
        Some("asa") => "application/rpki-aspa",
        Some("toa") => "application/rpki-toa",
        Some("sav") => "application/rpki-sispi",
        _ => "application/octet-stream",
    }
}

async fn list_repository_objects(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResult<Json<RepositoryList>> {
    authorize(&state, &headers)?;
    let manager = state.manager.clone();
    let objects = tokio::task::spawn_blocking(move || -> Result<_> {
        let signed_objects = manager.list_published_signed_objects()?;
        let mut objects = manager
            .list_published_objects()?
            .into_iter()
            .map(|name| {
                let bytes = manager.read_published_object(&name)?;
                let withdrawable = signed_objects.contains(&name) && !name.ends_with(".roa");
                Ok(summarize(name, &bytes, withdrawable))
            })
            .collect::<Result<Vec<_>>>()?;
        objects.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(objects)
    })
    .await
    .map_err(internal)?
    .map_err(internal)?;
    Ok(Json(RepositoryList { objects }))
}

async fn inspect_repository_object(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> ApiResult<Json<RepositoryInspection>> {
    authorize(&state, &headers)?;
    if !valid_object_name(&name) {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid_name",
            "invalid repository object name".into(),
        ));
    }
    let manager = state.manager.clone();
    tokio::task::spawn_blocking(move || {
        let bytes = manager.read_published_object(&name)?;
        inspect(name, bytes)
    })
    .await
    .map_err(internal)?
    .map(Json)
    .map_err(|error| {
        ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "inspection_failed",
            error.to_string(),
        )
    })
}

async fn validate_repository_object(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> ApiResult<Json<crate::ValidationReport>> {
    authorize(&state, &headers)?;
    if !valid_object_name(&name) {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid_name",
            "invalid repository object name".into(),
        ));
    }
    let manager = state.manager.clone();
    tokio::task::spawn_blocking(move || manager.validate_published_object(&name))
        .await
        .map_err(internal)?
        .map(Json)
        .map_err(internal)
}

fn authorize(state: &ApiState, headers: &HeaderMap) -> ApiResult<()> {
    let expected = format!("Bearer {}", state.token);
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        != Some(expected.as_str())
    {
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "a valid bearer token is required".into(),
        ));
    }
    Ok(())
}

fn validate_content_key(value: &str) -> ApiResult<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid_logical_key",
            "TOA key must contain exactly 64 hexadecimal characters".into(),
        ));
    }
    Ok(())
}

fn parse_asn_identifier(value: &str) -> ApiResult<u32> {
    value.parse().map_err(|_| {
        ApiError(
            StatusCode::BAD_REQUEST,
            "invalid_asn",
            "ASN path parameter must be an unsigned 32-bit integer".into(),
        )
    })
}

fn valid_object_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn withdrawable_object_kind(value: &str) -> ApiResult<ObjectKind> {
    if !valid_object_name(value) {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid_object_name",
            "invalid repository object name".into(),
        ));
    }
    let kind = value
        .rsplit_once('.')
        .and_then(|(_, extension)| ObjectKind::from_extension(extension))
        .ok_or_else(|| {
            ApiError(
                StatusCode::UNPROCESSABLE_ENTITY,
                "object_not_withdrawable",
                "only published signed objects can be withdrawn".into(),
            )
        })?;
    if kind == ObjectKind::Roa {
        return Err(ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "roa_managed_by_authorizations",
            "ROA files are derived; remove their authorization configurations through /api/v1/roas"
                .into(),
        ));
    }
    Ok(kind)
}

fn internal(error: impl std::fmt::Display) -> ApiError {
    ApiError(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        error.to_string(),
    )
}

fn not_found(_: impl std::fmt::Display) -> ApiError {
    ApiError(
        StatusCode::NOT_FOUND,
        "not_found",
        "ROA request or object was not found".into(),
    )
}

#[cfg(test)]
#[path = "../../tests/unit/api/server.rs"]
mod tests;
