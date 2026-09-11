//! Axum server, routes, handlers, and HTTP DTOs.

use crate::{
    AspaRequest, CaCertificateRenewal, CaCertificateStatus, CaManager, ObjectDefinition,
    ObjectKind, RoaRequest,
    infrastructure::idempotency::{IdempotencyStore, LocalIdempotencyStore},
};
use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path as AxumPath, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc};
use tokio::time::{Duration, interval};
use tokio::{net::TcpListener, sync::Semaphore};
use tower_http::cors::CorsLayer;

#[derive(Clone)]
struct ApiState {
    manager: Arc<CaManager>,
    idempotency: Arc<dyn IdempotencyStore>,
    token: Arc<str>,
    writer: Arc<Semaphore>,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdempotencyRecord {
    request_hash: String,
    definition: ObjectDefinition,
    requested_name: String,
    published_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct ObjectResponse {
    id: String,
    object_name: String,
    download_url: String,
    created: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificateRenewalRequest {
    certificate_base64: String,
    #[serde(default)]
    chain_base64: Vec<String>,
    #[serde(default)]
    crls_base64: Vec<String>,
    #[serde(default)]
    manifests_base64: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: &'static str,
    message: String,
}

type ApiResult<T> = std::result::Result<T, ApiError>;

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
        idempotency: Arc::new(LocalIdempotencyStore::new(root)),
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
        }
    });
    let mut app = Router::new()
        .route("/healthz", get(health))
        .route("/api/v1/roas", post(create_roa))
        .route("/api/v1/roas/{id}", get(get_roa).delete(delete_roa))
        .route("/api/v1/aspas", post(create_aspa))
        .route("/api/v1/aspas/{id}", get(get_aspa).delete(delete_aspa))
        .route("/api/v1/ca/certificate", get(certificate_status))
        .route("/api/v1/ca/certificate-renewals", post(renew_certificate))
        .route("/repository/{name}", get(download_object))
        .with_state(state);
    if let Some(origin) = cors_origin {
        let origin = HeaderValue::from_str(&origin).context("invalid CORS_ORIGIN")?;
        app = app.layer(
            CorsLayer::new()
                .allow_origin(origin)
                .allow_methods([Method::GET, Method::POST, Method::DELETE])
                .allow_headers([
                    header::AUTHORIZATION,
                    header::CONTENT_TYPE,
                    header::HeaderName::from_static("idempotency-key"),
                ]),
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

fn decode_base64(value: &str) -> ApiResult<Vec<u8>> {
    STANDARD
        .decode(value)
        .map_err(|error| ApiError(StatusCode::BAD_REQUEST, "invalid_base64", error.to_string()))
}

fn decode_base64_list(values: &[String]) -> ApiResult<Vec<Vec<u8>>> {
    values.iter().map(|value| decode_base64(value)).collect()
}

async fn create_roa(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<RoaRequest>,
) -> ApiResult<(StatusCode, Json<ObjectResponse>)> {
    create_signed_object(state, headers, ObjectDefinition::Roa(request)).await
}

async fn create_aspa(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<AspaRequest>,
) -> ApiResult<(StatusCode, Json<ObjectResponse>)> {
    create_signed_object(state, headers, ObjectDefinition::Aspa(request)).await
}

async fn create_signed_object(
    state: ApiState,
    headers: HeaderMap,
    definition: ObjectDefinition,
) -> ApiResult<(StatusCode, Json<ObjectResponse>)> {
    authorize(&state, &headers)?;
    definition.validate().map_err(|e| {
        ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_object",
            e.to_string(),
        )
    })?;
    let key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            ApiError(
                StatusCode::BAD_REQUEST,
                "missing_idempotency_key",
                "Idempotency-Key header is required".into(),
            )
        })?;
    validate_idempotency_key(key)?;
    let kind = definition.kind();
    let id = idempotency_id(kind, key);
    let request_hash = digest_hex(&serde_json::to_vec(&definition).map_err(internal)?);
    let requested_name = match &definition {
        ObjectDefinition::Roa(_) => format!("roa-{}.roa", &id[..24]),
        ObjectDefinition::Aspa(request) => format!("aspa-AS{}.asa", request.customer_asn),
    };
    let record = IdempotencyRecord {
        request_hash,
        definition,
        requested_name,
        published_name: None,
    };
    let _permit = state.writer.acquire().await.map_err(internal)?;
    let manager = state.manager.clone();
    let idempotency = state.idempotency.clone();
    let id_for_task = id.clone();
    let (created, stored) = tokio::task::spawn_blocking(move || {
        issue_idempotently(manager.as_ref(), idempotency.as_ref(), &id_for_task, record)
    })
    .await
    .map_err(internal)?
    .map_err(|e| {
        ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "issuance_failed",
            e.to_string(),
        )
    })?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        Json(ObjectResponse {
            id,
            download_url: format!(
                "/repository/{}",
                stored
                    .published_name
                    .as_deref()
                    .expect("issued object name")
            ),
            object_name: stored.published_name.expect("issued object name"),
            created,
        }),
    ))
}

async fn get_roa(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> ApiResult<Json<ObjectResponse>> {
    get_signed_object(state, headers, id, ObjectKind::Roa).await
}

async fn get_aspa(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> ApiResult<Json<ObjectResponse>> {
    get_signed_object(state, headers, id, ObjectKind::Aspa).await
}

async fn delete_roa(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> ApiResult<StatusCode> {
    withdraw_signed_object(state, headers, id, ObjectKind::Roa).await
}

async fn delete_aspa(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> ApiResult<StatusCode> {
    withdraw_signed_object(state, headers, id, ObjectKind::Aspa).await
}

async fn withdraw_signed_object(
    state: ApiState,
    headers: HeaderMap,
    id: String,
    expected: ObjectKind,
) -> ApiResult<StatusCode> {
    authorize(&state, &headers)?;
    validate_id(&id)?;
    let record = read_record(state.idempotency.as_ref(), &id).map_err(not_found)?;
    if record.definition.kind() != expected {
        return Err(not_found("object kind mismatch"));
    }
    let _permit = state.writer.acquire().await.map_err(internal)?;
    let manager = state.manager.clone();
    tokio::task::spawn_blocking(move || {
        manager.withdraw_definition(&record.definition, &record.requested_name)
    })
    .await
    .map_err(internal)?
    .map_err(internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_signed_object(
    state: ApiState,
    headers: HeaderMap,
    id: String,
    expected_kind: ObjectKind,
) -> ApiResult<Json<ObjectResponse>> {
    authorize(&state, &headers)?;
    validate_id(&id)?;
    let record = read_record(state.idempotency.as_ref(), &id).map_err(not_found)?;
    if record.definition.kind() != expected_kind {
        return Err(not_found("object kind mismatch"));
    }
    let object_name = record
        .published_name
        .ok_or_else(|| not_found("object not issued"))?;
    let created = state
        .manager
        .has_published_object(&object_name)
        .map_err(internal)?;
    Ok(Json(ObjectResponse {
        id,
        download_url: format!("/repository/{object_name}"),
        object_name,
        created,
    }))
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
    let content_type = if name.ends_with(".roa") {
        "application/rpki-roa"
    } else if name.ends_with(".asa") {
        "application/rpki-aspa"
    } else {
        "application/octet-stream"
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(bytes))
        .map_err(internal)
}

fn issue_idempotently(
    manager: &CaManager,
    idempotency: &dyn IdempotencyStore,
    id: &str,
    new_record: IdempotencyRecord,
) -> Result<(bool, IdempotencyRecord)> {
    let mut record = if let Some(bytes) = idempotency.get(id)? {
        let existing: IdempotencyRecord = serde_json::from_slice(&bytes)?;
        if existing.request_hash != new_record.request_hash {
            anyhow::bail!("Idempotency-Key was already used with a different request");
        }
        existing
    } else {
        let bytes = serde_json::to_vec_pretty(&new_record)?;
        if idempotency.put_if_absent(id, &bytes)? {
            new_record
        } else {
            let existing = read_record(idempotency, id)?;
            if existing.request_hash != new_record.request_hash {
                anyhow::bail!("Idempotency-Key was already used with a different request");
            }
            existing
        }
    };
    let logical_key = record.definition.logical_key(&record.requested_name);
    if let Some(name) = manager.published_name(&logical_key)? {
        record.published_name = Some(name);
        idempotency.replace(id, &serde_json::to_vec_pretty(&record)?)?;
        return Ok((false, record));
    }
    let output = manager.sign_object(record.definition.clone(), &record.requested_name)?;
    record.published_name = Some(output.name);
    idempotency.replace(id, &serde_json::to_vec_pretty(&record)?)?;
    Ok((true, record))
}

fn read_record(store: &dyn IdempotencyStore, id: &str) -> Result<IdempotencyRecord> {
    let bytes = store
        .get(id)?
        .context("idempotency record does not exist")?;
    Ok(serde_json::from_slice(&bytes)?)
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

fn validate_idempotency_key(value: &str) -> ApiResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid_idempotency_key",
            "use 1-128 ASCII letters, digits, '-', '_', '.', or ':'".into(),
        ));
    }
    Ok(())
}

fn validate_id(value: &str) -> ApiResult<()> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid_id",
            "invalid request id".into(),
        ));
    }
    Ok(())
}

fn valid_object_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn digest_hex(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn idempotency_id(kind: ObjectKind, key: &str) -> String {
    digest_hex(format!("{kind}:{key}").as_bytes())
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
