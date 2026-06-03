//! HTTP REST handlers for the Signing Gateway (Axum).
//!
//! Endpoints:
//!   POST /v1/sign                 — sign a payload
//!   POST /v1/verify               — verify a signature
//!   GET  /v1/keys                 — list keys
//!   GET  /v1/keys/:key_id/public  — get public key
//!   GET  /health                  — health check
//!   GET  /metrics                 — Prometheus metrics

use crate::{
    config::Algorithm,
    hsm::HsmError,
    AppState,
};
use axum::{
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use base64::Engine;
use chrono::Utc;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

// ─── Request / Response types ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SignHttpRequest {
    /// Calling service identifier (validated against auth config)
    pub caller_id: String,
    /// Logical key ID
    #[serde(default)]
    pub key_id: String,
    /// Algorithm (default = key's algorithm)
    pub algorithm: Option<String>,
    /// Payload to sign — accepts hex (SHA-256 hash), base64, or base64url
    pub payload: String,
    /// If true, payload is already a digest
    #[serde(default)]
    pub prehashed: bool,
    /// Client-supplied idempotency key
    pub request_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SignHttpResponse {
    pub signature_hex: String,
    pub key_id: String,
    pub algorithm: String,
    pub signed_at: String,
    pub request_id: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyHttpRequest {
    pub key_id: String,
    pub algorithm: String,
    pub payload: String,
    pub signature: String,
    #[serde(default)]
    pub prehashed: bool,
}

#[derive(Debug, Serialize)]
pub struct VerifyHttpResponse {
    pub valid: bool,
    pub key_id: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub hsm_backend: String,
    pub version: String,
    pub uptime_seconds: String,
    pub keys_loaded: usize,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
}

// ─── Error → HTTP response ────────────────────────────────────────────────────

impl IntoResponse for HsmError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            HsmError::KeyNotFound(_) => (StatusCode::NOT_FOUND, "KEY_NOT_FOUND"),
            HsmError::KeyDisabled(_) => (StatusCode::FORBIDDEN, "KEY_DISABLED"),
            HsmError::AlgorithmNotSupported { .. } => (StatusCode::BAD_REQUEST, "ALGO_NOT_SUPPORTED"),
            HsmError::SigningFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, "SIGNING_FAILED"),
            HsmError::VerificationFailed(_) => (StatusCode::BAD_REQUEST, "VERIFICATION_FAILED"),
            HsmError::BackendError(_) => (StatusCode::SERVICE_UNAVAILABLE, "BACKEND_ERROR"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
        };

        let body = Json(ErrorResponse {
            error: self.to_string(),
            code: code.to_string(),
        });

        (status, body).into_response()
    }
}

// ─── Auth helper ──────────────────────────────────────────────────────────────

fn check_caller(state: &AppState, caller_id: &str, token: Option<&str>) -> bool {
    let auth = state.auth.read().unwrap();
    if auth.allow_all {
        return true;
    }
    match token {
        Some(t) => auth.tokens.get(t).map(|id| id == caller_id).unwrap_or(false),
        None => false,
    }
}

/// Returns true if the caller is allowed to use the given key.
/// Callers with no entry in `allowed_keys` may use any key.
fn check_key_allowed(state: &AppState, caller_id: &str, key_id: &str) -> bool {
    let auth = state.auth.read().unwrap();
    if auth.allow_all {
        return true;
    }
    match auth.allowed_keys.get(caller_id) {
        Some(keys) => keys.iter().any(|k| k == key_id),
        None => true,
    }
}

/// Returns true if the source IP is permitted for this caller.
/// Entries may be exact IPs ("10.0.1.5") or CIDR ranges ("10.0.0.0/8").
/// Callers with no entry in `allowed_ips` may connect from any IP.
fn check_ip_allowed(state: &AppState, caller_id: &str, ip: std::net::IpAddr) -> bool {
    let auth = state.auth.read().unwrap();
    if auth.allow_all {
        return true;
    }
    let Some(patterns) = auth.allowed_ips.get(caller_id) else {
        return true; // no restriction configured
    };
    for pattern in patterns {
        if let Ok(net) = pattern.parse::<IpNet>() {
            if net.contains(&ip) {
                return true;
            }
        } else if let Ok(exact) = pattern.parse::<std::net::IpAddr>() {
            if exact == ip {
                return true;
            }
        }
    }
    false
}

fn extract_bearer(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Decode payload from hex, base64, or base64url.
/// Hex is tried first — a 64-char lowercase hex string is a SHA-256 hash.
fn decode_payload(s: &str) -> Result<Vec<u8>, String> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    // Try hex first (e.g. "cf7c032733c6ecbf..." from sha256sum / openssl dgst)
    if s.len() % 2 == 0 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return hex::decode(s).map_err(|e| e.to_string());
    }
    // Try standard base64, then base64url no-pad
    STANDARD
        .decode(s)
        .or_else(|_| URL_SAFE_NO_PAD.decode(s))
        .map_err(|e| e.to_string())
}

fn parse_algorithm(s: &str) -> Result<Algorithm, String> {
    match s.to_uppercase().as_str() {
        "RS256" => Ok(Algorithm::Rs256),
        "RS384" => Ok(Algorithm::Rs384),
        "RS512" => Ok(Algorithm::Rs512),
        "PS256" => Ok(Algorithm::Ps256),
        "PS384" => Ok(Algorithm::Ps384),
        "PS512" => Ok(Algorithm::Ps512),
        "ES256" => Ok(Algorithm::Es256),
        "ES384" => Ok(Algorithm::Es384),
        "HS256" => Ok(Algorithm::Hs256),
        "HS384" => Ok(Algorithm::Hs384),
        "HS512" => Ok(Algorithm::Hs512),
        other => Err(format!("Unknown algorithm: {}", other)),
    }
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// POST /v1/sign
#[instrument(skip(state, headers, req), fields(caller_id = %req.caller_id, key_id = %req.key_id))]
pub async fn handle_sign(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<SignHttpRequest>,
) -> Response {
    let token = extract_bearer(&headers);
    if !check_caller(&state, &req.caller_id, token) {
        warn!(caller_id = %req.caller_id, "Unauthorized sign request");
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Unauthorized".into(),
                code: "UNAUTHORIZED".into(),
            }),
        )
            .into_response();
    }

    let xff = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());
    let client_ip = state.resolve_client_ip(peer.ip(), xff);

    if !check_ip_allowed(&state, &req.caller_id, client_ip) {
        warn!(caller_id = %req.caller_id, ip = %client_ip, "IP not allowed for caller");
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: format!("Source IP '{}' is not permitted for caller '{}'", client_ip, req.caller_id),
                code: "IP_NOT_ALLOWED".into(),
            }),
        )
            .into_response();
    }

    if !req.key_id.is_empty() && !check_key_allowed(&state, &req.caller_id, &req.key_id) {
        warn!(caller_id = %req.caller_id, key_id = %req.key_id, "Key not allowed for caller");
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: format!("Key '{}' is not permitted for caller '{}'", req.key_id, req.caller_id),
                code: "KEY_NOT_ALLOWED".into(),
            }),
        )
            .into_response();
    }

    let payload = match decode_payload(&req.payload) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid payload (expected hex, base64, or base64url): {}", e),
                    code: "INVALID_PAYLOAD".into(),
                }),
            )
                .into_response();
        }
    };

    // Resolve key and algorithm
    let (key_id, algorithm) = {
        let keys = state.hsm.list_keys().await;
        let keys = match keys {
            Ok(k) => k,
            Err(e) => return e.into_response(),
        };

        let key_id = if req.key_id.is_empty() {
            match keys.first() {
                Some(k) => k.id.clone(),
                None => {
                    return HsmError::KeyNotFound("no keys registered".into()).into_response()
                }
            }
        } else {
            req.key_id.clone()
        };

        let algo = if let Some(a) = &req.algorithm {
            match parse_algorithm(a) {
                Ok(alg) => alg,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: e,
                            code: "INVALID_ALGORITHM".into(),
                        }),
                    )
                        .into_response();
                }
            }
        } else {
            match keys.iter().find(|k| k.id == key_id) {
                Some(k) => k.algorithm,
                None => return HsmError::KeyNotFound(key_id.clone()).into_response(),
            }
        };

        (key_id, algo)
    };

    let request_id = req.request_id.unwrap_or_else(|| Uuid::new_v4().to_string());

    match state.hsm.sign(&key_id, algorithm, &payload, req.prehashed).await {
        Ok(sig) => {
            let sig_hex = hex::encode(&sig.0);

            info!(
                key_id = %key_id,
                algorithm = %algorithm,
                request_id = %request_id,
                "Signed successfully"
            );

            // Metrics
            metrics::counter!("signing_gateway_sign_total", "algorithm" => algorithm.to_string(), "key_id" => key_id.clone()).increment(1);

            Json(SignHttpResponse {
                signature_hex: sig_hex,
                key_id,
                algorithm: algorithm.to_string(),
                signed_at: Utc::now().to_rfc3339(),
                request_id,
            })
            .into_response()
        }
        Err(e) => {
            error!(error = %e, key_id = %key_id, "Signing failed");
            metrics::counter!("signing_gateway_sign_errors_total").increment(1);
            e.into_response()
        }
    }
}

/// POST /v1/verify
#[instrument(skip(state, req), fields(key_id = %req.key_id))]
pub async fn handle_verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyHttpRequest>,
) -> Response {
    let payload = match decode_payload(&req.payload) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid payload (expected hex, base64, or base64url): {}", e),
                    code: "INVALID_PAYLOAD".into(),
                }),
            )
                .into_response();
        }
    };

    let signature = match decode_payload(&req.signature) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid signature: {}", e),
                    code: "INVALID_SIGNATURE".into(),
                }),
            )
                .into_response();
        }
    };

    let algorithm = match parse_algorithm(&req.algorithm) {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: e, code: "INVALID_ALGORITHM".into() }),
            )
                .into_response();
        }
    };

    match state.hsm.verify(&req.key_id, algorithm, &payload, &signature, req.prehashed).await {
        Ok(valid) => Json(VerifyHttpResponse {
            valid,
            key_id: req.key_id.clone(),
            message: if valid { "Signature is valid".into() } else { "Signature is invalid".into() },
        })
        .into_response(),
        Err(e) => e.into_response(),
    }
}

/// GET /v1/keys
pub async fn handle_list_keys(State(state): State<Arc<AppState>>) -> Response {
    match state.hsm.list_keys().await {
        Ok(keys) => Json(keys).into_response(),
        Err(e) => e.into_response(),
    }
}

/// GET /v1/keys/:key_id/public
pub async fn handle_get_public_key(
    State(state): State<Arc<AppState>>,
    Path(key_id): Path<String>,
) -> Response {
    match state.hsm.public_key(&key_id).await {
        Ok(pk) => Json(pk).into_response(),
        Err(e) => e.into_response(),
    }
}

/// GET /health
pub async fn handle_health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let keys_loaded = state.hsm.list_keys().await.map(|k| k.len()).unwrap_or(0);
    Json(HealthResponse {
        status: "SERVING".into(),
        hsm_backend: state.hsm.backend_name().to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: state.start_time.elapsed().as_secs().to_string(),
        keys_loaded,
    })
}
