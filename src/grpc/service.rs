//! gRPC service implementation (Tonic).
//! Implements the generated `signing_service_server::SigningService` trait.

use crate::{config::Algorithm, hsm::HsmError, AppState};
use chrono::Utc;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{error, info};
use uuid::Uuid;

use super::proto::{
    signing_service_server::SigningService,
    GetPublicKeyRequest, GetPublicKeyResponse,
    HealthRequest, HealthResponse,
    ListKeysRequest, ListKeysResponse, KeyInfo,
    SignRequest, SignResponse,
    VerifyRequest, VerifyResponse,
};

// ─── Algorithm conversion ─────────────────────────────────────────────────────

fn proto_to_algorithm(v: i32) -> Option<Algorithm> {
    match v {
        1  => Some(Algorithm::Rs256),
        2  => Some(Algorithm::Rs384),
        3  => Some(Algorithm::Rs512),
        4  => Some(Algorithm::Ps256),
        5  => Some(Algorithm::Ps384),
        6  => Some(Algorithm::Ps512),
        7  => Some(Algorithm::Es256),
        8  => Some(Algorithm::Es384),
        9  => Some(Algorithm::Hs256),
        10 => Some(Algorithm::Hs384),
        11 => Some(Algorithm::Hs512),
        _  => None,
    }
}

fn algorithm_to_proto(a: Algorithm) -> i32 {
    match a {
        Algorithm::Rs256 => 1,  Algorithm::Rs384 => 2,  Algorithm::Rs512 => 3,
        Algorithm::Ps256 => 4,  Algorithm::Ps384 => 5,  Algorithm::Ps512 => 6,
        Algorithm::Es256 => 7,  Algorithm::Es384 => 8,
        Algorithm::Hs256 => 9,  Algorithm::Hs384 => 10, Algorithm::Hs512 => 11,
    }
}

fn hsm_err_to_status(e: HsmError) -> Status {
    match &e {
        HsmError::KeyNotFound(_)              => Status::not_found(e.to_string()),
        HsmError::KeyDisabled(_)              => Status::permission_denied(e.to_string()),
        HsmError::AlgorithmNotSupported { .. } => Status::invalid_argument(e.to_string()),
        HsmError::SigningFailed(_)            => Status::internal(e.to_string()),
        HsmError::VerificationFailed(_)       => Status::invalid_argument(e.to_string()),
        _                                     => Status::unavailable(e.to_string()),
    }
}

// ─── Service struct ───────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SigningGatewayService {
    pub state: Arc<AppState>,
    pub start_time: std::time::Instant,
}

impl SigningGatewayService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state, start_time: std::time::Instant::now() }
    }
}

// ─── Trait implementation ─────────────────────────────────────────────────────

#[tonic::async_trait]
impl SigningService for SigningGatewayService {
    async fn sign(
        &self,
        request: Request<SignRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        // Auth: check bearer token from metadata
        if !self.state.config.auth.allow_all {
            let token = request
                .metadata()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "));

            let caller_ok = token.and_then(|t| self.state.config.auth.tokens.get(t)).is_some();
            if !caller_ok {
                return Err(Status::unauthenticated("Invalid or missing Bearer token"));
            }
        }

        let req = request.into_inner();

        let algorithm = if req.algorithm == 0 {
            // UNSPECIFIED — look up default from key registry
            self.state
                .hsm
                .list_keys()
                .await
                .map_err(hsm_err_to_status)?
                .iter()
                .find(|k| k.id == req.key_id)
                .map(|k| k.algorithm)
                .ok_or_else(|| Status::not_found(format!("Key not found: {}", req.key_id)))?
        } else {
            proto_to_algorithm(req.algorithm)
                .ok_or_else(|| Status::invalid_argument("Unknown algorithm"))?
        };

        let request_id = if req.request_id.is_empty() {
            Uuid::new_v4().to_string()
        } else {
            req.request_id.clone()
        };

        let sig = self
            .state
            .hsm
            .sign(&req.key_id, algorithm, &req.payload, req.prehashed)
            .await
            .map_err(|e| {
                error!(error = %e, key_id = %req.key_id, "gRPC sign failed");
                hsm_err_to_status(e)
            })?;

        metrics::counter!("signing_gateway_grpc_sign_total",
            "algorithm" => algorithm.to_string(),
            "key_id"    => req.key_id.clone()
        ).increment(1);

        info!(
            key_id     = %req.key_id,
            algorithm  = %algorithm,
            caller_id  = %req.caller_id,
            request_id = %request_id,
            "gRPC sign OK"
        );

        Ok(Response::new(SignResponse {
            signature_hex: hex::encode(&sig.0),
            key_id:        req.key_id,
            algorithm:     algorithm_to_proto(algorithm),
            signed_at:     Utc::now().to_rfc3339(),
            request_id,
        }))
    }

    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        let req = request.into_inner();

        let algorithm = proto_to_algorithm(req.algorithm)
            .ok_or_else(|| Status::invalid_argument("Unknown algorithm"))?;

        let valid = self
            .state
            .hsm
            .verify(&req.key_id, algorithm, &req.payload, &req.signature, req.prehashed)
            .await
            .map_err(hsm_err_to_status)?;

        Ok(Response::new(VerifyResponse {
            valid,
            key_id:  req.key_id,
            message: if valid { "valid".into() } else { "invalid".into() },
        }))
    }

    async fn list_keys(
        &self,
        _request: Request<ListKeysRequest>,
    ) -> Result<Response<ListKeysResponse>, Status> {
        let keys = self.state.hsm.list_keys().await.map_err(hsm_err_to_status)?;

        let proto_keys = keys
            .into_iter()
            .map(|k| KeyInfo {
                key_id:            k.id,
                description:       k.description,
                default_algorithm: algorithm_to_proto(k.algorithm),
                status:            if k.enabled { 1 } else { 2 },
                created_at:        String::new(),
                key_type:          k.key_type,
            })
            .collect();

        Ok(Response::new(ListKeysResponse { keys: proto_keys }))
    }

    async fn get_public_key(
        &self,
        request: Request<GetPublicKeyRequest>,
    ) -> Result<Response<GetPublicKeyResponse>, Status> {
        let req = request.into_inner();
        let pk  = self.state.hsm.public_key(&req.key_id).await.map_err(hsm_err_to_status)?;

        Ok(Response::new(GetPublicKeyResponse {
            key_id:         pk.key_id,
            public_key_pem: pk.pem,
            algorithm:      algorithm_to_proto(pk.algorithm),
            key_type:       pk.key_type,
        }))
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let keys_loaded = self.state.hsm.list_keys().await.map(|k| k.len()).unwrap_or(0) as u32;
        Ok(Response::new(HealthResponse {
            status:         1, // SERVING
            hsm_backend:    self.state.hsm.backend_name().to_string(),
            version:        env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: self.start_time.elapsed().as_secs().to_string(),
            keys_loaded,
        }))
    }
}
