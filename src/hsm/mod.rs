pub mod cluster;
pub mod software;

use crate::config::{Algorithm, KeyConfig};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum HsmError {
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Key disabled: {0}")]
    KeyDisabled(String),
    #[error("Algorithm not supported for key '{key_id}': {algorithm}")]
    AlgorithmNotSupported { key_id: String, algorithm: String },
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("HSM cluster error: {0}")]
    ClusterError(String),
    #[error("HSM session pool exhausted")]
    PoolExhausted,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Config error: {0}")]
    Config(String),
    #[error("Backend error: {0}")]
    BackendError(String),
}

pub type HsmResult<T> = Result<T, HsmError>;

// ─── Core types ───────────────────────────────────────────────────────────────

/// Signature bytes — zeroized when dropped
#[derive(Debug, Clone, Zeroize)]
pub struct Signature(pub Vec<u8>);
impl Drop for Signature {
    fn drop(&mut self) { self.0.zeroize(); }
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicKey {
    pub key_id: String,
    pub pem: String,
    pub algorithm: Algorithm,
    pub key_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    pub id: String,
    pub description: String,
    pub algorithm: Algorithm,
    pub enabled: bool,
    pub key_type: String,
}

// ─── Trait ────────────────────────────────────────────────────────────────────

#[async_trait]
pub trait HsmBackend: Send + Sync {
    async fn sign(
        &self,
        key_id: &str,
        algorithm: Algorithm,
        payload: &[u8],
        prehashed: bool,
    ) -> HsmResult<Signature>;

    async fn verify(
        &self,
        key_id: &str,
        algorithm: Algorithm,
        payload: &[u8],
        signature: &[u8],
        prehashed: bool,
    ) -> HsmResult<bool>;

    async fn public_key(&self, key_id: &str) -> HsmResult<PublicKey>;
    async fn list_keys(&self) -> HsmResult<Vec<KeyInfo>>;
    fn backend_name(&self) -> &'static str;
}

// ─── Factory ─────────────────────────────────────────────────────────────────

use crate::config::HsmConfig;
use std::sync::Arc;

pub async fn create_backend(
    cfg: &HsmConfig,
    keys: &[KeyConfig],
) -> anyhow::Result<Arc<dyn HsmBackend>> {
    match cfg {
        HsmConfig::Software(sw) => {
            let b = software::SoftwareHsm::new(sw, keys)?;
            Ok(Arc::new(b))
        }
        HsmConfig::HsmCluster(hc) => {
            let b = cluster::HsmClusterBackend::new(hc, keys)?;
            Ok(Arc::new(b))
        }
    }
}

// ─── Digest helper ────────────────────────────────────────────────────────────

use sha2::{Digest, Sha256, Sha384, Sha512};

pub fn compute_digest(algorithm: Algorithm, payload: &[u8]) -> Vec<u8> {
    match algorithm {
        Algorithm::Rs256 | Algorithm::Ps256 | Algorithm::Es256 | Algorithm::Hs256
            => Sha256::digest(payload).to_vec(),
        Algorithm::Rs384 | Algorithm::Ps384 | Algorithm::Es384 | Algorithm::Hs384
            => Sha384::digest(payload).to_vec(),
        Algorithm::Rs512 | Algorithm::Ps512 | Algorithm::Hs512
            => Sha512::digest(payload).to_vec(),
    }
}
