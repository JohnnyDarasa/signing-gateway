use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level gateway configuration
#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub server: ServerConfig,
    pub hsm: HsmConfig,
    pub keys: Vec<KeyConfig>,
    pub auth: AuthConfig,
    pub observability: ObservabilityConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// HTTP bind address — e.g. "0.0.0.0:8080"
    pub http_addr: String,
    /// gRPC bind address — e.g. "0.0.0.0:50051"
    pub grpc_addr: String,
    pub tls: Option<TlsConfig>,
    pub shutdown_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert_pem_path: String,
    pub key_pem_path: String,
    /// CA cert for mutual TLS
    pub ca_pem_path: Option<String>,
}

// ─── HSM config ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "backend", rename_all = "snake_case")]
pub enum HsmConfig {
    /// In-process software keys — DEV / TEST only, never production
    Software(SoftwareHsmConfig),
    /// PKCS#11 HSM cluster (Thales Luna SA, Entrust nShield Connect,
    /// AWS CloudHSM on-prem client, SoftHSM2)
    HsmCluster(HsmClusterConfig),
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SoftwareHsmConfig {
    /// Directory to read PEM private keys from (chmod 700)
    pub key_dir: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct HsmClusterConfig {
    /// Path to the vendor PKCS#11 shared library
    /// Examples:
    ///   Thales Luna SA    → /usr/lib/libCryptoki2_64.so
    ///   Entrust nShield   → /opt/nfast/toolkits/pkcs11/libcknfast.so
    ///   AWS CloudHSM      → /opt/cloudhsm/lib/libcloudhsm_pkcs11.so
    ///   SoftHSM2 (dev)    → /usr/lib/softhsm/libsofthsm2.so
    pub library_path: String,

    /// PKCS#11 slot index (or slot ID) to use.
    /// For HA setups: use the HA virtual slot provided by the vendor client.
    pub slot_id: u64,

    /// Crypto Officer / User PIN
    /// In production: load from AWS Secrets Manager or Vault, not config file.
    pub pin: String,

    /// Session pool size — how many concurrent PKCS#11 sessions to maintain.
    /// HSM vendors typically allow 16–256 sessions per slot.
    /// Default: 8
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,

    /// Max retry attempts on transient HSM errors before returning failure.
    /// Default: 3
    #[serde(default = "default_retry_attempts")]
    pub retry_attempts: u32,

    /// Delay between retries in milliseconds. Default: 200
    #[serde(default = "default_retry_delay_ms")]
    pub retry_delay_ms: u64,

    /// Login mode:
    ///   "user"   → CKU_USER  (normal signing operations)
    ///   "so"     → CKU_SO    (Security Officer, key management only)
    #[serde(default = "default_login_mode")]
    pub login_mode: String,
}

fn default_pool_size() -> usize { 8 }
fn default_retry_attempts() -> u32 { 3 }
fn default_retry_delay_ms() -> u64 { 200 }
fn default_login_mode() -> String { "user".to_string() }

// ─── Key config ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct KeyConfig {
    /// Logical key ID used by callers — e.g. "service-signing-ec"
    pub id: String,
    pub description: String,

    /// Backend reference:
    ///   software   → filename stem under key_dir (e.g. "service-ec" → service-ec.pem)
    ///   hsm_cluster → CKA_LABEL of the key on the HSM token
    pub backend_ref: String,

    pub algorithm: AlgorithmConfig,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AlgorithmConfig {
    Rs256, Rs384, Rs512,
    Ps256, Ps384, Ps512,
    Es256, Es384,
    Hs256, Hs384, Hs512,
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    /// Static bearer tokens → caller_id mapping.
    /// Production: replace with mTLS client cert CN or IRSA.
    pub tokens: HashMap<String, String>,
    /// DEV only — accept any caller_id without a token
    pub allow_all: bool,
    /// Per-caller key allowlist: caller_id → list of permitted key IDs.
    /// If a caller has no entry here, all keys are accessible.
    #[serde(default)]
    pub allowed_keys: HashMap<String, Vec<String>>,
}

// ─── Observability ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct ObservabilityConfig {
    pub log_format: LogFormat,
    pub log_level: String,
    pub metrics_addr: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat { Pretty, Json }

// ─── Load ─────────────────────────────────────────────────────────────────────

impl GatewayConfig {
    pub fn load() -> anyhow::Result<Self> {
        let cfg = config::Config::builder()
            .add_source(config::File::with_name("config").required(false))
            .add_source(config::File::with_name("keys").required(false))
            .add_source(config::Environment::with_prefix("SGW").separator("__"))
            .build()?;
        Ok(cfg.try_deserialize()?)
    }
}

// ─── Runtime Algorithm enum ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Algorithm {
    Rs256, Rs384, Rs512,
    Ps256, Ps384, Ps512,
    Es256, Es384,
    Hs256, Hs384, Hs512,
}

impl From<AlgorithmConfig> for Algorithm {
    fn from(a: AlgorithmConfig) -> Self {
        match a {
            AlgorithmConfig::Rs256 => Algorithm::Rs256,
            AlgorithmConfig::Rs384 => Algorithm::Rs384,
            AlgorithmConfig::Rs512 => Algorithm::Rs512,
            AlgorithmConfig::Ps256 => Algorithm::Ps256,
            AlgorithmConfig::Ps384 => Algorithm::Ps384,
            AlgorithmConfig::Ps512 => Algorithm::Ps512,
            AlgorithmConfig::Es256 => Algorithm::Es256,
            AlgorithmConfig::Es384 => Algorithm::Es384,
            AlgorithmConfig::Hs256 => Algorithm::Hs256,
            AlgorithmConfig::Hs384 => Algorithm::Hs384,
            AlgorithmConfig::Hs512 => Algorithm::Hs512,
        }
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Algorithm::Rs256 => "RS256", Algorithm::Rs384 => "RS384", Algorithm::Rs512 => "RS512",
            Algorithm::Ps256 => "PS256", Algorithm::Ps384 => "PS384", Algorithm::Ps512 => "PS512",
            Algorithm::Es256 => "ES256", Algorithm::Es384 => "ES384",
            Algorithm::Hs256 => "HS256", Algorithm::Hs384 => "HS384", Algorithm::Hs512 => "HS512",
        };
        write!(f, "{}", s)
    }
}
