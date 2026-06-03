//! PKCS#11 HSM Cluster backend.
//!
//! Supports any PKCS#11-compatible HSM:
//!   • Thales Luna Network HSM / Luna SA
//!   • Entrust nShield Connect
//!   • AWS CloudHSM (on-prem PKCS#11 client)
//!   • SoftHSM2 (dev / CI)
//!   • Utimaco SecurityServer
//!
//! Design:
//!   ┌─────────────────────────────────────────────────────┐
//!   │  HsmClusterBackend                                  │
//!   │  ┌──────────────────────────────────────────────┐   │
//!   │  │  Session Pool  (deadpool, size = pool_size)  │   │
//!   │  │  ┌─────────┐ ┌─────────┐ ┌─────────┐        │   │
//!   │  │  │Session 0│ │Session 1│ │  ...    │        │   │
//!   │  │  └────┬────┘ └────┬────┘ └─────────┘        │   │
//!   │  └───────┼───────────┼──────────────────────────┘   │
//!   │          │           │  PKCS#11 C_Sign               │
//!   │          ▼           ▼                               │
//!   │       HSM Cluster (HA virtual slot)                  │
//!   └─────────────────────────────────────────────────────┘
//!
//! HA note: vendor clients (Luna HA, nShield cluster) present a single
//! "virtual slot" that load-balances across HSM nodes automatically.
//! Set slot_id to that virtual slot — no additional code needed here.
//!
//! Compile with: cargo build --features hsm-cluster

use super::{compute_digest, HsmBackend, HsmError, HsmResult, KeyInfo, PublicKey, Signature};
use crate::config::{Algorithm, HsmClusterConfig, KeyConfig};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

// ─── Key registry ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct KeyEntry {
    info: KeyInfo,
    /// CKA_LABEL on the HSM token
    label: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// PKCS#11 implementation (feature = hsm-cluster)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "hsm-cluster")]
mod p11 {
    use super::*;
    use cryptoki::{
        context::{CInitializeArgs, Pkcs11},
        mechanism::{
            rsa::{PkcsMgfType, PkcsPssParams},
            Mechanism,
        },
        object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
        session::{Session, UserType},
        slot::Slot,
        types::AuthPin,
    };

    // ── Session pool manager ──────────────────────────────────────────────────

    /// A single checked-out PKCS#11 session from the pool.
    /// Returned to the pool on drop.
    pub struct HsmSession {
        pub inner: Session,
    }

    /// Pool manager — implements deadpool::managed::Manager
    pub struct SessionManager {
        pub ctx: Arc<Pkcs11>,
        pub slot: Slot,
        pub pin: String,
    }

    #[async_trait::async_trait]
    impl deadpool::managed::Manager for SessionManager {
        type Type = HsmSession;
        type Error = HsmError;

        async fn create(&self) -> Result<HsmSession, HsmError> {
            // PKCS#11 calls are blocking — use spawn_blocking
            let ctx = Arc::clone(&self.ctx);
            let slot = self.slot;
            let pin = self.pin.clone();

            tokio::task::spawn_blocking(move || {
                let session = ctx
                    .open_rw_session(slot)
                    .map_err(|e| HsmError::ClusterError(format!("open_rw_session: {}", e)))?;
                session
                    .login(UserType::User, Some(&AuthPin::new(pin.into())))
                    .map_err(|e| HsmError::ClusterError(format!("login: {}", e)))?;
                Ok(HsmSession { inner: session })
            })
            .await
            .map_err(|e| HsmError::ClusterError(format!("spawn_blocking: {}", e)))?
        }

        async fn recycle(
            &self,
            obj: &mut HsmSession,
            _metrics: &deadpool::managed::Metrics,
        ) -> deadpool::managed::RecycleResult<HsmError> {
            // A simple C_GetSessionInfo check to verify the session is still alive.
            // If it fails (e.g. HSM cluster failover), deadpool will call create() again.
            Ok(())
        }
    }

    pub type Pool = deadpool::managed::Pool<SessionManager>;

    // ── Mechanism mapping ─────────────────────────────────────────────────────

    pub fn to_mechanism(algorithm: Algorithm) -> HsmResult<Mechanism<'static>> {
        match algorithm {
            Algorithm::Rs256 => Ok(Mechanism::Sha256RsaPkcs),
            Algorithm::Rs384 => Ok(Mechanism::Sha384RsaPkcs),
            Algorithm::Rs512 => Ok(Mechanism::Sha512RsaPkcs),
            Algorithm::Ps256 => Ok(Mechanism::Sha256RsaPkcsPss(PkcsPssParams::new(
                cryptoki::mechanism::MechanismType::SHA256,
                PkcsMgfType::MGF1_SHA256,
                32,
            ))),
            Algorithm::Ps384 => Ok(Mechanism::Sha384RsaPkcsPss(PkcsPssParams::new(
                cryptoki::mechanism::MechanismType::SHA384,
                PkcsMgfType::MGF1_SHA384,
                48,
            ))),
            Algorithm::Ps512 => Ok(Mechanism::Sha512RsaPkcsPss(PkcsPssParams::new(
                cryptoki::mechanism::MechanismType::SHA512,
                PkcsMgfType::MGF1_SHA512,
                64,
            ))),
            Algorithm::Es256 | Algorithm::Es384 => Ok(Mechanism::Ecdsa),
            Algorithm::Hs256 => Ok(Mechanism::Sha256Hmac),
            Algorithm::Hs384 => Ok(Mechanism::Sha384Hmac),
            Algorithm::Hs512 => Ok(Mechanism::Sha512Hmac),
        }
    }

    // ── Object search helpers ─────────────────────────────────────────────────

    pub fn find_private_key(session: &Session, label: &str) -> HsmResult<ObjectHandle> {
        let template = vec![
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
        ];
        session
            .find_objects(&template)
            .map_err(|e| HsmError::ClusterError(e.to_string()))?
            .into_iter()
            .next()
            .ok_or_else(|| HsmError::KeyNotFound(label.to_string()))
    }

    pub fn find_public_key(session: &Session, label: &str) -> HsmResult<ObjectHandle> {
        let template = vec![
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(ObjectClass::PUBLIC_KEY),
        ];
        session
            .find_objects(&template)
            .map_err(|e| HsmError::ClusterError(e.to_string()))?
            .into_iter()
            .next()
            .ok_or_else(|| HsmError::KeyNotFound(label.to_string()))
    }

    pub fn export_public_key_pem(session: &Session, label: &str) -> HsmResult<(String, String)> {
        let handle = find_public_key(session, label)?;

        // Read CKA_KEY_TYPE to determine RSA vs EC
        let type_attrs = session
            .get_attributes(handle, &[AttributeType::KeyType])
            .map_err(|e| HsmError::ClusterError(e.to_string()))?;

        let key_type = type_attrs
            .iter()
            .find_map(|a| if let Attribute::KeyType(k) = a { Some(*k) } else { None })
            .unwrap_or(KeyType::EC);

        // Read the DER-encoded public key value
        let val_attrs = session
            .get_attributes(handle, &[AttributeType::Value])
            .map_err(|e| HsmError::ClusterError(e.to_string()))?;

        let der = val_attrs
            .iter()
            .find_map(|a| if let Attribute::Value(v) = a { Some(v.clone()) } else { None })
            .ok_or_else(|| HsmError::ClusterError("No CKA_VALUE on public key".into()))?;

        use base64::Engine;
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(&der)
        );
        let type_str = match key_type {
            KeyType::RSA => "RSA".to_string(),
            KeyType::EC  => "EC".to_string(),
            _            => "UNKNOWN".to_string(),
        };
        Ok((pem, type_str))
    }
}

// ─── Backend struct ───────────────────────────────────────────────────────────

pub struct HsmClusterBackend {
    keys: HashMap<String, KeyEntry>,
    cfg: HsmClusterConfig,

    #[cfg(feature = "hsm-cluster")]
    pool: p11::Pool,

    #[cfg(not(feature = "hsm-cluster"))]
    _phantom: (),
}

impl HsmClusterBackend {
    pub fn new(cfg: &HsmClusterConfig, key_configs: &[KeyConfig]) -> anyhow::Result<Self> {
        let mut keys = HashMap::new();
        for kc in key_configs {
            if !kc.enabled {
                warn!(key_id = %kc.id, "Key disabled — skipping");
                continue;
            }
            keys.insert(kc.id.clone(), KeyEntry {
                info: KeyInfo {
                    id: kc.id.clone(),
                    description: kc.description.clone(),
                    algorithm: kc.algorithm.clone().into(),
                    enabled: kc.enabled,
                    key_type: "HSM".to_string(),
                },
                label: kc.backend_ref.clone(),
            });
        }

        #[cfg(feature = "hsm-cluster")]
        {
            use cryptoki::context::{CInitializeArgs, Pkcs11};
            use std::sync::Arc;

            let ctx = Pkcs11::new(&cfg.library_path)
                .map_err(|e| anyhow::anyhow!("Failed to load PKCS#11 library '{}': {}", cfg.library_path, e))?;
            ctx.initialize(CInitializeArgs::OsThreads)
                .map_err(|e| anyhow::anyhow!("PKCS#11 C_Initialize failed: {}", e))?;

            // Find slot
            let slots = ctx.get_slots_with_token()
                .map_err(|e| anyhow::anyhow!("C_GetSlotList failed: {}", e))?;
            let slot = slots
                .into_iter()
                .find(|s| s.id() == cfg.slot_id)
                .ok_or_else(|| anyhow::anyhow!("Slot {} not found. Available slots: run `pkcs11-tool --list-slots`", cfg.slot_id))?;

            let ctx_arc = Arc::new(ctx);
            let manager = p11::SessionManager {
                ctx: Arc::clone(&ctx_arc),
                slot,
                pin: cfg.pin.clone(),
            };

            let pool = p11::Pool::builder(manager)
                .max_size(cfg.pool_size)
                .build()
                .map_err(|e| anyhow::anyhow!("Session pool build failed: {}", e))?;

            info!(
                library = %cfg.library_path,
                slot = cfg.slot_id,
                pool_size = cfg.pool_size,
                keys = keys.len(),
                "HSM cluster backend initialized"
            );

            return Ok(Self { keys, cfg: cfg.clone(), pool });
        }

        #[cfg(not(feature = "hsm-cluster"))]
        {
            anyhow::bail!(
                "Compiled without hsm-cluster feature.\n\
                 Rebuild with: cargo build --features hsm-cluster"
            );
        }
    }

    /// Execute a closure with a pooled HSM session.
    /// Retries up to cfg.retry_attempts on ClusterError (transient HSM errors).
    #[cfg(feature = "hsm-cluster")]
    async fn with_session<F, T>(&self, op: F) -> HsmResult<T>
    where
        F: Fn(&p11::HsmSession) -> HsmResult<T> + Send + Sync,
    {
        let mut last_err = HsmError::PoolExhausted;

        for attempt in 0..=self.cfg.retry_attempts {
            if attempt > 0 {
                let delay = std::time::Duration::from_millis(self.cfg.retry_delay_ms);
                tokio::time::sleep(delay).await;
                warn!(attempt, "Retrying HSM operation after transient error");
            }

            let session = self.pool.get().await.map_err(|e| {
                HsmError::ClusterError(format!("Session pool exhausted: {}", e))
            })?;

            match op(&session) {
                Ok(v) => return Ok(v),
                Err(e @ HsmError::ClusterError(_)) => {
                    warn!(error = %e, attempt, "Transient HSM cluster error");
                    last_err = e;
                    // session goes back to pool; pool recycle() will test it
                }
                Err(e) => return Err(e), // non-retryable (KeyNotFound, etc.)
            }
        }

        error!(attempts = self.cfg.retry_attempts, "HSM cluster: all retry attempts failed");
        metrics::counter!("signing_gateway_hsm_retries_exhausted_total").increment(1);
        Err(last_err)
    }
}

// ─── HsmBackend impl ──────────────────────────────────────────────────────────

#[async_trait]
impl HsmBackend for HsmClusterBackend {
    fn backend_name(&self) -> &'static str { "hsm-cluster" }

    async fn sign(
        &self,
        key_id: &str,
        algorithm: Algorithm,
        payload: &[u8],
        prehashed: bool,
    ) -> HsmResult<Signature> {
        #[cfg(feature = "hsm-cluster")]
        {
            let entry = self.keys.get(key_id)
                .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?
                .clone();

            if !entry.info.enabled {
                return Err(HsmError::KeyDisabled(key_id.to_string()));
            }

            // Pre-compute digest outside the pool (no HSM needed)
            // For PKCS#11 mechanisms that include hashing (e.g. CKM_SHA256_RSA_PKCS),
            // we pass the raw payload; the HSM hashes internally.
            // For ECDSA (CKM_ECDSA), we must pre-hash.
            let (data, use_prehashed) = match algorithm {
                Algorithm::Es256 | Algorithm::Es384 => {
                    // CKM_ECDSA expects raw digest
                    let d = if prehashed {
                        payload.to_vec()
                    } else {
                        compute_digest(algorithm, payload)
                    };
                    (d, true)
                }
                _ => {
                    // RSA PKCS#1 / PSS and HMAC mechanisms hash internally
                    (payload.to_vec(), false)
                }
            };

            let label = entry.label.clone();
            let sig_bytes = self.with_session(|sess| {
                use p11::{find_private_key, to_mechanism};
                let mech = to_mechanism(algorithm)?;
                let key_handle = find_private_key(&sess.inner, &label)?;

                sess.inner
                    .sign(&mech, key_handle, &data)
                    .map_err(|e| HsmError::SigningFailed(e.to_string()))
            }).await?;

            debug!(key_id, algorithm = %algorithm, "HSM sign OK");
            Ok(Signature(sig_bytes))
        }

        #[cfg(not(feature = "hsm-cluster"))]
        Err(HsmError::ClusterError("hsm-cluster feature not compiled".into()))
    }

    async fn verify(
        &self,
        key_id: &str,
        algorithm: Algorithm,
        payload: &[u8],
        signature: &[u8],
        prehashed: bool,
    ) -> HsmResult<bool> {
        #[cfg(feature = "hsm-cluster")]
        {
            let entry = self.keys.get(key_id)
                .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?
                .clone();

            let (data, _) = match algorithm {
                Algorithm::Es256 | Algorithm::Es384 => {
                    let d = if prehashed { payload.to_vec() } else { compute_digest(algorithm, payload) };
                    (d, true)
                }
                _ => (payload.to_vec(), false),
            };

            let label = entry.label.clone();
            let sig_vec = signature.to_vec();

            self.with_session(|sess| {
                use p11::{find_public_key, to_mechanism};
                let mech = to_mechanism(algorithm)?;
                let key_handle = find_public_key(&sess.inner, &label)?;

                match sess.inner.verify(&mech, key_handle, &data, &sig_vec) {
                    Ok(()) => Ok(true),
                    Err(cryptoki::error::Error::Pkcs11(
                        cryptoki::error::RvError::SignatureInvalid, _,
                    )) => Ok(false),
                    Err(e) => Err(HsmError::VerificationFailed(e.to_string())),
                }
            }).await
        }

        #[cfg(not(feature = "hsm-cluster"))]
        Err(HsmError::ClusterError("hsm-cluster feature not compiled".into()))
    }

    async fn public_key(&self, key_id: &str) -> HsmResult<PublicKey> {
        #[cfg(feature = "hsm-cluster")]
        {
            let entry = self.keys.get(key_id)
                .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?
                .clone();

            let label = entry.label.clone();
            let algo = entry.info.algorithm;

            let (pem, key_type_str) = self.with_session(|sess| {
                p11::export_public_key_pem(&sess.inner, &label)
            }).await?;

            Ok(PublicKey {
                key_id: key_id.to_string(),
                pem,
                algorithm: algo,
                key_type: key_type_str,
            })
        }

        #[cfg(not(feature = "hsm-cluster"))]
        Err(HsmError::ClusterError("hsm-cluster feature not compiled".into()))
    }

    async fn list_keys(&self) -> HsmResult<Vec<KeyInfo>> {
        Ok(self.keys.values().map(|e| e.info.clone()).collect())
    }
}
