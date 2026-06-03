//! Software HSM — loads PEM private keys from disk.
//! ⚠️  DEV / TEST ONLY — private keys are in memory.

use super::{compute_digest, HsmBackend, HsmError, HsmResult, KeyInfo, PublicKey, Signature};
use crate::config::{Algorithm, KeyConfig, SoftwareHsmConfig};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

// ─── Stored key ───────────────────────────────────────────────────────────────

#[derive(Clone)]
struct StoredKey {
    info: KeyInfo,
    /// Raw PEM bytes — zeroized on drop via Zeroizing wrapper
    private_pem: Arc<Zeroizing<Vec<u8>>>,
}

// ─── Backend struct ───────────────────────────────────────────────────────────

pub struct SoftwareHsm {
    keys: HashMap<String, StoredKey>,
}

impl SoftwareHsm {
    pub fn new(cfg: &SoftwareHsmConfig, key_configs: &[KeyConfig]) -> anyhow::Result<Self> {
        let mut keys = HashMap::new();

        for kc in key_configs {
            if !kc.enabled {
                warn!(key_id = %kc.id, "Key disabled — skipping load");
                continue;
            }

            let path = format!("{}/{}.pem", cfg.key_dir.trim_end_matches('/'), kc.backend_ref);

            let pem_bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    // If the key file doesn't exist yet, generate one automatically
                    warn!(
                        key_id = %kc.id,
                        path = %path,
                        "Key file not found ({}); generating ephemeral key", e
                    );
                    let generated = generate_key(&kc.algorithm.clone().into())?;
                    std::fs::create_dir_all(&cfg.key_dir)?;
                    std::fs::write(&path, &generated)?;
                    generated
                }
            };

            let algo: Algorithm = kc.algorithm.clone().into();
            let key_type = key_type_label(algo);

            keys.insert(
                kc.id.clone(),
                StoredKey {
                    info: KeyInfo {
                        id: kc.id.clone(),
                        description: kc.description.clone(),
                        algorithm: algo,
                        enabled: kc.enabled,
                        key_type,
                    },
                    private_pem: Arc::new(Zeroizing::new(pem_bytes)),
                },
            );

            debug!(key_id = %kc.id, "Loaded software key");
        }

        Ok(Self { keys })
    }
}

// ─── HsmBackend impl ──────────────────────────────────────────────────────────

#[async_trait]
impl HsmBackend for SoftwareHsm {
    fn backend_name(&self) -> &'static str {
        "software"
    }

    async fn sign(
        &self,
        key_id: &str,
        algorithm: Algorithm,
        payload: &[u8],
        prehashed: bool,
    ) -> HsmResult<Signature> {
        let sk = self.keys.get(key_id).ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;

        if !sk.info.enabled {
            return Err(HsmError::KeyDisabled(key_id.to_string()));
        }

        let msg = if prehashed {
            payload.to_vec()
        } else {
            compute_digest(algorithm, payload)
        };

        let sig = match algorithm {
            Algorithm::Rs256 | Algorithm::Rs384 | Algorithm::Rs512
            | Algorithm::Ps256 | Algorithm::Ps384 | Algorithm::Ps512 => {
                sign_rsa(&sk.private_pem, algorithm, &msg, prehashed, payload)?
            }
            Algorithm::Es256 | Algorithm::Es384 => {
                sign_ecdsa(&sk.private_pem, algorithm, payload, prehashed)?
            }
            Algorithm::Hs256 | Algorithm::Hs384 | Algorithm::Hs512 => {
                sign_hmac(&sk.private_pem, algorithm, payload)?
            }
        };

        Ok(Signature(sig))
    }

    async fn verify(
        &self,
        key_id: &str,
        algorithm: Algorithm,
        payload: &[u8],
        signature: &[u8],
        prehashed: bool,
    ) -> HsmResult<bool> {
        let sk = self.keys.get(key_id).ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;
        let pub_key = derive_public_key_pem(&sk.private_pem, algorithm)?;
        verify_with_public_key(pub_key.as_bytes(), algorithm, payload, signature, prehashed)
    }

    async fn public_key(&self, key_id: &str) -> HsmResult<PublicKey> {
        let sk = self.keys.get(key_id).ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;
        let pem = derive_public_key_pem(&sk.private_pem, sk.info.algorithm)?;
        Ok(PublicKey {
            key_id: key_id.to_string(),
            pem,
            algorithm: sk.info.algorithm,
            key_type: sk.info.key_type.clone(),
        })
    }

    async fn list_keys(&self) -> HsmResult<Vec<KeyInfo>> {
        Ok(self.keys.values().map(|sk| sk.info.clone()).collect())
    }
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────

fn sign_rsa(
    pem: &[u8],
    algorithm: Algorithm,
    _digest_bytes: &[u8],
    _prehashed: bool,
    original_payload: &[u8],
) -> HsmResult<Vec<u8>> {
    let pem_str = std::str::from_utf8(pem)
        .map_err(|e| HsmError::SigningFailed(e.to_string()))?;

    // We re-sign from original payload using ring for full PSS/PKCS1 support
    use ring::rand::SystemRandom;
    use ring::signature::{self, RsaEncoding, RsaKeyPair};

    let der = rsa_pem_to_pkcs8_der(pem_str)?;
    let key_pair = RsaKeyPair::from_pkcs8(&der)
        .map_err(|e| HsmError::SigningFailed(format!("RsaKeyPair: {:?}", e)))?;

    let rng = SystemRandom::new();
    let encoding: &dyn RsaEncoding = match algorithm {
        Algorithm::Rs256 => &signature::RSA_PKCS1_SHA256,
        Algorithm::Rs384 => &signature::RSA_PKCS1_SHA384,
        Algorithm::Rs512 => &signature::RSA_PKCS1_SHA512,
        Algorithm::Ps256 => &signature::RSA_PSS_SHA256,
        Algorithm::Ps384 => &signature::RSA_PSS_SHA384,
        Algorithm::Ps512 => &signature::RSA_PSS_SHA512,
        _ => unreachable!(),
    };

    let mut sig = vec![0u8; key_pair.public().modulus_len()];
    key_pair
        .sign(encoding, &rng, original_payload, &mut sig)
        .map_err(|e| HsmError::SigningFailed(format!("{:?}", e)))?;

    Ok(sig)
}

fn sign_ecdsa(pem: &[u8], algorithm: Algorithm, payload: &[u8], _prehashed: bool) -> HsmResult<Vec<u8>> {
    use ring::rand::SystemRandom;
    use ring::signature::{self, EcdsaKeyPair};

    let pem_str = std::str::from_utf8(pem)
        .map_err(|e| HsmError::SigningFailed(e.to_string()))?;

    let der = ecdsa_pem_to_pkcs8_der(pem_str)?;
    let rng = SystemRandom::new();

    let (_alg, key_pair) = match algorithm {
        Algorithm::Es256 => {
            let kp = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng)
                .map_err(|e| HsmError::SigningFailed(format!("EC P256: {:?}", e)))?;
            (&signature::ECDSA_P256_SHA256_FIXED_SIGNING, kp)
        }
        Algorithm::Es384 => {
            let kp = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P384_SHA384_FIXED_SIGNING, &der, &rng)
                .map_err(|e| HsmError::SigningFailed(format!("EC P384: {:?}", e)))?;
            (&signature::ECDSA_P384_SHA384_FIXED_SIGNING, kp)
        }
        _ => return Err(HsmError::AlgorithmNotSupported {
            key_id: "?".into(),
            algorithm: format!("{}", algorithm),
        }),
    };

    let sig = key_pair
        .sign(&rng, payload)
        .map_err(|e| HsmError::SigningFailed(format!("{:?}", e)))?;

    Ok(sig.as_ref().to_vec())
}

fn sign_hmac(pem: &[u8], algorithm: Algorithm, payload: &[u8]) -> HsmResult<Vec<u8>> {
    use hmac::{Hmac, Mac};
    use sha2::{Sha256, Sha384, Sha512};

    match algorithm {
        Algorithm::Hs256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(pem)
                .map_err(|e| HsmError::SigningFailed(e.to_string()))?;
            mac.update(payload);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        Algorithm::Hs384 => {
            let mut mac = Hmac::<Sha384>::new_from_slice(pem)
                .map_err(|e| HsmError::SigningFailed(e.to_string()))?;
            mac.update(payload);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        Algorithm::Hs512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(pem)
                .map_err(|e| HsmError::SigningFailed(e.to_string()))?;
            mac.update(payload);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        _ => unreachable!(),
    }
}

fn verify_with_public_key(
    pub_pem: &[u8],
    algorithm: Algorithm,
    payload: &[u8],
    signature: &[u8],
    _prehashed: bool,
) -> HsmResult<bool> {
    use ring::signature::{self, UnparsedPublicKey};

    let pem_str = std::str::from_utf8(pub_pem)
        .map_err(|e| HsmError::VerificationFailed(e.to_string()))?;

    let der = spki_pem_to_der(pem_str)?;

    let result = match algorithm {
        Algorithm::Rs256 => {
            UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, &der)
                .verify(payload, signature)
        }
        Algorithm::Rs384 => {
            UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA384, &der)
                .verify(payload, signature)
        }
        Algorithm::Rs512 => {
            UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA512, &der)
                .verify(payload, signature)
        }
        Algorithm::Ps256 => {
            UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA256, &der)
                .verify(payload, signature)
        }
        Algorithm::Ps384 => {
            UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA384, &der)
                .verify(payload, signature)
        }
        Algorithm::Ps512 => {
            UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA512, &der)
                .verify(payload, signature)
        }
        Algorithm::Es256 => {
            use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            use p256::pkcs8::DecodePublicKey;
            let pem_str = std::str::from_utf8(pub_pem)
                .map_err(|e| HsmError::VerificationFailed(e.to_string()))?;
            let vk = VerifyingKey::from_public_key_pem(pem_str)
                .map_err(|e| HsmError::VerificationFailed(format!("key: {}", e)))?;
            let sig = Signature::from_slice(signature)
                .map_err(|e| HsmError::VerificationFailed(format!("sig: {}", e)))?;
            return Ok(vk.verify(payload, &sig).is_ok());
        }
        Algorithm::Es384 => {
            use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            use p384::pkcs8::DecodePublicKey;
            let pem_str = std::str::from_utf8(pub_pem)
                .map_err(|e| HsmError::VerificationFailed(e.to_string()))?;
            let vk = VerifyingKey::from_public_key_pem(pem_str)
                .map_err(|e| HsmError::VerificationFailed(format!("key: {}", e)))?;
            let sig = Signature::from_slice(signature)
                .map_err(|e| HsmError::VerificationFailed(format!("sig: {}", e)))?;
            return Ok(vk.verify(payload, &sig).is_ok());
        }
        Algorithm::Hs256 | Algorithm::Hs384 | Algorithm::Hs512 => {
            // HMAC verify: re-sign and constant-time compare
            return Err(HsmError::VerificationFailed(
                "HMAC verify requires the secret key — use the /verify endpoint instead".into(),
            ));
        }
    };

    Ok(result.is_ok())
}

// ─── PEM/DER utilities ────────────────────────────────────────────────────────

fn rsa_pem_to_pkcs8_der(pem: &str) -> HsmResult<Vec<u8>> {
    use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
    let key = rsa::RsaPrivateKey::from_pkcs8_pem(pem)
        .map_err(|e| HsmError::SigningFailed(format!("RSA PEM decode: {}", e)))?;
    let der = key
        .to_pkcs8_der()
        .map_err(|e| HsmError::SigningFailed(format!("RSA DER encode: {}", e)))?;
    Ok(der.as_bytes().to_vec())
}

fn ecdsa_pem_to_pkcs8_der(pem: &str) -> HsmResult<Vec<u8>> {
    // Strip PEM headers and base64-decode
    let lines: Vec<&str> = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let b64: String = lines.join("");
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| HsmError::SigningFailed(format!("ECDSA DER decode: {}", e)))
}

use base64::Engine;
fn spki_pem_to_der(pem: &str) -> HsmResult<Vec<u8>> {
    let lines: Vec<&str> = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let b64: String = lines.join("");
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| HsmError::VerificationFailed(format!("SPKI decode: {}", e)))
}

fn derive_public_key_pem(private_pem: &[u8], algorithm: Algorithm) -> HsmResult<String> {
    let pem_str = std::str::from_utf8(private_pem)
        .map_err(|e| HsmError::BackendError(e.to_string()))?;

    match algorithm {
        Algorithm::Rs256
        | Algorithm::Rs384
        | Algorithm::Rs512
        | Algorithm::Ps256
        | Algorithm::Ps384
        | Algorithm::Ps512 => {
            use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
            let key = rsa::RsaPrivateKey::from_pkcs8_pem(pem_str)
                .map_err(|e| HsmError::BackendError(e.to_string()))?;
            key.to_public_key()
                .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
                .map_err(|e| HsmError::BackendError(e.to_string()))
        }
        Algorithm::Es256 => {
            use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};
            let key = p256::ecdsa::SigningKey::from_pkcs8_pem(pem_str)
                .map_err(|e| HsmError::BackendError(e.to_string()))?;
            key.verifying_key()
                .to_public_key_pem(p256::pkcs8::LineEnding::LF)
                .map_err(|e| HsmError::BackendError(e.to_string()))
        }
        Algorithm::Es384 => {
            use p384::pkcs8::{DecodePrivateKey, EncodePublicKey};
            let key = p384::ecdsa::SigningKey::from_pkcs8_pem(pem_str)
                .map_err(|e| HsmError::BackendError(e.to_string()))?;
            key.verifying_key()
                .to_public_key_pem(p384::pkcs8::LineEnding::LF)
                .map_err(|e| HsmError::BackendError(e.to_string()))
        }
        Algorithm::Hs256 | Algorithm::Hs384 | Algorithm::Hs512 => {
            // HMAC: "public key" is just the raw secret in PEM wrapper
            Ok(format!(
                "-----BEGIN SYMMETRIC KEY-----\n{}\n-----END SYMMETRIC KEY-----\n",
                base64::engine::general_purpose::STANDARD.encode(private_pem)
            ))
        }
    }
}

fn generate_key(algorithm: &Algorithm) -> anyhow::Result<Vec<u8>> {
    match algorithm {
        Algorithm::Rs256
        | Algorithm::Rs384
        | Algorithm::Rs512
        | Algorithm::Ps256
        | Algorithm::Ps384
        | Algorithm::Ps512 => {
            use rsa::pkcs8::EncodePrivateKey;
            let mut rng = rand::thread_rng();
            let key = rsa::RsaPrivateKey::new(&mut rng, 2048)?;
            let pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?;
            Ok(pem.as_bytes().to_vec())
        }
        Algorithm::Es256 => {
            use p256::pkcs8::EncodePrivateKey;
            let key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
            let pem = key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF)?;
            Ok(pem.as_bytes().to_vec())
        }
        Algorithm::Es384 => {
            use p384::pkcs8::EncodePrivateKey;
            let key = p384::ecdsa::SigningKey::random(&mut rand::thread_rng());
            let pem = key.to_pkcs8_pem(p384::pkcs8::LineEnding::LF)?;
            Ok(pem.as_bytes().to_vec())
        }
        Algorithm::Hs256 => Ok(rand_bytes(32)),
        Algorithm::Hs384 => Ok(rand_bytes(48)),
        Algorithm::Hs512 => Ok(rand_bytes(64)),
    }
}

fn rand_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

fn key_type_label(algorithm: Algorithm) -> String {
    match algorithm {
        Algorithm::Rs256 | Algorithm::Ps256 => "RSA-2048",
        Algorithm::Rs384 | Algorithm::Ps384 => "RSA-3072",
        Algorithm::Rs512 | Algorithm::Ps512 => "RSA-4096",
        Algorithm::Es256 => "EC-P256",
        Algorithm::Es384 => "EC-P384",
        Algorithm::Hs256 => "HMAC-256",
        Algorithm::Hs384 => "HMAC-384",
        Algorithm::Hs512 => "HMAC-512",
    }
    .to_string()
}
