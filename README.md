# Signing Gateway

Production-grade cryptographic signing gateway in Rust.  
Private keys **never leave the HSM cluster** — all services call this gateway instead of holding key material.

```
AWS VPC
┌────────────────────────────────────────────────────────────┐
│                                                            │
│  Service A ──┐                                             │
│              │                                             │
│  Service B ──┼──► Signing Gateway ◄──► HSM Cluster        │
│              │    (only node with     private key          │
│  Service C ──┘     PKCS#11 client)    lives here          │
│                         │                                  │
│                         ▼                                  │
│                   returns signature                        │
│                         │                                  │
│          ┌──────────────┼──────────────┐                   │
│          ▼              ▼              ▼                   │
│      Service A      Service B      Service C               │
│      verify with    verify with    verify with             │
│      public key     public key     public key              │
│      (JDK/stdlib)   (JDK/stdlib)   (JDK/stdlib)           │
└────────────────────────────────────────────────────────────┘
```

## Backends

| Backend | Feature flag | Use case |
|---------|-------------|----------|
| **Software** | `software-hsm` (default) | Dev / CI — PEM files on disk |
| **HSM Cluster** | `hsm-cluster` | Production — PKCS#11 to real HSM |

Supported HSM vendors (PKCS#11):

| Vendor | Library path |
|--------|-------------|
| Thales Luna SA / Network HSM | `/usr/lib/libCryptoki2_64.so` |
| Entrust nShield Connect | `/opt/nfast/toolkits/pkcs11/libcknfast.so` |
| AWS CloudHSM (PKCS#11 client) | `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so` |
| Utimaco SecurityServer | `/usr/lib/libcs_pkcs11_R2.so` |
| SoftHSM2 (dev/CI) | `/usr/lib/softhsm/libsofthsm2.so` |

---

## Quick Start

### Dev (software HSM)

```bash
cargo build --release
./target/release/signing-gateway
# Auto-generates keys under /tmp/signing-gateway-keys on first run
```

### Production (HSM cluster)

```bash
cargo build --release --features hsm-cluster

# Edit config.toml:
#   [hsm]
#   backend      = "hsm_cluster"
#   library_path = "/usr/lib/libCryptoki2_64.so"
#   slot_id      = 0          ← HA virtual slot
#   pin          = "..."
#   pool_size    = 16

./target/release/signing-gateway
```

Ports:
- HTTP  → `0.0.0.0:8080`
- gRPC  → `0.0.0.0:50051`
- Prometheus metrics → `0.0.0.0:9090`

---

## HTTP API

### POST /v1/sign

The `payload` field accepts **hex** (recommended), base64, or base64url.  
Pass `"prehashed": true` when sending a pre-computed SHA-256 digest.

```bash
# Sign a raw payload (gateway hashes internally)
curl -X POST http://localhost:8080/v1/sign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer tok-service-a-xxxxxxxx" \
  -d '{
    "caller_id":  "service-a",
    "key_id":     "svc-signing-ec",
    "algorithm":  "ES256",
    "payload":    "'"$(echo -n '{"sub":"user123"}' | openssl dgst -sha256 | awk '{print $2}')"'",
    "prehashed":  true,
    "request_id": "req-001"
  }'
```

> **Auth:** Replace `tok-service-a-xxxxxxxx` with the actual token from `auth.toml` (`[auth.tokens]`).  
> Set `allow_all = true` in `auth.toml` to skip auth in local dev.

Response:
```json
{
  "signature_hex": "3045...",
  "key_id":        "svc-signing-ec",
  "algorithm":     "ES256",
  "signed_at":     "2025-01-01T00:00:00Z",
  "request_id":    "req-001"
}
```

### POST /v1/verify

```bash
curl -X POST http://localhost:8080/v1/verify \
  -H "Content-Type: application/json" \
  -d '{
    "key_id":    "svc-signing-ec",
    "algorithm": "ES256",
    "payload":   "<hex-sha256-of-original-data>",
    "signature": "<signature_hex from sign response>",
    "prehashed": true
  }'
```

### GET /v1/keys/:key_id/public

Returns the PEM public key — services can cache this and verify locally without calling the gateway:

```bash
curl http://localhost:8080/v1/keys/svc-signing-ec/public
```

```json
{
  "key_id":         "svc-signing-ec",
  "pem":            "-----BEGIN PUBLIC KEY-----\n...",
  "algorithm":      "Es256",
  "key_type":       "EC-P256"
}
```

### GET /health

```json
{ "status": "serving", "hsm_backend": "hsm-cluster", "version": "0.1.0" }
```

---

## gRPC API

See [`proto/signing.proto`](proto/signing.proto) for the full service definition.

```protobuf
service SigningService {
  rpc Sign         (SignRequest)         returns (SignResponse);
  rpc Verify       (VerifyRequest)       returns (VerifyResponse);
  rpc ListKeys     (ListKeysRequest)     returns (ListKeysResponse);
  rpc GetPublicKey (GetPublicKeyRequest) returns (GetPublicKeyResponse);
  rpc Health       (HealthRequest)       returns (HealthResponse);
}
```

The gRPC server starts automatically on port `50051` alongside the HTTP server.  
Server reflection is enabled — test with `grpcurl` out of the box:

```bash
# Health check
grpcurl -plaintext localhost:50051 signing.v1.SigningService/Health

# Sign (payload = base64 of raw bytes for grpcurl; use hex in HTTP API)
HASH_B64=$(echo -n '{"sub":"user123"}' | openssl dgst -sha256 | awk '{print $2}' | xxd -r -p | base64)
grpcurl -plaintext \
  -H 'Authorization: Bearer tok-service-a-xxxxxxxx' \
  -d '{
    "caller_id": "service-a",
    "key_id":    "svc-signing-ec",
    "algorithm": "ES256",
    "payload":   "'"$HASH_B64"'",
    "prehashed": true
  }' \
  localhost:50051 signing.v1.SigningService/Sign

# Verify (convert signature_hex → base64 for grpcurl)
# Replace the value below with signature_hex from the Sign response above
SIG_HEX="f553674d..."
SIG_B64=$(echo -n "$SIG_HEX" | xxd -r -p | base64)
grpcurl -plaintext \
  -H 'Authorization: Bearer tok-service-a-xxxxxxxx' \
  -d '{
    "key_id":    "svc-signing-ec",
    "algorithm": "ES256",
    "payload":   "'"$HASH_B64"'",
    "signature": "'"$SIG_B64"'",
    "prehashed": true
  }' \
  localhost:50051 signing.v1.SigningService/Verify

# List keys
grpcurl -plaintext \
  -H 'Authorization: Bearer tok-service-a-xxxxxxxx' \
  -d '{"caller_id": "service-a"}' \
  localhost:50051 signing.v1.SigningService/ListKeys
```

> **Auth:** Replace `tok-service-a-xxxxxxxx` with the actual token from `auth.toml` (`[auth.tokens]`).  
> Set `allow_all = true` in `auth.toml` to skip auth in local dev.

### Key allowlist per caller

In `auth.toml`, restrict each caller to a specific set of keys:

```toml
[auth.allowed_keys]
"service-a" = ["svc-signing-ec", "svc-signing-rsa"]
"service-b" = ["svc-signing-rsa"]
"service-c" = ["jwt-hmac"]
```

- Callers with no entry here may use **any** key.
- Requests for a key outside the allowlist are rejected with `403 Forbidden` (HTTP) or `PERMISSION_DENIED` (gRPC).

### IP allowlist per caller

Restrict each caller to specific source IPs or CIDR ranges:

```toml
[auth.allowed_ips]
"service-a" = ["10.0.1.0/24", "192.168.10.5"]
"service-b" = ["10.0.2.0/24"]
"service-c" = ["10.0.3.0/24"]
```

- Accepts exact IPs (`"192.168.10.5"`) or CIDR ranges (`"10.0.1.0/24"`). IPv4 and IPv6 are both supported.
- Callers with no entry here may connect from **any** IP.
- Requests from a disallowed IP are rejected with `403 Forbidden` (HTTP) or `PERMISSION_DENIED` (gRPC), **after** the bearer token is validated.
- The IP check uses the direct TCP peer address by default. If the gateway sits behind a load balancer or reverse proxy, see **Trusted Proxies** below.

### Trusted proxies (ALB / nginx)

When the gateway runs behind a load balancer, all requests appear to come from the LB's IP. Configure `trusted_proxies` in `config.toml` so the gateway reads the real client IP from `X-Forwarded-For` instead:

```toml
# config.toml
trusted_proxies = ["10.0.0.0/16"]   # your ALB / nginx subnet
```

Resolution logic:

```
peer IP in trusted_proxies?
    YES + X-Forwarded-For present  →  use leftmost IP in X-Forwarded-For
    YES + X-Forwarded-For absent   →  fall back to raw peer IP
    NO                             →  use raw peer IP
```

AWS ALB adds `X-Forwarded-For` automatically — no ALB configuration needed. Just make sure the ALB header mode is not set to `remove`.

---

> **Note:** `grpcurl` requires `bytes` fields to be base64-encoded in JSON input.  
> Native gRPC clients (Rust/Go/Python) send raw bytes directly — no encoding needed.

---

## HSM Cluster — Session Pool

The gateway maintains a pool of `pool_size` PKCS#11 sessions (default 16).  
Each sign/verify request checks out a session, performs the operation, and returns the session.

On transient HSM errors (e.g., momentary cluster failover), the gateway retries up to `retry_attempts` times with `retry_delay_ms` backoff.

For **HA setups**: Luna HA Group and nShield cluster both present a single virtual slot that load-balances across physical HSMs. Just set `slot_id` to that virtual slot — no additional code needed.

```
pool_size = 16 sessions
    ↕ checkout/return (deadpool)
Signing Gateway ──── PKCS#11 ────► Luna HA Virtual Slot
                                        ├─ HSM Node 1
                                        ├─ HSM Node 2
                                        └─ HSM Node 3
```

---

## Preparing HSM Keys (SoftHSM2 example)

```bash
# Initialize token
softhsm2-util --init-token --slot 0 \
  --label "signing-gw" --pin 1234 --so-pin 0000

# Generate EC P-256 key pair
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --keypairgen --key-type EC:prime256v1 \
  --label "svc-signing-ec" --id 01

# Generate RSA-2048 key pair
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --keypairgen --key-type rsa:2048 \
  --label "svc-signing-rsa" --id 02

# List objects to verify
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 --list-objects
```

For **Thales Luna SA**, use `cmu` or `lunacm` tools instead of `pkcs11-tool`.  
For **AWS CloudHSM**, use `key_mgmt_util`.

---

## Production Checklist

- [ ] `[hsm] backend = "hsm_cluster"` with correct `library_path` and `slot_id`
- [ ] Load HSM PIN from AWS Secrets Manager or Vault (not hardcoded)
- [ ] `[auth] allow_all = false` — use mTLS or IRSA
- [ ] TLS on gRPC: set `[server.tls]`
- [ ] `key_dir` chmod 700, service user only (software HSM)
- [ ] `log_format = "json"`, ship to CloudWatch / Datadog
- [ ] Prometheus alert on `signing_gateway_hsm_retries_exhausted_total > 0`
- [ ] Key rotation: add new key → cut over callers → disable old key

---

## Project Structure

```
signing-gateway/
├── Cargo.toml
├── build.rs                   # tonic-build: proto → Rust codegen
├── config.toml
├── proto/signing.proto        # gRPC service definition
└── src/
    ├── main.rs                # startup, router, graceful shutdown
    ├── config.rs              # GatewayConfig, HsmClusterConfig, Algorithm
    ├── hsm/
    │   ├── mod.rs             # HsmBackend trait + factory
    │   ├── software.rs        # PEM file backend (dev/CI)
    │   └── cluster.rs         # PKCS#11 HSM cluster (production)
    ├── http/handlers.rs       # Axum REST handlers
    └── grpc/service.rs        # Tonic gRPC service impl
```
