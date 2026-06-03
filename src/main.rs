//! Signing Gateway — entry point.
//!
//! Starts two servers concurrently:
//!   • Axum  HTTP  on config.server.http_addr  (default 0.0.0.0:8080)
//!   • Tonic gRPC  on config.server.grpc_addr  (default 0.0.0.0:50051)
//!
//! Both share a single Arc<AppState> wrapping the HSM backend.

mod config;
mod grpc;
mod hsm;
mod http;

use crate::{
    config::{AuthConfig, GatewayConfig},
    grpc::{
        proto::signing_service_server::SigningServiceServer,
        service::SigningGatewayService,
    },
    http::handlers::*,
    hsm::HsmBackend,
};
use tonic_reflection::server::Builder as ReflectionBuilder;
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::{Arc, RwLock};
use tokio::signal;
use tower_http::{cors::{Any, CorsLayer}, trace::TraceLayer};
use tracing::{info, warn};
use toml;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

// ─── Shared application state ─────────────────────────────────────────────────

pub struct AppState {
    pub config: GatewayConfig,
    /// Hot-reloadable auth config (updated when keys.toml changes)
    pub auth: Arc<RwLock<AuthConfig>>,
    pub hsm: Arc<dyn HsmBackend>,
    pub start_time: std::time::Instant,
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load config (config.toml + SGW__* env vars)
    let cfg = GatewayConfig::load().unwrap_or_else(|_| {
        warn!("config.toml not found — using built-in dev defaults");
        default_config()
    });

    // Init tracing
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&cfg.observability.log_level));
    match cfg.observability.log_format {
        config::LogFormat::Json => {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        }
        config::LogFormat::Pretty => {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer().pretty())
                .init();
        }
    }

    info!(
        version    = env!("CARGO_PKG_VERSION"),
        http_addr  = %cfg.server.http_addr,
        grpc_addr  = %cfg.server.grpc_addr,
        "Signing Gateway starting"
    );

    // Init Prometheus metrics
    if let Some(metrics_addr) = &cfg.observability.metrics_addr {
        let addr: std::net::SocketAddr = metrics_addr.parse()?;
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .with_http_listener(addr)
            .install()?;
        info!(addr = %metrics_addr, "Prometheus metrics endpoint ready");
    }

    // Init HSM backend
    let hsm_backend = hsm::create_backend(&cfg.hsm, &cfg.keys).await?;
    info!(backend = %hsm_backend.backend_name(), "HSM backend ready");

    let auth = Arc::new(RwLock::new(cfg.auth.clone()));

    let state = Arc::new(AppState {
        config: cfg.clone(),
        auth: Arc::clone(&auth),
        hsm: hsm_backend,
        start_time: std::time::Instant::now(),
    });

    // ── Hot-reload watcher for keys.toml ──────────────────────────────────────
    {
        use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
        use std::time::Duration;

        let hsm_ref  = Arc::clone(&state.hsm);
        let auth_ref = Arc::clone(&auth);

        let (tx, mut rx) = tokio::sync::mpsc::channel(4);

        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<notify::Event>| {
                if let Ok(event) = res {
                    if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                        let _ = tx.blocking_send(());
                    }
                }
            },
            Config::default().with_poll_interval(Duration::from_secs(1)),
        )?;

        watcher.watch(std::path::Path::new("keys.toml"), RecursiveMode::NonRecursive)?;

        tokio::spawn(async move {
            // Keep watcher alive in this task
            let _watcher = watcher;
            while rx.recv().await.is_some() {
                // Debounce — ignore rapid duplicate events
                tokio::time::sleep(Duration::from_millis(200)).await;
                while rx.try_recv().is_ok() {}

                match load_keys_file() {
                    Ok((keys, new_auth)) => {
                        if let Err(e) = hsm_ref.reload_keys(&keys).await {
                            warn!(error = %e, "Failed to reload keys");
                        }
                        *auth_ref.write().unwrap() = new_auth;
                        info!("keys.toml reloaded");
                    }
                    Err(e) => warn!(error = %e, "keys.toml parse error — keeping previous config"),
                }
            }
        });
    }

    // HTTP router
    let http_addr: std::net::SocketAddr = cfg.server.http_addr.parse()?;
    let http_router = build_http_router(Arc::clone(&state));

    // gRPC service
    let grpc_addr: std::net::SocketAddr = cfg.server.grpc_addr.parse()?;
    let grpc_service = SigningGatewayService::new(Arc::clone(&state));

    // Spawn HTTP server
    let http_task = tokio::spawn(async move {
        info!(addr = %http_addr, "HTTP server listening");
        let listener = tokio::net::TcpListener::bind(http_addr).await.unwrap();
        axum::serve(listener, http_router.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .with_graceful_shutdown(shutdown_signal())
            .await
            .unwrap();
        info!("HTTP server stopped");
    });

    // gRPC reflection (grpcurl, Postman, evans)
    let descriptor = include_bytes!("grpc/signing_descriptor.bin");
    let reflection = ReflectionBuilder::configure()
        .register_encoded_file_descriptor_set(descriptor)
        .build()
        .unwrap();

    // Spawn gRPC server
    let grpc_task = tokio::spawn(async move {
        info!(addr = %grpc_addr, "gRPC server listening");
        tonic::transport::Server::builder()
            .add_service(SigningServiceServer::new(grpc_service))
            .add_service(reflection)
            .serve_with_shutdown(grpc_addr, shutdown_signal())
            .await
            .unwrap();
        info!("gRPC server stopped");
    });

    info!("Signing Gateway READY ✓  (HTTP:{} | gRPC:{})", cfg.server.http_addr, cfg.server.grpc_addr);

    tokio::select! {
        _ = http_task => info!("HTTP task exited"),
        _ = grpc_task => info!("gRPC task exited"),
    }

    info!("Signing Gateway shut down cleanly");
    Ok(())
}

// ─── HTTP router ─────────────────────────────────────────────────────────────

fn build_http_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/sign",                  post(handle_sign))
        .route("/v1/verify",                post(handle_verify))
        .route("/v1/keys",                  get(handle_list_keys))
        .route("/v1/keys/:key_id/public",   get(handle_get_public_key))
        .route("/health",                   get(handle_health))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
}

// ─── Graceful shutdown ────────────────────────────────────────────────────────

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("Shutdown signal received — draining connections");
}

// ─── Hot-reload helper ────────────────────────────────────────────────────────

fn load_keys_file() -> anyhow::Result<(Vec<config::KeyConfig>, config::AuthConfig)> {
    #[derive(serde::Deserialize)]
    struct KeysFile {
        keys: Vec<config::KeyConfig>,
        auth: config::AuthConfig,
    }
    let text = std::fs::read_to_string("keys.toml")?;
    let parsed: KeysFile = toml::from_str(&text)?;
    Ok((parsed.keys, parsed.auth))
}

// ─── Built-in dev defaults ────────────────────────────────────────────────────

fn default_config() -> GatewayConfig {
    use config::*;
    use std::collections::HashMap;

    GatewayConfig {
        server: ServerConfig {
            http_addr: "0.0.0.0:8080".into(),
            grpc_addr: "0.0.0.0:50051".into(),
            tls: None,
            shutdown_timeout_secs: 30,
        },
        hsm: HsmConfig::Software(SoftwareHsmConfig {
            key_dir: "/tmp/signing-gateway-keys".into(),
        }),
        keys: vec![
            KeyConfig {
                id:          "default-ec".into(),
                description: "Default EC P-256 signing key (dev)".into(),
                backend_ref: "default-ec".into(),
                algorithm:   AlgorithmConfig::Es256,
                enabled:     true,
            },
            KeyConfig {
                id:          "default-rsa".into(),
                description: "Default RSA-2048 signing key (dev)".into(),
                backend_ref: "default-rsa".into(),
                algorithm:   AlgorithmConfig::Rs256,
                enabled:     true,
            },
        ],
        auth: AuthConfig {
            tokens:       HashMap::new(),
            allow_all:    true, // ⚠ dev only
            allowed_keys: HashMap::new(),
            allowed_ips:  HashMap::new(),
        },
        observability: ObservabilityConfig {
            log_format:   LogFormat::Pretty,
            log_level:    "info".into(),
            metrics_addr: Some("0.0.0.0:9090".into()),
        },
    }
}
