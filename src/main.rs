use anyhow::Context;
use nmchain::api::{ApiState, router};
use nmchain::chain::ChainRuntime;
use nmchain::config::Settings;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "nmchain=info,axum=info".to_string()),
        )
        .init();

    let settings = Settings::from_env()?;
    if settings.app_tokens.is_empty() && settings.auth_session_url.is_none() {
        warn!("NMCHAIN auth is not configured; the API is running without bearer-token protection");
    }
    let runtime = ChainRuntime::load(settings.clone())?;
    let status = runtime.status();
    let auth_client = reqwest::Client::builder()
        .timeout(Duration::from_millis(settings.auth_timeout_ms))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    info!(
        chain_id = %status.chain_id,
        validator_id = %status.validator_id,
        height = status.height,
        listen = %settings.listen,
        auth_mode = %settings.auth_mode(),
        "nmchain ready"
    );

    let state = ApiState {
        runtime: Arc::new(RwLock::new(runtime)),
        tokens: Arc::new(settings.app_tokens.clone()),
        auth_session_url: settings.auth_session_url.clone(),
        auth_client,
        auth_cache_ttl_ms: settings.auth_cache_ttl_ms,
        auth_cache: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
    };

    let app = router(state);
    let listener = tokio::net::TcpListener::bind(&settings.listen)
        .await
        .with_context(|| format!("failed to bind '{}'", settings.listen))?;
    axum::serve(listener, app)
        .await
        .context("nmchain server failed")?;
    Ok(())
}
