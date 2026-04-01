use anyhow::Context;
use nmchain::api::{ApiState, router};
use nmchain::chain::ChainRuntime;
use nmchain::config::Settings;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "nmchain=info,axum=info".to_string()),
        )
        .init();

    let settings = Settings::from_env()?;
    if settings.app_tokens.is_empty() {
        warn!(
            "NMCHAIN_APP_TOKENS is not set; the API is running without bearer-token protection"
        );
    }
    let runtime = ChainRuntime::load(settings.clone())?;
    let status = runtime.status();
    info!(
        chain_id = %status.chain_id,
        validator_id = %status.validator_id,
        height = status.height,
        listen = %settings.listen,
        "nmchain ready"
    );

    let state = ApiState {
        runtime: Arc::new(RwLock::new(runtime)),
        tokens: Arc::new(settings.app_tokens.clone()),
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
