use anyhow::Context;
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Settings {
    pub listen: String,
    pub data_dir: PathBuf,
    pub chain_id: String,
    pub validator_id: String,
    pub validator_key_path: PathBuf,
    pub app_tokens: HashMap<String, String>,
    pub auth_session_url: Option<String>,
    pub auth_cache_ttl_ms: u64,
    pub auth_timeout_ms: u64,
}

impl Settings {
    pub fn from_env() -> anyhow::Result<Self> {
        let data_dir = PathBuf::from(env_string("NMCHAIN_DATA_DIR", "data"));
        std::fs::create_dir_all(&data_dir)
            .with_context(|| format!("failed to create data dir '{}'", data_dir.display()))?;

        let validator_key_path = env::var("NMCHAIN_VALIDATOR_KEY_PATH")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("validator.key.json"));

        Ok(Self {
            listen: env_string("NMCHAIN_LISTEN", "127.0.0.1:9080"),
            chain_id: env_string("NMCHAIN_CHAIN_ID", "neuralmimicry-private-chain"),
            validator_id: env_string("NMCHAIN_VALIDATOR_ID", "nm-validator-1"),
            app_tokens: parse_app_tokens(env::var("NMCHAIN_APP_TOKENS").ok()),
            auth_session_url: env_first(&[
                "NMCHAIN_AUTH_SESSION_URL",
                "NMCHAIN_CENTRAL_AUTH_SESSION_URL",
                "NM_CENTRAL_AUTH_SESSION_URL",
            ]),
            auth_cache_ttl_ms: env_u64("NMCHAIN_AUTH_CACHE_TTL_MS", 15_000).clamp(1_000, 300_000),
            auth_timeout_ms: env_u64("NMCHAIN_AUTH_TIMEOUT_MS", 3_000).clamp(500, 15_000),
            data_dir,
            validator_key_path,
        })
    }

    pub fn auth_mode(&self) -> &'static str {
        if self.app_tokens.is_empty() && self.auth_session_url.is_none() {
            "open"
        } else if self.auth_session_url.is_some() && !self.app_tokens.is_empty() {
            "central+bearer"
        } else if self.auth_session_url.is_some() {
            "central"
        } else {
            "bearer"
        }
    }
}

fn env_string(key: &str, default: &str) -> String {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn env_first(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        env::var(key)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn parse_app_tokens(raw: Option<String>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Some(raw) = raw else {
        return out;
    };

    for entry in raw.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (app, token) = if let Some((left, right)) = trimmed.split_once('=') {
            (left.trim(), right.trim())
        } else if let Some((left, right)) = trimmed.split_once(':') {
            (left.trim(), right.trim())
        } else {
            continue;
        };
        if !app.is_empty() && !token.is_empty() {
            out.insert(app.to_string(), token.to_string());
        }
    }

    out
}
