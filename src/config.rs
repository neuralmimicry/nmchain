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
            data_dir,
            validator_key_path,
        })
    }

    pub fn auth_mode(&self) -> &'static str {
        if self.app_tokens.is_empty() {
            "open"
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
