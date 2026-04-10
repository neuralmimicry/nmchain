use crate::chain::ChainRuntime;
use crate::model::{
    AccountRef, AccountScope, IdentityUpsertRequest, ListQuery, LoginObservedRequest,
    PaymentCaptureRequest, TokenMutationRequest,
};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::sync::RwLock as AsyncRwLock;

#[derive(Clone)]
pub struct ApiState {
    pub runtime: Arc<RwLock<ChainRuntime>>,
    pub tokens: Arc<HashMap<String, String>>,
    pub auth_session_url: Option<String>,
    pub auth_client: reqwest::Client,
    pub auth_cache_ttl_ms: u64,
    pub auth_cache: Arc<AsyncRwLock<HashMap<String, AuthCacheEntry>>>,
}

#[derive(Clone, Debug)]
pub struct AuthCacheEntry {
    actor: Option<String>,
    expires_at: Instant,
}

#[derive(Debug, Deserialize)]
struct SessionResponse {
    authenticated: bool,
    user: Option<String>,
}

impl ApiState {
    fn auth_enabled(&self) -> bool {
        !self.tokens.is_empty()
            || self
                .auth_session_url
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_some()
    }

    fn negative_cache_ttl_ms(&self) -> u64 {
        self.auth_cache_ttl_ms.min(2_000).max(250)
    }

    fn match_static_token(&self, token: &str) -> Option<String> {
        self.tokens.iter().find_map(|(app, candidate)| {
            if candidate == token {
                Some(app.clone())
            } else {
                None
            }
        })
    }

    async fn cached_actor(&self, token: &str) -> Option<Option<String>> {
        let now = Instant::now();
        {
            let cache = self.auth_cache.read().await;
            if let Some(entry) = cache.get(token)
                && entry.expires_at > now
            {
                return Some(entry.actor.clone());
            }
        }
        let mut cache = self.auth_cache.write().await;
        if let Some(entry) = cache.get(token)
            && entry.expires_at > now
        {
            return Some(entry.actor.clone());
        }
        cache.remove(token);
        None
    }

    async fn cache_actor(&self, token: &str, actor: Option<String>, ttl_ms: u64) {
        const MAX_CACHE_ENTRIES: usize = 1024;

        let now = Instant::now();
        let mut cache = self.auth_cache.write().await;
        cache.retain(|_, entry| entry.expires_at > now);
        if cache.len() >= MAX_CACHE_ENTRIES {
            cache.clear();
        }
        cache.insert(
            token.to_string(),
            AuthCacheEntry {
                actor,
                expires_at: now + std::time::Duration::from_millis(ttl_ms.max(1)),
            },
        );
    }

    async fn validate_central_session(&self, token: &str) -> Result<Option<String>, ()> {
        let Some(session_url) = self
            .auth_session_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };

        let response = self
            .auth_client
            .get(session_url)
            .header("Accept", "application/json")
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| ())?;

        let status = response.status();
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return Ok(None);
        }
        if status.is_server_error() || !status.is_success() {
            return Err(());
        }

        let payload = response.json::<SessionResponse>().await.map_err(|_| ())?;
        let user = payload
            .user
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        if payload.authenticated {
            Ok(user)
        } else {
            Ok(None)
        }
    }
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/chain", get(chain_status))
        .route("/api/blocks", get(list_blocks))
        .route("/api/blocks/{index}", get(get_block))
        .route("/api/accounts/{scope}/{account_id}", get(account_snapshot))
        .route(
            "/api/accounts/{scope}/{account_id}/ledger",
            get(account_ledger),
        )
        .route("/api/events/identity", post(submit_identity))
        .route("/api/events/login", post(submit_login))
        .route("/api/events/payment", post(submit_payment))
        .route("/api/events/token", post(submit_token))
        .with_state(state)
}

async fn health(State(state): State<ApiState>) -> impl IntoResponse {
    let runtime = state.runtime.read().unwrap();
    Json(json!({
        "ok": true,
        "chain": runtime.status(),
    }))
}

async fn chain_status(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    let app = match authorize(&state, &headers).await {
        Ok(app) => app,
        Err(response) => return response,
    };
    let runtime = state.runtime.read().unwrap();
    Json(json!({
        "app": app,
        "chain": runtime.status(),
    }))
    .into_response()
}

async fn list_blocks(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    if let Err(response) = authorize(&state, &headers).await {
        return response;
    }
    let runtime = state.runtime.read().unwrap();
    let limit = query.limit.unwrap_or(20).clamp(1, 200);
    Json(json!({ "blocks": runtime.list_blocks(limit) })).into_response()
}

async fn get_block(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(index): Path<u64>,
) -> Response {
    if let Err(response) = authorize(&state, &headers).await {
        return response;
    }
    let runtime = state.runtime.read().unwrap();
    match runtime.block(index) {
        Some(block) => Json(json!({ "block": block })).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "block_not_found" })),
        )
            .into_response(),
    }
}

async fn account_snapshot(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((scope, account_id)): Path<(String, String)>,
) -> Response {
    if let Err(response) = authorize(&state, &headers).await {
        return response;
    }
    let scope = match scope.parse::<AccountScope>() {
        Ok(scope) => scope,
        Err(err) => {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": err }))).into_response();
        }
    };
    let runtime = state.runtime.read().unwrap();
    let account = AccountRef::new(scope, account_id);
    Json(runtime.account_snapshot(&account)).into_response()
}

async fn account_ledger(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((scope, account_id)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
) -> Response {
    if let Err(response) = authorize(&state, &headers).await {
        return response;
    }
    let scope = match scope.parse::<AccountScope>() {
        Ok(scope) => scope,
        Err(err) => {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": err }))).into_response();
        }
    };
    let runtime = state.runtime.read().unwrap();
    let account = AccountRef::new(scope, account_id);
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    Json(json!({ "entries": runtime.account_ledger(&account, limit) })).into_response()
}

async fn submit_identity(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(payload): Json<IdentityUpsertRequest>,
) -> Response {
    let app = match authorize(&state, &headers).await {
        Ok(app) => app,
        Err(response) => return response,
    };
    let mut runtime = state.runtime.write().unwrap();
    match runtime.submit_identity(&app, payload) {
        Ok(result) => Json(result).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response(),
    }
}

async fn submit_login(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(payload): Json<LoginObservedRequest>,
) -> Response {
    let app = match authorize(&state, &headers).await {
        Ok(app) => app,
        Err(response) => return response,
    };
    let mut runtime = state.runtime.write().unwrap();
    match runtime.submit_login(&app, payload) {
        Ok(result) => Json(result).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response(),
    }
}

async fn submit_payment(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(payload): Json<PaymentCaptureRequest>,
) -> Response {
    let app = match authorize(&state, &headers).await {
        Ok(app) => app,
        Err(response) => return response,
    };
    let mut runtime = state.runtime.write().unwrap();
    match runtime.submit_payment(&app, payload) {
        Ok(result) => Json(result).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response(),
    }
}

async fn submit_token(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(payload): Json<TokenMutationRequest>,
) -> Response {
    let app = match authorize(&state, &headers).await {
        Ok(app) => app,
        Err(response) => return response,
    };
    let mut runtime = state.runtime.write().unwrap();
    match runtime.submit_token(&app, payload) {
        Ok(result) => Json(result).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response(),
    }
}

async fn authorize(state: &ApiState, headers: &HeaderMap) -> Result<String, Response> {
    if !state.auth_enabled() {
        return Ok("development".to_string());
    }
    let Some(raw_auth) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "missing_authorization" })),
        )
            .into_response());
    };
    let Some(token) = raw_auth.strip_prefix("Bearer ") else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_authorization" })),
        )
            .into_response());
    };
    let token = token.trim();
    if token.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_authorization" })),
        )
            .into_response());
    }

    if let Some(cached) = state.cached_actor(token).await {
        return cached.ok_or_else(|| {
            (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "invalid_token" })),
            )
                .into_response()
        });
    }

    match state.validate_central_session(token).await {
        Ok(Some(user)) => {
            let actor = format!("user:{}", user);
            state
                .cache_actor(token, Some(actor.clone()), state.auth_cache_ttl_ms)
                .await;
            return Ok(actor);
        }
        Ok(None) => {}
        Err(()) => {
            if let Some(app) = state.match_static_token(token) {
                state
                    .cache_actor(token, Some(app.clone()), state.auth_cache_ttl_ms)
                    .await;
                return Ok(app);
            }
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "auth_unavailable" })),
            )
                .into_response());
        }
    }

    if let Some(app) = state.match_static_token(token) {
        state
            .cache_actor(token, Some(app.clone()), state.auth_cache_ttl_ms)
            .await;
        return Ok(app);
    }

    state
        .cache_actor(token, None, state.negative_cache_ttl_ms())
        .await;
    Err((
        StatusCode::FORBIDDEN,
        Json(json!({ "error": "invalid_token" })),
    )
        .into_response())
}
