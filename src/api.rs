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
use serde_json::json;
use std::sync::{Arc, RwLock};

#[derive(Clone)]
pub struct ApiState {
    pub runtime: Arc<RwLock<ChainRuntime>>,
    pub tokens: Arc<std::collections::HashMap<String, String>>,
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

async fn chain_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Response {
    let app = match authorize(&state, &headers) {
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
    if let Err(response) = authorize(&state, &headers) {
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
    if let Err(response) = authorize(&state, &headers) {
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
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let scope = match scope.parse::<AccountScope>() {
        Ok(scope) => scope,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": err })),
            )
                .into_response()
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
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let scope = match scope.parse::<AccountScope>() {
        Ok(scope) => scope,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": err })),
            )
                .into_response()
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
    let app = match authorize(&state, &headers) {
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
    let app = match authorize(&state, &headers) {
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
    let app = match authorize(&state, &headers) {
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
    let app = match authorize(&state, &headers) {
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

fn authorize(state: &ApiState, headers: &HeaderMap) -> Result<String, Response> {
    if state.tokens.is_empty() {
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
    for (app, candidate) in state.tokens.iter() {
        if candidate == token.trim() {
            return Ok(app.clone());
        }
    }
    Err((
        StatusCode::FORBIDDEN,
        Json(json!({ "error": "invalid_token" })),
    )
        .into_response())
}
