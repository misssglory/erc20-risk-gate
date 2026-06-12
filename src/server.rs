use crate::config::AppConfig;
use crate::models::RiskReport;
use crate::scanner::Scanner;
use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;

#[derive(Clone)]
struct AppState {
    scanner: Scanner,
}

#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub address: String,

    #[serde(default)]
    pub chain_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub service: String,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub async fn run(cfg: AppConfig) -> Result<()> {
    let addr: SocketAddr = format!("{}:{}", cfg.server.host, cfg.server.port).parse()?;

    let scanner = Scanner::new(cfg)?;

    let state = AppState { scanner };

    let app = Router::new()
        .route("/health", get(health))
        .route("/scan", post(scan_post))
        .route("/scan/{chain_id}/{address}", get(scan_get))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(Arc::new(state));

    let listener = TcpListener::bind(addr).await?;

    info!(%addr, "HTTP server listening");

    axum::serve(listener, app).await?;

    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        service: "erc20-risk-gate".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn scan_post(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ScanRequest>,
) -> Result<Json<RiskReport>, ApiError> {
    validate_address(&payload.address)?;

    let report = state
        .scanner
        .scan(payload.address, payload.chain_id)
        .await;

    Ok(Json(report))
}

async fn scan_get(
    State(state): State<Arc<AppState>>,
    Path((chain_id, address)): Path<(String, String)>,
) -> Result<Json<RiskReport>, ApiError> {
    validate_address(&address)?;

    let report = state
        .scanner
        .scan(address, Some(chain_id))
        .await;

    Ok(Json(report))
}

fn validate_address(address: &str) -> Result<(), ApiError> {
    let is_valid = address.starts_with("0x") && address.len() == 42;

    if !is_valid {
        return Err(ApiError::bad_request(
            "invalid token address; expected 0x-prefixed 20-byte address",
        ));
    }

    Ok(())
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let body = Json(ErrorResponse {
            error: self.message,
        });

        (self.status, body).into_response()
    }
}