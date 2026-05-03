//! harbor-sdk — Rust SDK for Harbor API monetization
//!
//! Add API key auth and billing to your Rust API in one line.
//! See [harbor-black.vercel.app](https://harbor-black.vercel.app) for docs.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

pub const DEFAULT_VALIDATE_URL: &str = "https://harbor-black.vercel.app/api/validate";

#[derive(Debug, Error)]
pub enum HarborError {
    #[error("Invalid or revoked API key")]
    InvalidKey,
    #[error("Missing API key")]
    MissingKey,
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Harbor validation service unavailable")]
    ServiceUnavailable,
}

/// Validated API key metadata returned after successful validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "projectId")]
    pub project_id: String,
    pub plan: String,
    #[serde(rename = "callsThisMonth", default)]
    pub calls_this_month: u64,
    pub name: String,
    pub country: Option<String>,
}

#[derive(Deserialize)]
struct ValidateResponse {
    valid: bool,
    #[serde(rename = "keyId")]
    key_id: Option<String>,
    #[serde(rename = "projectId")]
    project_id: Option<String>,
    plan: Option<String>,
    #[serde(rename = "callsThisMonth")]
    calls_this_month: Option<u64>,
    name: Option<String>,
    country: Option<String>,
    error: Option<String>,
}

/// Validate a Harbor API key asynchronously.
pub async fn validate(api_key: &str) -> Result<KeyInfo, HarborError> {
    validate_with_url(api_key, DEFAULT_VALIDATE_URL).await
}

/// Validate with a custom URL (for local dev emulator).
pub async fn validate_with_url(api_key: &str, url: &str) -> Result<KeyInfo, HarborError> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .user_agent(format!("harbor-sdk-rust/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| HarborError::ServiceUnavailable)?;

    let response = client.get(url).query(&[("key", api_key)]).send().await?;
    let result: ValidateResponse = response.json().await?;

    if !result.valid {
        return Err(HarborError::InvalidKey);
    }

    Ok(KeyInfo {
        key_id: result.key_id.unwrap_or_default(),
        project_id: result.project_id.unwrap_or_default(),
        plan: result.plan.unwrap_or_else(|| "free".to_string()),
        calls_this_month: result.calls_this_month.unwrap_or(0),
        name: result.name.unwrap_or_default(),
        country: result.country,
    })
}

#[cfg(feature = "axum")]
pub mod axum_middleware {
    use super::*;
    use axum::{
        extract::Request,
        http::StatusCode,
        middleware::Next,
        response::{IntoResponse, Response},
    };

    pub async fn harbor_auth(
        axum::extract::State(project_id): axum::extract::State<String>,
        mut req: Request,
        next: Next,
    ) -> Response {
        let api_key = req
            .headers()
            .get("x-harbor-key")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let api_key = match api_key {
            Some(k) => k,
            None => return (StatusCode::UNAUTHORIZED, r#"{"error":"Missing API key"}"#).into_response(),
        };

        match validate(&api_key).await {
            Ok(info) if info.project_id == project_id || project_id.is_empty() => {
                req.extensions_mut().insert(info);
                next.run(req).await
            }
            Ok(_) => (StatusCode::FORBIDDEN, r#"{"error":"Key does not belong to this project"}"#).into_response(),
            Err(_) => (StatusCode::UNAUTHORIZED, r#"{"error":"Invalid or revoked API key"}"#).into_response(),
        }
    }
}

#[derive(Clone)]
pub struct HarborLayer {
    project_id: Arc<String>,
    validate_url: Arc<String>,
}

impl HarborLayer {
    pub fn new(project_id: impl Into<String>) -> Self {
        Self { project_id: Arc::new(project_id.into()), validate_url: Arc::new(DEFAULT_VALIDATE_URL.to_string()) }
    }

    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.validate_url = Arc::new(url.into());
        self
    }
}
