//! Optispan Iris — in-process built-in extension (Apollo clinical data).
//!
//! Reads patient data through the Apollo HTTP API so authorization
//! (can_access_patient / has_staff_access) and the access audit stay on the
//! server — this built-in holds NO authorization logic of its own. Configure
//! via env:
//!   IRIS_API_BASE     Apollo API base URL (e.g. https://.../api)
//!   IRIS_STAFF_TOKEN  bearer token for the acting staff member (optional now;
//!                     the SMART/gateway flow provides it later)
//!
//! This is the in-process successor to the Python stdio prototype: same tool
//! surface, compiled into the distro, no external process.
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, ContentBlock, ErrorCode, ErrorData, Implementation, InitializeResult,
        ServerCapabilities, ServerInfo,
    },
    schemars::JsonSchema,
    tool, tool_handler, tool_router, ServerHandler,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct PatientIdParams {
    /// Apollo patient_id (integer).
    pub patient_id: i64,
}

#[derive(Clone)]
pub struct IrisServer {
    tool_router: ToolRouter<Self>,
    http: reqwest::Client,
    api_base: String,
    token: Option<String>,
}

impl Default for IrisServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router(router = tool_router)]
impl IrisServer {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
            http: reqwest::Client::new(),
            api_base: std::env::var("IRIS_API_BASE").unwrap_or_default(),
            token: std::env::var("IRIS_STAFF_TOKEN").ok().filter(|t| !t.is_empty()),
        }
    }

    /// Authenticated GET against the Apollo API, returning the parsed JSON body.
    async fn api_get(&self, path: &str) -> Result<serde_json::Value, ErrorData> {
        if self.api_base.is_empty() {
            return Err(ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                "IRIS_API_BASE is not set".to_string(),
                None,
            ));
        }
        let url = format!("{}{}", self.api_base.trim_end_matches('/'), path);
        let mut req = self.http.get(&url);
        if let Some(t) = &self.token {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.map_err(|e| {
            ErrorData::new(ErrorCode::INTERNAL_ERROR, format!("request failed: {e}"), None)
        })?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                format!("Apollo returned {status}: {body}"),
                None,
            ));
        }
        serde_json::from_str(&body).map_err(|e| {
            ErrorData::new(ErrorCode::INTERNAL_ERROR, format!("invalid JSON from Apollo: {e}"), None)
        })
    }

    #[tool(
        name = "iris_get_biological_age",
        description = "LinAge biological age for a patient (Apollo /optiage): biological vs chronological age and the delta. Arg: patient_id."
    )]
    pub async fn iris_get_biological_age(
        &self,
        params: Parameters<PatientIdParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let v = self
            .api_get(&format!("/optiage?patient_id={}", params.0.patient_id))
            .await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(v.to_string())]))
    }

    #[tool(
        name = "iris_get_dexa",
        description = "Most recent DEXA body-composition scan for a patient (Apollo /dexa). Arg: patient_id."
    )]
    pub async fn iris_get_dexa(
        &self,
        params: Parameters<PatientIdParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let v = self
            .api_get(&format!("/dexa?patient_id={}", params.0.patient_id))
            .await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(v.to_string())]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for IrisServer {
    fn get_info(&self) -> ServerInfo {
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("goose-iris", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Optispan Iris clinical-data tools. Resolve a patient_id, then query the \
                 patient's biological age and DEXA scan. Reads go through the Apollo API, \
                 which enforces staff access and auditing."
                    .to_string(),
            )
    }
}
