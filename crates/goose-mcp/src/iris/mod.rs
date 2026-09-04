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

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct FindPatientParams {
    /// Name (or partial name / email) to search for.
    pub query: String,
    /// Max results to return (default 10).
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListDocumentsParams {
    /// Apollo patient_id (integer).
    pub patient_id: i64,
    /// Optional category filter (e.g. "lab-reports").
    pub category: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct GetDocumentParams {
    /// Apollo patient_id (integer).
    pub patient_id: i64,
    /// Document id (UUID) from iris_list_documents.
    pub document_id: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct FileDocumentParams {
    /// Apollo patient_id (integer) whose folder the document is filed to.
    pub patient_id: i64,
    /// Human-readable title for the document.
    pub title: String,
    /// Absolute path to the local file to upload.
    pub file_path: String,
    /// Optional category (e.g. "lab-reports"); Apollo classifies if omitted.
    pub category: Option<String>,
}

/// True for a canonical 8-4-4-4-12 hex UUID (Apollo document ids). Guards against
/// path/query injection when a document_id is interpolated into a URL.
fn is_uuid(s: &str) -> bool {
    let groups = [8, 4, 4, 4, 12];
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts
            .iter()
            .zip(groups)
            .all(|(p, n)| p.len() == n && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn mime_from_path(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase();
    match lower.rsplit('.').next() {
        Some("pdf") => "application/pdf",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("txt") => "text/plain",
        Some("csv") => "text/csv",
        Some("json") => "application/json",
        Some("html") | Some("htm") => "text/html",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        _ => "application/octet-stream",
    }
}

#[derive(Clone)]
pub struct IrisServer {
    tool_router: ToolRouter<Self>,
    http: reqwest::Client,
    api_base: String,
    /// Fallback bearer token from IRIS_STAFF_TOKEN (env, captured at startup).
    token: Option<String>,
    /// Path from IRIS_STAFF_TOKEN_FILE holding the current staff token. Read
    /// fresh on each request so the desktop can refresh the token in place
    /// without restarting goosed; takes precedence over `token` when non-empty.
    token_file: Option<String>,
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
            token_file: std::env::var("IRIS_STAFF_TOKEN_FILE").ok().filter(|t| !t.is_empty()),
        }
    }

    /// Resolve the current staff bearer token. Prefers IRIS_STAFF_TOKEN_FILE,
    /// read fresh on each call so the desktop's periodic refresh is picked up
    /// without restarting goosed; falls back to the IRIS_STAFF_TOKEN env value.
    fn current_token(&self) -> Option<String> {
        if let Some(path) = &self.token_file {
            if let Ok(contents) = std::fs::read_to_string(path) {
                let trimmed = contents.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
        self.token.clone()
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
        if let Some(t) = self.current_token() {
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

    /// Authenticated POST (JSON) against the Apollo API, returning the parsed body.
    async fn api_post(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value, ErrorData> {
        if self.api_base.is_empty() {
            return Err(ErrorData::new(ErrorCode::INTERNAL_ERROR, "IRIS_API_BASE is not set".to_string(), None));
        }
        let url = format!("{}{}", self.api_base.trim_end_matches('/'), path);
        let mut req = self.http.post(&url).json(body);
        if let Some(t) = self.current_token() {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.map_err(|e| {
            ErrorData::new(ErrorCode::INTERNAL_ERROR, format!("request failed: {e}"), None)
        })?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(ErrorData::new(ErrorCode::INTERNAL_ERROR, format!("Apollo returned {status}: {text}"), None));
        }
        serde_json::from_str(&text).map_err(|e| {
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

    #[tool(
        name = "iris_find_patient",
        description = "Resolve a patient_id by name (or partial name / email). Returns a short list of {patient_id, name, dob, ...} matches. Call this FIRST to get the patient_id every other tool needs. Args: query, limit?."
    )]
    pub async fn iris_find_patient(
        &self,
        params: Parameters<FindPatientParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let limit = params.0.limit.unwrap_or(10).max(1) as usize;
        let needle = params.0.query.trim().to_lowercase();
        // GET /patients returns the full staff-visible list; filter by name locally.
        let v = self.api_get("/patients").await?;
        // Response may be an array or {patients:[...]} / {data:[...]}.
        let rows = v
            .as_array()
            .cloned()
            .or_else(|| v.get("patients").and_then(|x| x.as_array()).cloned())
            .or_else(|| v.get("data").and_then(|x| x.as_array()).cloned())
            .unwrap_or_default();
        let name_fields = ["name", "full_name", "first_name", "last_name", "preferred_name", "email", "personal_email"];
        let mut matches: Vec<serde_json::Value> = Vec::new();
        for r in rows {
            let hit = name_fields.iter().any(|f| {
                r.get(*f)
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_lowercase().contains(&needle))
                    .unwrap_or(false)
            });
            if hit {
                matches.push(r);
                if matches.len() >= limit {
                    break;
                }
            }
        }
        let out = serde_json::json!({ "count": matches.len(), "patients": matches });
        Ok(CallToolResult::success(vec![ContentBlock::text(out.to_string())]))
    }

    #[tool(
        name = "iris_list_documents",
        description = "List the documents in a patient's folder (Apollo /document-storage-api). Returns document metadata: id, title/filename, category, status, upload date. Args: patient_id, category?."
    )]
    pub async fn iris_list_documents(
        &self,
        params: Parameters<ListDocumentsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut path = format!("/document-storage-api?patient_id={}", params.0.patient_id);
        if let Some(cat) = params.0.category.as_deref().filter(|c| !c.is_empty()) {
            path.push_str(&format!("&category={}", urlencoding_encode(cat)));
        }
        let v = self.api_get(&path).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(v.to_string())]))
    }

    #[tool(
        name = "iris_get_document",
        description = "Get a readable handle (a short-lived signed download URL) for one document in a patient's folder. Fetch the document_id from iris_list_documents first. Read the file via the computercontroller tool. Args: patient_id, document_id."
    )]
    pub async fn iris_get_document(
        &self,
        params: Parameters<GetDocumentParams>,
    ) -> Result<CallToolResult, ErrorData> {
        // Validate the document_id is a bare UUID before interpolating it into
        // the URL — rejects any path/query-injection ("../x", "id?patient_id=..").
        if !is_uuid(params.0.document_id.trim()) {
            return Err(ErrorData::new(
                ErrorCode::INVALID_PARAMS,
                "document_id must be a UUID (from iris_list_documents)".to_string(),
                None,
            ));
        }
        // patient_id in the query so the server's per-patient authz applies.
        let path = format!(
            "/document-storage-api/{}/download?patient_id={}",
            params.0.document_id.trim(),
            params.0.patient_id
        );
        let v = self.api_get(&path).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(v.to_string())]))
    }

    #[tool(
        name = "iris_file_document",
        description = "WRITE: file a local document into a patient's folder in the chart. This is a chart write and requires confirmation. Uploads the file at file_path via Apollo's signed-URL flow (initiate -> upload -> complete). Args: patient_id, title, file_path, category?."
    )]
    pub async fn iris_file_document(
        &self,
        params: Parameters<FileDocumentParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let p = params.0;
        let bytes = std::fs::read(&p.file_path).map_err(|e| {
            ErrorData::new(ErrorCode::INVALID_PARAMS, format!("cannot read file '{}': {e}", p.file_path), None)
        })?;
        let filename = std::path::Path::new(&p.file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("document")
            .to_string();
        let mime = mime_from_path(&p.file_path);
        let category = p.category.clone().unwrap_or_else(|| "other".to_string());

        // 1. initiate -> signed GCS upload URL + file id
        let init = self
            .api_post(
                "/document-storage-api/initiate",
                &serde_json::json!({
                    "patient_id": p.patient_id,
                    "filename": filename,
                    "mime_type": mime,
                    "size_bytes": bytes.len(),
                    "category": category,
                    "notes": p.title,
                }),
            )
            .await?;
        let upload_url = init.get("upload_url").and_then(|x| x.as_str()).ok_or_else(|| {
            ErrorData::new(ErrorCode::INTERNAL_ERROR, format!("initiate returned no upload_url: {init}"), None)
        })?;

        // 2. PUT the bytes straight to GCS (signed URL carries its own auth).
        let put = self
            .http
            .put(upload_url)
            .header(reqwest::header::CONTENT_TYPE, mime)
            .body(bytes.clone())
            .send()
            .await
            .map_err(|e| ErrorData::new(ErrorCode::INTERNAL_ERROR, format!("GCS upload failed: {e}"), None))?;
        if !put.status().is_success() {
            let s = put.status();
            let b = put.text().await.unwrap_or_default();
            return Err(ErrorData::new(ErrorCode::INTERNAL_ERROR, format!("GCS upload returned {s}: {b}"), None));
        }

        // 3. complete -> persist metadata.
        let mut complete_body = serde_json::json!({
            "patient_id": p.patient_id,
            "original_filename": filename,
            "mime_type": mime,
            "size_bytes": bytes.len(),
            "category": category,
            "notes": p.title,
            "metadata": { "title": p.title, "filed_by": "optispan-assistant" },
        });
        for k in ["gcs_path", "gcs_uri", "file_id"] {
            if let Some(val) = init.get(k) {
                complete_body[k] = val.clone();
            }
        }
        let done = self.api_post("/document-storage-api/complete", &complete_body).await?;
        let out = serde_json::json!({ "filed": true, "title": p.title, "result": done });
        Ok(CallToolResult::success(vec![ContentBlock::text(out.to_string())]))
    }
}

/// Minimal percent-encoding for query values (space and a few reserved chars).
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for IrisServer {
    fn get_info(&self) -> ServerInfo {
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("goose-iris", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Optispan Iris clinical-data tools. ALWAYS resolve the patient first with \
                 iris_find_patient to get the patient_id, then pass that explicit patient_id \
                 to the other tools (never assume it). Reads (biological age, DEXA, documents) \
                 go through the Apollo API, which enforces staff access and auditing. \
                 iris_file_document is a chart WRITE and will ask for confirmation."
                    .to_string(),
            )
    }
}
