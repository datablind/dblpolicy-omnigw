// Copyright 2023 Salesforce, Inc. All rights reserved.
mod generated;

use anyhow::{anyhow, Result};
use flate2::read::GzDecoder;
use std::{io::Read, ops::Deref};

use pdk::hl::*;
use pdk::logger;
use pdk::script::{HandlerAttributesBinding, TryFromValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::generated::config::Config as GeneratedConfig;

// Policy version is sourced from the `version` field in Cargo.toml at compile time
// (Cargo exposes it as CARGO_PKG_VERSION), so it never needs manual updating here.
const POLICY_VERSION: &str = env!("CARGO_PKG_VERSION");
const LOG_LABEL: &str = concat!("MCP_DATABLIND 6.0.12 v", env!("CARGO_PKG_VERSION"), ": ");
const POLICY_INJECTION_POINT: &str = "inbound";
const DICTUM_HEADER: &str = "DataBlind-Dictum";

// Endpoint paths appended to the stage/base path configured in dataCryptService
// (e.g. .../Prod + /filter -> .../Prod/filter).
const FILTER_PATH: &str = "/filter";
const DATACRYPT_PATH: &str = "/datacrypt";
const NLP_PATH: &str = "/datacrypt-nlp";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EncryptMode {
    None,
    SpecifySensitiveFields,
    DetermineFieldsUsingNlp,
}

#[derive(Deserialize)]
struct ConfigCompatibility {
    #[serde(alias = "sensitiveFieldsSpecified")]
    sensitive_fields_specified: Option<bool>,
}

#[derive(Clone)]
struct RuntimeConfig {
    inner: GeneratedConfig,
    encrypt_mode: EncryptMode,
}

impl RuntimeConfig {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner: GeneratedConfig = serde_json::from_slice(bytes).map_err(|err| {
            anyhow!(
                "Failed to parse configuration '{}'. Cause: {}",
                String::from_utf8_lossy(bytes),
                err
            )
        })?;
        let compatibility: ConfigCompatibility = serde_json::from_slice(bytes).map_err(|err| {
            anyhow!(
                "Failed to parse configuration compatibility '{}'. Cause: {}",
                String::from_utf8_lossy(bytes),
                err
            )
        })?;

        Ok(Self {
            encrypt_mode: resolve_encrypt_mode(
                inner.encrypt_mode.as_deref(),
                compatibility.sensitive_fields_specified,
            ),
            inner,
        })
    }
}

impl Deref for RuntimeConfig {
    type Target = GeneratedConfig;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

fn resolve_encrypt_mode(
    encrypt_mode: Option<&str>,
    legacy_sensitive_fields_specified: Option<bool>,
) -> EncryptMode {
    match encrypt_mode
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        Some("none") => EncryptMode::None,
        Some("specify sensitive fields") | Some("specify pii (sensitive) fields") => {
            EncryptMode::SpecifySensitiveFields
        }
        Some(
            "determine sensitive fields using nlp (identifies pii related to financial, contact, identity, auth, device, tax, health, vehicle, gov id, and url data)",
        )
        | Some("determine sensitive fields using nlp")
        | Some("determine pii (sensitive) fields using nlp")
        | Some("determine fields using nlp") => EncryptMode::DetermineFieldsUsingNlp,
        Some(_) | None => match legacy_sensitive_fields_specified {
            Some(true) => EncryptMode::SpecifySensitiveFields,
            Some(false) => EncryptMode::DetermineFieldsUsingNlp,
            None => EncryptMode::None,
        },
    }
}

/// Override credentials and trace context read from the inbound request and shared with the
/// response phase.
#[derive(Clone, Default)]
struct RequestContext {
    token: String,
    passphrase: String,
    trace_id: String,
}

/// Summary of DataBlind actions performed on a response, used to build the DataBlind-Dictum header.
#[derive(Default)]
struct DictumSummary {
    actions: Vec<String>,
}

impl DictumSummary {
    fn record_action(&mut self, action: &str) {
        if !self.actions.iter().any(|existing| existing == action) {
            self.actions.push(action.to_string());
        }
    }
}

/// Request body expected by the DataCrypt REST service (see DataCryptApp.RequestBody).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DataCryptRequest {
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tweak: Option<String>,
    data: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    sensitive_fields: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    filter_rule: Option<Value>,
    over_ride_token: String,
    over_ride_pass_phrase: String,
}

/// Response body returned by the DataCrypt REST service (see DataCryptApp.ResponseBody).
#[derive(Deserialize)]
struct DataCryptResponse {
    token: String,
}

/// Builds the filter rule JSON sent to DataCrypt from the Filter Rule UI fields (filterMode plus
/// the include/exclude field+value pairs). Returns `None` (skip the filter step) when the mode is
/// "None"/unset or when the field for the selected mode is blank.
fn build_filter_rule(config: &RuntimeConfig) -> Option<Value> {
    // Normalize to lowercase so the emitted rule always uses "include"/"exclude" (what DataCrypt
    // expects), regardless of how the mode is cased in the UI enum. Any mode other than
    // include/exclude (e.g. the default "None") skips filtering entirely.
    let mode = config
        .filter_mode
        .as_deref()
        .unwrap_or("none")
        .to_lowercase();
    let (field, value) = match mode.as_str() {
        "include" => (config.include_field.as_deref(), config.include_value.as_deref()),
        "exclude" => (config.exclude_field.as_deref(), config.exclude_value.as_deref()),
        _ => return None,
    };

    // Accept the field name with or without surrounding quotes (e.g. person.phone or
    // "person.phone"), mirroring the value handling below.
    let field = field
        .map(|field| field.trim().trim_matches('"'))
        .filter(|field| !field.is_empty())?;

    let values: Vec<Value> = value
        .unwrap_or_default()
        .split(',')
        .map(|value| value.trim().trim_matches('"'))
        .filter(|value| !value.is_empty())
        .map(|value| Value::String(value.to_string()))
        .collect();

    let value = match values.len() {
        0 => Value::String(String::new()),
        1 => values.into_iter().next().unwrap_or(Value::Null),
        _ => Value::Array(values),
    };

    let mut rule = serde_json::Map::new();
    rule.insert("filter".to_string(), Value::String(mode.to_string()));
    rule.insert(field.to_string(), value);
    Some(Value::Object(rule))
}

/// Parses a configured JSON line: used as-is when it is valid JSON, otherwise treated as a plain
/// string, mirroring the `read(..., 'application/json')` handling in the original policy template.
fn parse_json_line(item: &str) -> Value {
    serde_json::from_str(item).unwrap_or_else(|_| Value::String(item.to_string()))
}

fn header_value(headers: &dyn HeadersHandler, name: &str) -> Option<String> {
    headers
        .header(name)
        .or_else(|| {
            headers.headers().into_iter().find_map(|(key, value)| {
                if key.eq_ignore_ascii_case(name) {
                    Some(value)
                } else {
                    None
                }
            })
        })
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Extracts the 32-hex trace-id segment from a W3C `traceparent` header value.
fn extract_trace_id(traceparent: &str) -> Option<String> {
    let parts: Vec<&str> = traceparent.trim().split('-').collect();
    if parts.len() < 2 {
        return None;
    }

    let trace_id = parts[1];
    if trace_id.len() == 32 && trace_id.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(trace_id.to_ascii_lowercase())
    } else {
        None
    }
}

fn generate_trace_id() -> String {
    let mut bytes = [0u8; 4];
    if getrandom::getrandom(&mut bytes).is_ok() {
        format!("db-{:08x}", u32::from_be_bytes(bytes))
    } else {
        "db-00000000".to_string()
    }
}

fn get_or_generate_trace_id(headers: &dyn HeadersHandler) -> String {
    if let Some(traceparent) = header_value(headers, "traceparent") {
        if let Some(trace_id) = extract_trace_id(&traceparent) {
            return trace_id;
        }
    }

    if let Some(correlation_id) = header_value(headers, "X-Correlation-ID") {
        return correlation_id;
    }

    generate_trace_id()
}

fn count_sensitive_fields(config: &RuntimeConfig) -> u32 {
    let Some(text) = config
        .sensitive_fields_multi_line
        .as_deref()
        .map(str::trim)
        .filter(|fields| !fields.is_empty())
    else {
        return 0;
    };

    match parse_json_line(text) {
        Value::Object(map) => map.len() as u32,
        Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_object())
            .map(|map| map.len() as u32)
            .sum(),
        _ => 0,
    }
}

fn format_dictum(summary: &DictumSummary, field_count: u32, trace_id: &str) -> String {
    let action = if summary.actions.is_empty() {
        "none".to_string()
    } else {
        summary.actions.join(",")
    };

    format!(
        "action={action}; ver={POLICY_VERSION}; fields={field_count}; risk=low; trace={trace_id}"
    )
}

#[cfg(test)]
mod dictum_tests {
    use super::*;

    struct MockHeaders {
        headers: Vec<(String, String)>,
    }

    impl HeadersHandler for MockHeaders {
        fn headers(&self) -> Vec<(String, String)> {
            self.headers.clone()
        }

        fn header(&self, name: &str) -> Option<String> {
            self.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.clone())
        }

        fn add_header(&self, _: &str, _: &str) {}
        fn set_header(&self, _: &str, _: &str) {}
        fn set_headers(&self, _: Vec<(&str, &str)>) {}
        fn remove_header(&self, _: &str) {}
    }

    #[test]
    fn extract_trace_id_from_traceparent() {
        let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        assert_eq!(
            extract_trace_id(traceparent),
            Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string())
        );
    }

    #[test]
    fn get_or_generate_trace_id_prefers_correlation_id() {
        let headers = MockHeaders {
            headers: vec![(
                "X-Correlation-ID".to_string(),
                "corr-12345".to_string(),
            )],
        };
        assert_eq!(get_or_generate_trace_id(&headers), "corr-12345");
    }

    #[test]
    fn join_uri_path_preserves_configured_stage() {
        assert_eq!(join_uri_path("/Prod", "/filter"), "/Prod/filter");
        assert_eq!(join_uri_path("/Prod", "/datacrypt"), "/Prod/datacrypt");
        assert_eq!(join_uri_path("/Prod", "/datacrypt-nlp"), "/Prod/datacrypt-nlp");
    }

    #[test]
    fn join_uri_path_supports_base_url_without_stage() {
        assert_eq!(join_uri_path("/", "/Prod/filter"), "/Prod/filter");
        assert_eq!(join_uri_path("", "/Prod/filter"), "/Prod/filter");
    }

    #[test]
    fn format_dictum_matches_expected_shape() {
        let mut dictum = DictumSummary::default();
        dictum.record_action("filter");
        dictum.record_action("datacrypt");
        assert_eq!(
            format_dictum(&dictum, 3, "db-8f2a1c91"),
            format!(
                "action=filter,datacrypt; ver={POLICY_VERSION}; fields=3; risk=low; trace=db-8f2a1c91"
            )
        );
    }

    #[test]
    fn resolve_encrypt_mode_defaults_to_none_for_new_configs() {
        assert_eq!(
            resolve_encrypt_mode(Some("None"), None),
            EncryptMode::None
        );
    }

    #[test]
    fn resolve_encrypt_mode_uses_manual_mode_from_new_config() {
        assert_eq!(
            resolve_encrypt_mode(Some("Specify Sensitive fields"), None),
            EncryptMode::SpecifySensitiveFields
        );
    }

    #[test]
    fn resolve_encrypt_mode_uses_nlp_mode_from_new_config() {
        assert_eq!(
            resolve_encrypt_mode(
                Some("Determine Sensitive fields using NLP (Identifies PII related to Financial, Contact, Identity, Auth, Device, Tax, Health, Vehicle, GOV ID, and URL data)"),
                Some(true)
            ),
            EncryptMode::DetermineFieldsUsingNlp
        );
    }

    #[test]
    fn resolve_encrypt_mode_keeps_support_for_previous_manual_label() {
        assert_eq!(
            resolve_encrypt_mode(Some("Specify Sensitive Fields"), None),
            EncryptMode::SpecifySensitiveFields
        );
    }

    #[test]
    fn resolve_encrypt_mode_keeps_support_for_previous_nlp_label() {
        assert_eq!(
            resolve_encrypt_mode(Some("Determine fields using NLP"), None),
            EncryptMode::DetermineFieldsUsingNlp
        );
    }

    #[test]
    fn resolve_encrypt_mode_falls_back_to_legacy_manual_flag() {
        assert_eq!(
            resolve_encrypt_mode(None, Some(true)),
            EncryptMode::SpecifySensitiveFields
        );
    }

    #[test]
    fn resolve_encrypt_mode_falls_back_to_legacy_nlp_flag() {
        assert_eq!(
            resolve_encrypt_mode(None, Some(false)),
            EncryptMode::DetermineFieldsUsingNlp
        );
    }

    #[test]
    fn resolve_encrypt_mode_treats_missing_values_as_none() {
        assert_eq!(resolve_encrypt_mode(None, None), EncryptMode::None);
    }
}

/// Parses the upstream response body as JSON when possible.
fn parse_response_json(bytes: &[u8]) -> Value {
    if bytes.is_empty() {
        return Value::Object(serde_json::Map::new());
    }

    if let Ok(value) = serde_json::from_slice(bytes) {
        return value;
    }

    // Upstream bodies are often gzip-compressed. We strip Content-Encoding before reading the
    // body (required before set_body), so Envoy may deliver compressed bytes to the policy.
    if is_gzip(bytes) {
        if let Some(decompressed) = decompress_gzip(bytes) {
            logger::info!(
                "{LOG_LABEL}Decompressed gzip response body ({} -> {} bytes)",
                bytes.len(),
                decompressed.len()
            );
            if let Ok(value) = serde_json::from_slice(&decompressed) {
                return value;
            }
            let text = String::from_utf8_lossy(&decompressed);
            if let Ok(value) = serde_json::from_str(text.trim()) {
                return value;
            }
        } else {
            logger::warn!("{LOG_LABEL}Failed to decompress gzip response body");
        }
    }

    let text = String::from_utf8_lossy(bytes);
    if let Ok(value) = serde_json::from_str(text.trim()) {
        return value;
    }

    logger::warn!(
        "{LOG_LABEL}Unable to parse upstream response as JSON ({} bytes)",
        bytes.len()
    );
    Value::String(text.into_owned())
}

fn is_gzip(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b
}

fn decompress_gzip(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = GzDecoder::new(bytes);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).ok()?;
    Some(decompressed)
}

/// DataCrypt filter/encrypt APIs require `data` to be a JSON object or array. When the Java
/// service receives a JSON string scalar it calls `JsonNode.toString()`, which yields a quoted
/// JSON string token that the filter rejects with "Unsupported JSON input type".
fn normalize_data_for_datacrypt(value: Value) -> Value {
    match value {
        Value::Object(_) | Value::Array(_) => value,
        Value::String(text) => {
            if let Ok(parsed) = serde_json::from_str(text.trim()) {
                return normalize_data_for_datacrypt(parsed);
            }
            let mut map = serde_json::Map::new();
            map.insert("value".to_string(), Value::String(text));
            Value::Object(map)
        }
        other => {
            let mut map = serde_json::Map::new();
            map.insert("value".to_string(), other);
            Value::Object(map)
        }
    }
}

/// Returns true when DataCrypt responded with its standard `{"error":"..."}` payload.
fn is_datacrypt_error(token: &str) -> bool {
    serde_json::from_str::<Value>(token)
        .ok()
        .and_then(|value| value.get("error").map(|error| error.is_string()))
        .unwrap_or(false)
}

const DATACRYPT_ERROR_PREFIX: &str = "ZTensor DataBlind ";

/// Prefixes DataCrypt's `{"error": "..."}` responses with "ZTensor DataBlind " so error
/// messages surfaced to the client are consistently branded. Non-error tokens pass through
/// unchanged.
fn brand_datacrypt_error(token: &str) -> String {
    if !is_datacrypt_error(token) {
        return token.to_string();
    }

    let Ok(mut value) = serde_json::from_str::<Value>(token) else {
        return token.to_string();
    };

    if let Some(error) = value.get("error").and_then(Value::as_str) {
        if !error.starts_with(DATACRYPT_ERROR_PREFIX) {
            value["error"] = Value::String(format!("{DATACRYPT_ERROR_PREFIX}{error}"));
        }
    }

    serde_json::to_string(&value).unwrap_or_else(|_| token.to_string())
}

// Kept for the commented-out sensitive-payload log call sites above; not currently invoked.
#[allow(dead_code)]
fn log_datacrypt_response(operation: &str, token: &str) {
    logger::info!("{LOG_LABEL}{operation} response JSON: {token}");
}

// Kept for the commented-out sensitive-payload log call sites above; not currently invoked.
#[allow(dead_code)]
fn log_message(label: &str, bytes: impl AsRef<[u8]>) {
    logger::info!(
        "{LOG_LABEL}{label}: {}",
        String::from_utf8_lossy(bytes.as_ref())
    );
}

/// Converts a DataCrypt token string into the `data` payload for a follow-on operation.
/// Matches Mule, which passes the raw filter-json output string into encrypt-json.
fn datacrypt_data_from_token(token: &str) -> Value {
    let trimmed = token.trim();
    match serde_json::from_str(trimmed) {
        Ok(value) => normalize_data_for_datacrypt(value),
        Err(err) => {
            logger::warn!(
                "{LOG_LABEL}Unable to parse DataCrypt token as JSON ({err}); using raw token text"
            );
            normalize_data_for_datacrypt(Value::String(trimmed.to_string()))
        }
    }
}

fn describe_data_for_log(value: &Value) -> String {
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        return format!("error={{\"error\":\"{error}\"}}");
    }

    match value {
        Value::Object(map) => {
            let keys: Vec<&String> = map.keys().take(8).collect();
            format!("object keys={keys:?}")
        }
        Value::Array(items) => format!("array len={}", items.len()),
        other => {
            let compact = serde_json::to_string(other).unwrap_or_else(|_| other.to_string());
            if compact.len() > 120 {
                format!("{}...", &compact[..120])
            } else {
                compact
            }
        }
    }
}

/// Reads `result.content[0].text` from an MCP-style response envelope and parses it as JSON.
fn extract_mcp_content_text(envelope: &Value) -> Result<Value> {
    let text = envelope
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("MCP response missing result.content[0].text string"))?;

    let parsed = serde_json::from_str(text.trim())
        .map_err(|err| anyhow!("MCP result.content[0].text is not valid JSON: {err}"))?;
    Ok(normalize_data_for_datacrypt(parsed))
}

/// Writes a DataCrypt token back into `result.content[0].text` on the MCP envelope.
fn apply_mcp_content_text(envelope: &mut Value, token: &str) -> Result<()> {
    let content_item = envelope
        .pointer_mut("/result/content/0")
        .and_then(|value| value.as_object_mut())
        .ok_or_else(|| anyhow!("MCP response missing result.content[0] object"))?;

    content_item.insert("text".to_string(), Value::String(token.to_string()));
    Ok(())
}

fn serialize_mcp_envelope(envelope: &Value) -> Result<String> {
    serde_json::to_string(envelope).map_err(|err| anyhow!("Failed to serialize MCP envelope: {err}"))
}

fn finalize_mcp_response(envelope: &mut Value, final_token: &str) -> Result<String> {
    apply_mcp_content_text(envelope, final_token)?;
    serialize_mcp_envelope(envelope)
}

fn join_uri_path(base_path: &str, endpoint_path: &str) -> String {
    let base_path = base_path.trim_end_matches('/');
    let endpoint = if endpoint_path.starts_with('/') {
        endpoint_path
    } else {
        return format!("/{endpoint_path}");
    };

    if base_path.is_empty() || base_path == "/" {
        endpoint.to_string()
    } else {
        format!("{base_path}{endpoint}")
    }
}

fn join_service_path(service: &Service, endpoint_path: &str) -> String {
    join_uri_path(service.uri().path(), endpoint_path)
}

/// Error from a DataCrypt call. Distinguishes a non-2xx HTTP response (which carries a status
/// code we can surface to the client) from anything else (network failure, malformed body).
#[derive(Debug)]
enum DataCryptCallError {
    Status { status: u32, body: String },
    /// Anything else: network/dispatch failure (no status available), or a 2xx response whose
    /// body couldn't be parsed (status known, but not a rejection — kept separate from `Status`).
    Other { status: Option<u32>, message: String },
}

impl DataCryptCallError {
    /// The HTTP status DataCrypt responded with, if one was ever obtained.
    fn status(&self) -> Option<u32> {
        match self {
            Self::Status { status, .. } => Some(*status),
            Self::Other { status, .. } => *status,
        }
    }
}

impl std::fmt::Display for DataCryptCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status { status, body } => write!(f, "DataCrypt returned status {status}: {body}"),
            Self::Other { message, .. } => write!(f, "{message}"),
        }
    }
}

/// Performs a POST against the DataCrypt service and returns the resulting token.
async fn call_datacrypt(
    client: &HttpClient,
    service: &Service,
    operation: &str,
    path: &str,
    request: &DataCryptRequest,
    api_key: Option<&str>,
) -> Result<String, DataCryptCallError> {
    let request_path = join_service_path(service, path);
    let body = serde_json::to_vec(request).map_err(|err| DataCryptCallError::Other {
        status: None,
        message: format!("Failed to serialize DataCrypt {operation} request: {err}"),
    })?;

    let mut headers: Vec<(&str, &str)> = vec![("Content-Type", "application/json")];
    if let Some(key) = api_key.filter(|key| !key.is_empty()) {
        headers.push(("x-api-key", key));
    } else {
        logger::warn!(
            "{LOG_LABEL}{operation} call to {request_path} has no x-api-key header configured"
        );
    }

    logger::info!("{LOG_LABEL}Calling DataCrypt {operation} at {request_path}");

    let response = client
        .request(service)
        .path(&request_path)
        .headers(headers)
        .body(&body)
        .post()
        .await
        .map_err(|err| DataCryptCallError::Other {
            status: None,
            message: format!("DataCrypt {operation} request to {request_path} failed: {err:?}"),
        })?;

    let status = response.status_code();
    logger::info!("{LOG_LABEL}DataCrypt {operation} at {request_path} responded with status {status}");
    if (200..300).contains(&status) {
        let parsed: DataCryptResponse =
            serde_json::from_slice(response.body()).map_err(|err| DataCryptCallError::Other {
                status: Some(status),
                message: format!(
                    "DataCrypt {operation} returned status {status} but the response body could not be parsed: {err}"
                ),
            })?;
        Ok(parsed.token)
    } else {
        Err(DataCryptCallError::Status {
            status,
            body: String::from_utf8_lossy(response.body()).into_owned(),
        })
    }
}

fn normalized_api_key(key: &str) -> Option<String> {
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.contains("Please contact") || trimmed.contains('@') {
        return None;
    }

    Some(trimmed.to_string())
}

fn warn_if_api_key_missing(label: &str, key: Option<&str>) {
    if key.is_some() {
        return;
    }

    logger::warn!(
        "{LOG_LABEL}{label} is missing or still set to the placeholder value; DataCrypt calls will return 403 Forbidden until a valid x-api-key is configured in API Manager"
    );
}

/// Replaces the response body with a generic ZTensor DataBlind error. Used as the fail-closed
/// path: when filtering/encryption was configured but couldn't be completed (parse failure or a
/// failed DataCrypt call), we block the response instead of letting the original, unprotected
/// upstream payload reach the client.
fn block_unprotected_response(headers_body_handler: &dyn HeadersBodyHandler, reason: &str) {
    let body = serde_json::json!({ "error": format!("{DATACRYPT_ERROR_PREFIX}{reason}") });
    let body_bytes = serde_json::to_vec(&body)
        .unwrap_or_else(|_| b"{\"error\":\"ZTensor DataBlind response blocked\"}".to_vec());

    match headers_body_handler.set_body(&body_bytes) {
        Ok(_) => logger::warn!("{LOG_LABEL}DataBlind fail-safe: response blocked ({reason})"),
        Err(err) => logger::warn!(
            "{LOG_LABEL}DataBlind fail-safe: unable to block response ({reason}): {err:?}"
        ),
    }
}

/// Reads override credentials and trace context from the inbound request so they are available
/// when the upstream response is processed.
async fn request_filter(state: RequestState, config: &RuntimeConfig) -> Flow<RequestContext> {
    logger::info!("{LOG_LABEL}Processing inbound request headers for override credentials");
    let headers_state = state.into_headers_state().await;
    let headers_handler = headers_state.handler();
    let trace_id = get_or_generate_trace_id(headers_handler);

    let mut token_eval = config.data_blind_token.evaluator();
    token_eval.bind_attributes(&HandlerAttributesBinding::partial(headers_handler));
    let token: String = token_eval
        .eval()
        .and_then(TryFromValue::try_from_value)
        .unwrap_or_default();
    // TEMP(testing): logging raw secret value — remove before release.
    // logger::info!("{LOG_LABEL}Resolved dataBlindToken: {token}");

    let mut passphrase_eval = config.data_blind_passphrase.evaluator();
    passphrase_eval.bind_attributes(&HandlerAttributesBinding::partial(headers_handler));
    let passphrase: String = passphrase_eval
        .eval()
        .and_then(TryFromValue::try_from_value)
        .unwrap_or_default();
    // TEMP(testing): logging raw secret value — remove before release.
    // logger::info!("{LOG_LABEL}Resolved dataBlindPassphrase: {passphrase}");

    let _body_state = headers_state.into_body_state().await;
    // Sensitive: logs the raw inbound request body verbatim.
    // log_message("Inbound message", body_state.handler().body());

    Flow::Continue(RequestContext {
        token,
        passphrase,
        trace_id,
    })
}

/// Applies DataBlind protection to the upstream response when its status code is eligible.
async fn response_filter(
    state: ResponseState,
    request_data: RequestData<RequestContext>,
    config: &RuntimeConfig,
    client: &HttpClient,
) {
    let request_context = match request_data {
        RequestData::Continue(context) => context,
        _ => RequestContext::default(),
    };

    let headers_state = state.into_headers_state().await;
    let status_code = headers_state.status_code();
    logger::info!(
        "{LOG_LABEL} Upstream response  returned status {status_code}"
    );

    // Only apply DataBlind when the response status code is in the eligible list.
    let mut eligible_eval = config.eligible_http_codes.evaluator();
    eligible_eval.bind_attributes(&HandlerAttributesBinding::partial(headers_state.handler()));
    let eligible_codes: String = eligible_eval
        .eval()
        .and_then(TryFromValue::try_from_value)
        .unwrap_or_default();
    // logger::info!("{LOG_LABEL}Resolved eligibleHttpCodes: {eligible_codes}");

    let is_eligible = eligible_codes
        .split(',')
        .any(|code| code.trim() == status_code.to_string());

    if !is_eligible {
        logger::info!("{LOG_LABEL}DataBlind encryption ignored for status code {status_code}");
        return;
    }

    // Strip encoding/length headers before reading or replacing the body. Upstream responses
    // are often gzip-compressed; leaving Content-Encoding after set_body causes clients to fail
    // decompression with "incorrect header check".
    let headers_handler = headers_state.handler();
    headers_handler.remove_header("content-length");
    headers_handler.remove_header("content-encoding");
    headers_handler.remove_header("transfer-encoding");
    headers_handler.set_header("content-type", "application/json");

    let headers_body_state = headers_state.into_headers_body_state().await;
    let headers_body_handler = headers_body_state.handler();
    let payload_bytes = headers_body_handler.body();
    // Sensitive: logs the raw upstream response body (pre-protection) verbatim.
    // log_message("Outbound message (upstream)", &payload_bytes);

    let credentials = request_context;
    let mut dictum = DictumSummary::default();
    let field_count = count_sensitive_fields(config);
    let data_crypt_api_key = normalized_api_key(&config.data_crypt_api_key);
    warn_if_api_key_missing("dataCryptApiKey", data_crypt_api_key.as_deref());

    let key: String = config
        .data_blind_key
        .evaluator()
        .eval()
        .and_then(TryFromValue::try_from_value)
        .unwrap_or_default();
    // TEMP(testing): logging raw secret value — remove before release.
    // logger::info!("{LOG_LABEL}Resolved dataBlindKey: {key}");

    let mut tweak_eval = config.tweak.evaluator();
    tweak_eval.bind_payload(&headers_body_state);
    let tweak: String = tweak_eval
        .eval()
        .and_then(TryFromValue::try_from_value)
        .unwrap_or_default();
    // logger::info!("{LOG_LABEL}Resolved tweak: {tweak}");

    // Computed up front so both failure points below know whether protection was actually
    // configured, and therefore whether a failure should block the response (fail-closed) or
    // simply pass it through unchanged (nothing was requested).
    let filter_rule = build_filter_rule(config);
    let protection_requested = filter_rule.is_some() || config.encrypt_mode != EncryptMode::None;

    // Parse the MCP envelope and extract result.content[0].text for the DataCrypt pipeline.
    let mut mcp_envelope = normalize_data_for_datacrypt(parse_response_json(&payload_bytes));
    let mut datacrypt_data = match extract_mcp_content_text(&mcp_envelope) {
        Ok(data) => {
            logger::info!(
                "{LOG_LABEL}MCP result.content[0].text parsed for DataCrypt pipeline ({})",
                describe_data_for_log(&data)
            );
            data
        }
        Err(err) => {
            logger::warn!("{LOG_LABEL}Unable to parse MCP result.content[0].text: {err}");
            if protection_requested {
                block_unprotected_response(
                    headers_body_handler,
                    "upstream response could not be parsed as an MCP envelope",
                );
            }
            return;
        }
    };

    logger::info!(
        "{LOG_LABEL}Upstream MCP response parsed ({} bytes, content: {})",
        payload_bytes.len(),
        describe_data_for_log(&datacrypt_data)
    );

    let mut final_token: Option<String> = None;
    // Set whenever a DataCrypt call fails with a non-2xx status, so the fail-closed block
    // below can report the specific status instead of a generic message.
    let mut protection_failure_reason: Option<String> = None;

    // Step 1: optional filtering (replaces the zt:filter-json operation).
    if let Some(filter_rule) = filter_rule {
        let request = DataCryptRequest {
            key: key.clone(),
            tweak: None,
            data: datacrypt_data.clone(),
            sensitive_fields: None,
            filter_rule: Some(filter_rule),
            over_ride_token: credentials.token.clone(),
            over_ride_pass_phrase: credentials.passphrase.clone(),
        };

        match call_datacrypt(
            client,
            &config.data_crypt_service,
            "filterRule",
            FILTER_PATH,
            &request,
            data_crypt_api_key.as_deref(),
        )
        .await
        {
            Ok(token) => {
                let token = brand_datacrypt_error(&token);
                dictum.record_action("filter");
                // Sensitive: logs the filtered-but-not-yet-encrypted plaintext response.
                // log_datacrypt_response("filterRule", &token);
                datacrypt_data = datacrypt_data_from_token(&token);
                if is_datacrypt_error(&token) {
                    logger::warn!("{LOG_LABEL}filterRule returned error: {token}");
                } else {
                    logger::info!("{LOG_LABEL}filterRule applied");
                }
                final_token = Some(token);
                logger::info!(
                    "{LOG_LABEL}Encrypt step will use filter output ({})",
                    describe_data_for_log(&datacrypt_data)
                );
            }
            Err(err) => {
                match err.status() {
                    Some(status) => {
                        logger::warn!("{LOG_LABEL}filterRule call failed (status {status}): {err}");
                        protection_failure_reason = Some(format!(
                            "Unable to create a protected response message, caused DataBlind API Error {status}. Verify the DataBlind configuration."
                        ));
                    }
                    None => {
                        logger::warn!("{LOG_LABEL}filterRule call failed: {err}");
                        protection_failure_reason = Some(
                            "Unable to create a protected response message, could not reach the DataBlind service. Verify the DataBlind configuration.".to_string()
                        );
                    }
                }
            }
        }
    }

    // Step 2: encryption. Use manually specified sensitive fields, AI based redaction, or skip.
    match config.encrypt_mode {
        EncryptMode::None => {
            logger::info!("{LOG_LABEL}Encrypt mode is None; skipping encryption step");
        }
        EncryptMode::SpecifySensitiveFields => {
            let sensitive_fields = config
                .sensitive_fields_multi_line
                .as_deref()
                .map(str::trim)
                .filter(|fields| !fields.is_empty())
                .map(parse_json_line);

            logger::info!(
                "{LOG_LABEL}Calling encrypt-json with data: {}",
                describe_data_for_log(&datacrypt_data)
            );

            let request = DataCryptRequest {
                key: key.clone(),
                tweak: Some(tweak.clone()),
                data: datacrypt_data.clone(),
                sensitive_fields,
                filter_rule: None,
                over_ride_token: credentials.token.clone(),
                over_ride_pass_phrase: credentials.passphrase.clone(),
            };

            match call_datacrypt(
                client,
                &config.data_crypt_service,
                "encrypt-json",
                DATACRYPT_PATH,
                &request,
                data_crypt_api_key.as_deref(),
            )
            .await
            {
                Ok(token) => {
                    let token = brand_datacrypt_error(&token);
                    dictum.record_action("datacrypt");
                    if is_datacrypt_error(&token) {
                        logger::warn!("{LOG_LABEL}encrypt-json returned error: {token}");
                    } else {
                        // Sensitive: logs the encrypt-json response verbatim. Not guaranteed
                        // to be safe — if the configured sensitive fields don't match the
                        // payload's actual field names, this token is unmasked plaintext.
                        // log_datacrypt_response("encrypt-json", &token);
                    }
                    final_token = Some(token);
                }
                Err(err) => {
                    match err.status() {
                        Some(status) => {
                            logger::warn!("{LOG_LABEL}encrypt-json call failed (status {status}): {err}");
                            protection_failure_reason = Some(format!(
                                "Unable to create a protected response message, caused DataBlind API Error {status}. Verify the DataBlind configuration."
                            ));
                        }
                        None => {
                            logger::warn!("{LOG_LABEL}encrypt-json call failed: {err}");
                            protection_failure_reason = Some(
                                "Unable to create a protected response message, could not reach the DataBlind service. Verify the DataBlind configuration.".to_string()
                            );
                        }
                    }
                }
            }
        }
        EncryptMode::DetermineFieldsUsingNlp => {
            logger::info!(
                "{LOG_LABEL}Sensitive fields not specified, using AI to determine sensitive fields"
            );

            logger::info!(
                "{LOG_LABEL}Calling datacrypt-nlp with data: {}",
                describe_data_for_log(&datacrypt_data)
            );

            let request = DataCryptRequest {
                key: key.clone(),
                tweak: Some(tweak.clone()),
                data: datacrypt_data.clone(),
                sensitive_fields: None,
                filter_rule: None,
                over_ride_token: credentials.token.clone(),
                over_ride_pass_phrase: credentials.passphrase.clone(),
            };

            match call_datacrypt(
                client,
                &config.data_crypt_service,
                "datacrypt-nlp",
                NLP_PATH,
                &request,
                data_crypt_api_key.as_deref(),
            )
            .await
            {
                Ok(token) => {
                    let token = brand_datacrypt_error(&token);
                    dictum.record_action("datacrypt-nlp");
                    if is_datacrypt_error(&token) {
                        logger::warn!("{LOG_LABEL}AI redaction returned error: {token}");
                    } else {
                        // Sensitive: logs the datacrypt-nlp response verbatim. Not guaranteed
                        // to be safe — if NLP redaction doesn't catch every sensitive field,
                        // this token can contain unmasked plaintext.
                        // log_datacrypt_response("datacrypt-nlp", &token);
                    }
                    final_token = Some(token);
                }
                Err(err) => {
                    match err.status() {
                        Some(status) => {
                            logger::warn!("{LOG_LABEL}AI redaction call failed (status {status}): {err}");
                            protection_failure_reason = Some(format!(
                                "Unable to create a protected response message, caused DataBlind API Error {status}. Verify the DataBlind configuration."
                            ));
                        }
                        None => {
                            logger::warn!("{LOG_LABEL}AI redaction call failed: {err}");
                            protection_failure_reason = Some(
                                "Unable to create a protected response message, could not reach the DataBlind service. Verify the DataBlind configuration.".to_string()
                            );
                        }
                    }
                }
            }
        }
    }

    // Step 3: write the protected token back into result.content[0].text and replace the response body.
    let response_body = final_token.and_then(|token| {
        finalize_mcp_response(&mut mcp_envelope, &token)
            .map_err(|err| logger::warn!("{LOG_LABEL}Unable to finalize MCP response: {err}"))
            .ok()
    });

    if let Some(out) = response_body {
        // Sensitive: logs the full outbound response body, which is plaintext whenever
        // encryption was skipped (filter-only or encryptMode None).
        // logger::info!(
        //     "{LOG_LABEL}Outbound message (protected): {out}"
        // );
        logger::info!(
            "{LOG_LABEL}Setting response body ({} bytes)",
            out.len()
        );
        match headers_body_handler.set_body(out.as_bytes()) {
            Ok(_) => logger::info!("{LOG_LABEL}DataBlind encryption completed"),
            Err(err) => logger::warn!("{LOG_LABEL}Unable to set response body: {err:?}"),
        }
    } else if protection_requested {
        // Fail closed: filtering/encryption was configured but no protected output was
        // produced (a DataCrypt call failed) — block rather than let the unprotected
        // upstream payload reach the client. Use the specific status-based reason if one
        // of the DataCrypt calls failed with a non-2xx response; otherwise fall back to
        // the generic message (e.g. a network failure with no status code at all).
        let reason = protection_failure_reason
            .unwrap_or_else(|| " Unable to produce a protected response".to_string());
        block_unprotected_response(headers_body_handler, &reason);
    } else {
        logger::info!(
            "{LOG_LABEL}No DataBlind processing configured; upstream response body left unchanged"
        );
    }

    let dictum_value = format_dictum(&dictum, field_count, &credentials.trace_id);
    headers_body_handler.set_header(DICTUM_HEADER, &dictum_value);
    logger::info!("{LOG_LABEL}Set {DICTUM_HEADER}: {dictum_value}");
}

#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    client: HttpClient,
) -> Result<()> {
    let config = RuntimeConfig::from_bytes(&bytes)?;

    // Warn-level so this appears even when policy logging is set to warn in API Manager.
    logger::warn!(
        "{LOG_LABEL}Policy loaded ({POLICY_INJECTION_POINT} injection point, handlers: on_request + on_response)"
    );
    warn_if_api_key_missing(
        "dataCryptApiKey",
        normalized_api_key(&config.data_crypt_api_key).as_deref(),
    );

    let filter = on_request(|rs| request_filter(rs, &config))
        .on_response(|rs, request_data| response_filter(rs, request_data, &config, &client));

    launcher.launch(filter).await?;
    Ok(())
}
