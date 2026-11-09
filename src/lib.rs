// Copyright 2023 Salesforce, Inc. All rights reserved.
mod generated;
mod key_resolution;

use anyhow::{anyhow, Result};
use flate2::read::GzDecoder;
use std::{io::Read, ops::Deref, time::{Duration, UNIX_EPOCH}};

use pdk::cache::{Cache, CacheBuilder};
use pdk::hl::timer::Clock;
use pdk::hl::*;
use pdk::logger;
use pdk::script::{HandlerAttributesBinding, TryFromValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::generated::config::Config as GeneratedConfig;
use crate::key_resolution::{
    decode_cache_entry, encode_cache_entry, needs_workload_check, parse_resolve_response, plan,
    validate_key_source, validate_mode_config, workload_guid_from_passphrase, Credentials, Plan,
    ResolveFailure, ResolveRequest, ResolveResponse,
};

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

// Key-resolution mode (see key_resolution.rs): the key service endpoint appended to
// keyServiceUrl, how long to wait for it, and where the fetched key is cached.
const KEY_RESOLVE_PATH: &str = "/app-zone-key-resolve";
const KEY_SERVICE_TIMEOUT: Duration = Duration::from_secs(5);
const KEY_CACHE_ID: &str = "datablind-zone-key";
const KEY_CACHE_ENTRY: &str = "zone-key";

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
        let inner: GeneratedConfig =
            serde_json::from_slice(bytes).map_err(|err| config_parse_error("configuration", &err))?;
        let compatibility: ConfigCompatibility = serde_json::from_slice(bytes)
            .map_err(|err| config_parse_error("configuration compatibility", &err))?;

        Ok(Self {
            encrypt_mode: resolve_encrypt_mode(
                inner.encrypt_mode.as_deref(),
                compatibility.sensitive_fields_specified,
            ),
            inner,
        })
    }
}

/// A configuration parse failure that never repeats the configuration (it holds
/// secrets such as policyAccessKey and dataCryptApiKey) or serde's message (which
/// can echo a mistyped value): only the kind of error and where it is.
fn config_parse_error(what: &str, err: &serde_json::Error) -> anyhow::Error {
    anyhow!(
        "Failed to parse {what}: {:?} error at line {} column {}",
        err.classify(),
        err.line(),
        err.column()
    )
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

/// Builds the filter rule JSON sent to DataCrypt from the Filter Rule UI fields. Emits the
/// conditions-based shape the DataCrypt filter API supports:
///
/// ```json
/// { "filter": "exclude", "operator": "OR", "conditions": { "status": "inactive", ... } }
/// ```
///
/// The `conditions` object is assembled from the repeatable Filter Conditions list (each entry has a
/// field, match type, and value). Returns `None` (skip the filter step) when the mode is
/// "None"/unset or when no usable conditions are configured.
fn build_filter_rule(config: &RuntimeConfig) -> Option<Value> {
    // Normalize to lowercase so the emitted rule always uses "include"/"exclude" (what DataCrypt
    // expects), regardless of how the mode is cased in the UI enum. Any mode other than
    // include/exclude (e.g. the default "None") skips filtering entirely.
    let mode = config
        .filter_mode
        .as_deref()
        .unwrap_or("none")
        .to_lowercase();
    if mode != "include" && mode != "exclude" {
        return None;
    }

    let conditions = build_filter_conditions(config);
    if conditions.is_empty() {
        return None;
    }

    let operator = normalize_filter_operator(config.filter_operator.as_deref());

    let mut rule = serde_json::Map::new();
    rule.insert("filter".to_string(), Value::String(mode));
    rule.insert("operator".to_string(), Value::String(operator.to_string()));
    rule.insert("conditions".to_string(), Value::Object(conditions));
    Some(Value::Object(rule))
}

/// Normalizes the configured operator to the "OR"/"AND" tokens DataCrypt expects, defaulting to
/// "OR" when unset or unrecognized.
fn normalize_filter_operator(operator: Option<&str>) -> &'static str {
    match operator
        .map(str::trim)
        .filter(|op| !op.is_empty())
        .map(str::to_ascii_uppercase)
        .as_deref()
    {
        Some("AND") => "AND",
        _ => "OR",
    }
}

/// Assembles the `conditions` object from the repeatable Filter Conditions list. Each entry becomes
/// one `field -> value` pair:
/// - A single value is shaped by the entry's match type:
///   - Simple: the value directly (`"field": "value"`)
///   - Exact/Regex: `{ "type": "exact|regex", "value": "value" }`
/// - Multiple (comma-separated) values always emit a plain array (`"field": ["a", "b"]`), which the
///   DataCrypt filter API matches as "any of". Regex/Exact typing does not apply to arrays, so a
///   configured Regex match type is ignored (with a warning) when multiple values are given.
///
/// Entries with a blank field or blank value are skipped.
fn build_filter_conditions(config: &RuntimeConfig) -> serde_json::Map<String, Value> {
    let mut conditions = serde_json::Map::new();

    let items = match config.filter_conditions.as_ref() {
        Some(items) => items,
        None => return conditions,
    };

    for item in items {
        // Accept the field name with or without surrounding quotes (e.g. person.phone or
        // "person.phone").
        let field = match item
            .field
            .as_deref()
            .map(|field| field.trim().trim_matches('"'))
            .filter(|field| !field.is_empty())
        {
            Some(field) => field,
            None => continue,
        };

        let value = parse_condition_value(item.value.as_deref().unwrap_or_default());

        let match_type = item
            .match_type
            .as_deref()
            .map(str::trim)
            .filter(|match_type| !match_type.is_empty())
            .unwrap_or("Simple")
            .to_ascii_lowercase();

        let condition_value = match value {
            // No usable value: skip this entry.
            Value::Null => continue,
            // Multiple values are an "any of" match, sent as a plain array. Regex/Exact matchers
            // only apply to a single value, so they are not wrapped here.
            Value::Array(_) => {
                if match_type == "regex" {
                    logger::warn!(
                        "{LOG_LABEL}filter condition for '{field}' uses Regex with multiple values; \
                         regex is not supported for arrays, matching any of the listed values instead"
                    );
                }
                value
            }
            // Single value: apply the match type.
            single => match match_type.as_str() {
                "exact" | "regex" => {
                    let mut typed = serde_json::Map::new();
                    typed.insert("type".to_string(), Value::String(match_type));
                    typed.insert("value".to_string(), single);
                    Value::Object(typed)
                }
                // "simple" (and any unknown type) emits the value directly.
                _ => single,
            },
        };

        conditions.insert(field.to_string(), condition_value);
    }

    conditions
}

/// Parses a condition value into JSON: a single trimmed string, or an array of strings when the raw
/// value is a comma-separated list. Returns `Value::Null` when there is no usable value.
fn parse_condition_value(raw: &str) -> Value {
    let values: Vec<Value> = raw
        .split(',')
        .map(|value| value.trim().trim_matches('"'))
        .filter(|value| !value.is_empty())
        .map(|value| Value::String(value.to_string()))
        .collect();

    match values.len() {
        0 => Value::Null,
        1 => values.into_iter().next().unwrap_or(Value::Null),
        _ => Value::Array(values),
    }
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
    fn normalize_filter_operator_defaults_and_maps() {
        assert_eq!(normalize_filter_operator(None), "OR");
        assert_eq!(normalize_filter_operator(Some("")), "OR");
        assert_eq!(normalize_filter_operator(Some("or")), "OR");
        assert_eq!(normalize_filter_operator(Some(" And ")), "AND");
        assert_eq!(normalize_filter_operator(Some("AND")), "AND");
        assert_eq!(normalize_filter_operator(Some("xor")), "OR");
    }

    #[test]
    fn parse_condition_value_handles_single_and_multiple() {
        assert!(matches!(parse_condition_value(""), Value::Null));
        assert!(matches!(parse_condition_value("  , "), Value::Null));
        assert_eq!(
            parse_condition_value("US"),
            Value::String("US".to_string())
        );
        assert_eq!(
            parse_condition_value("\"US\""),
            Value::String("US".to_string())
        );
        assert_eq!(
            parse_condition_value("123, 456"),
            Value::Array(vec![
                Value::String("123".to_string()),
                Value::String("456".to_string()),
            ])
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

fn log_datacrypt_response(_operation: &str, _token: &str) {
    // logger::info!("{LOG_LABEL}{operation} response JSON: {token}");
}

fn log_message(label: &str, bytes: impl AsRef<[u8]>) {
    logger::info!(
        "{LOG_LABEL}{label}: {}",
        String::from_utf8_lossy(bytes.as_ref())
    );
}

/// Whether request/response payloads should be logged. Enabled per environment via the
/// `debugLogging` config flag (on in lower environments, off in higher environments).
fn debug_logging_enabled(config: &RuntimeConfig) -> bool {
    config.debug_logging.unwrap_or(false)
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

/// Performs a POST against the DataCrypt service and returns the resulting token.
async fn call_datacrypt(
    client: &HttpClient,
    service: &Service,
    operation: &str,
    path: &str,
    request: &DataCryptRequest,
    api_key: Option<&str>,
) -> Result<(u32, String)> {
    let request_path = join_service_path(service, path);
    let body = serde_json::to_vec(request)?;

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
        .map_err(|err| anyhow!("DataCrypt {operation} request to {request_path} failed: {err:?}"))?;

    let status = response.status_code();
    logger::info!("{LOG_LABEL}{operation} HTTP response code: {status}");
    if status == 200 {
        let parsed: DataCryptResponse = serde_json::from_slice(response.body())?;
        Ok((status, parsed.token))
    } else {
        Err(anyhow!(
            "DataCrypt {operation} returned status {status} for {request_path}: {}",
            String::from_utf8_lossy(response.body())
        ))
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

/// Replaces the upstream response with a generic policy failure.
fn block_unprotected_response(handler: &dyn HeadersBodyHandler) {
    let body = br#"{"error":"DataBlind policy failed to apply. Retry again."}"#;

    handler.set_header(":status", "500");
    match handler.set_body(body) {
        Ok(_) => {
            logger::warn!("{LOG_LABEL}DataBlind fail-safe: response blocked with status 500")
        }
        Err(set_err) => logger::warn!(
            "{LOG_LABEL}DataBlind fail-safe: unable to replace response body: {set_err:?}"
        ),
    }
}

/// Where the DataBlind key comes from for this policy instance.
enum KeyMode<'a> {
    /// dataBlindKey is configured directly (the original behaviour, unchanged).
    Legacy,
    /// The key is fetched from datablindcp with a policy access key.
    Resolved { key_id: &'a str, service: &'a Service, access_key: &'a str },
    /// keyId is set but the rest is missing. Startup validation prevents this; if it
    /// ever happened the response is blocked rather than falling back to another key.
    Misconfigured,
}

fn key_mode(config: &RuntimeConfig) -> KeyMode<'_> {
    let key_id = config.key_id.as_deref().map(str::trim).unwrap_or("");
    if key_id.is_empty() {
        return KeyMode::Legacy;
    }
    match (&config.key_service_url, config.policy_access_key.as_deref().map(str::trim)) {
        (Some(service), Some(access_key)) if !access_key.is_empty() => {
            KeyMode::Resolved { key_id, service, access_key }
        }
        _ => KeyMode::Misconfigured,
    }
}

/// Milliseconds since the Unix epoch, or None if the clock is unusable (then the
/// key cache is bypassed rather than trusted with a bogus time).
fn now_millis(clock: &Clock) -> Option<u64> {
    clock.now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_millis() as u64)
}

/// Asks the key service for the app zone key (and, when the caller sent override
/// credentials, whether they are valid). Logs only status codes: never the key,
/// the access key, the caller's credentials, or a response body.
async fn resolve_key(
    client: &HttpClient,
    service: &Service,
    access_key: &str,
    request: &ResolveRequest<'_>,
) -> Result<ResolveResponse, ResolveFailure> {
    let path = join_service_path(service, KEY_RESOLVE_PATH);
    let body = serde_json::to_vec(request).map_err(|_| ResolveFailure::Malformed)?;
    let headers: Vec<(&str, &str)> = vec![
        ("Content-Type", "application/json"),
        ("x-policy-access-key", access_key),
    ];

    let response = client
        .request(service)
        .path(&path)
        .headers(headers)
        .body(&body)
        .timeout(KEY_SERVICE_TIMEOUT)
        .post()
        .await
        .map_err(|_| {
            logger::warn!("{LOG_LABEL}Key service request failed (network error or timeout)");
            ResolveFailure::Transport
        })?;

    let status = response.status_code();
    if status != 200 {
        logger::warn!("{LOG_LABEL}Key service answered with status {status}");
    }
    parse_resolve_response(status, response.body())
}

/// Key-resolution mode: decides which key to use and which override credentials
/// DataCrypt may see, using the cache where that is safe. The workload/token
/// verdict is never cached: a request that carries override credentials always
/// asks the key service, so revocation applies on the very next request.
async fn plan_resolved_key(
    client: &HttpClient,
    cache: &dyn Cache,
    clock: &Clock,
    key_id: &str,
    service: &Service,
    access_key: &str,
    caller: &Credentials,
) -> Plan {
    let now_ms = now_millis(clock);
    let cached_key = now_ms
        .and_then(|now| cache.get(KEY_CACHE_ENTRY).and_then(|bytes| decode_cache_entry(&bytes, key_id, now)));

    let check_workload = needs_workload_check(caller);
    let outcome = if cached_key.is_some() && !check_workload {
        None
    } else {
        let request = ResolveRequest {
            key_id,
            workload_guid: if check_workload { workload_guid_from_passphrase(&caller.passphrase) } else { None },
            override_token: if check_workload { Some(caller.token.as_str()) } else { None },
        };
        Some(resolve_key(client, service, access_key, &request).await)
    };

    let called = outcome.is_some();
    let decision = plan(cached_key, outcome, caller, check_workload);
    if let Plan::Use { key, creds, cache_it } = &decision {
        logger::info!(
            "{LOG_LABEL}Key resolution: service_called={called} workload_check_requested={check_workload} override_credentials_forwarded={}",
            !creds.token.is_empty()
        );
        if *cache_it {
            if let Some(now) = now_ms {
                if cache.save(KEY_CACHE_ENTRY, encode_cache_entry(key_id, key, now)).is_err() {
                    logger::warn!("{LOG_LABEL}Could not cache the DataBlind key");
                }
            }
        }
    }
    decision
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

    let body_state = headers_state.into_body_state().await;
    if debug_logging_enabled(config) {
        log_message("Inbound message", body_state.handler().body());
    }

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
    cache: &dyn Cache,
    clock: &Clock,
) {
    let request_context = match request_data {
        RequestData::Continue(context) => context,
        _ => RequestContext::default(),
    };

    let headers_state = state.into_headers_state().await;
    let status_code = headers_state.status_code();
    logger::info!(
        "{LOG_LABEL}Processing outbound response (status {status_code})"
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
    if debug_logging_enabled(config) {
        log_message("Outbound message (upstream)", &payload_bytes);
    }

    let mut credentials = request_context;
    let mut dictum = DictumSummary::default();
    let field_count = count_sensitive_fields(config);
    let data_crypt_api_key = normalized_api_key(&config.data_crypt_api_key);
    warn_if_api_key_missing("dataCryptApiKey", data_crypt_api_key.as_deref());

    let key: String = match key_mode(config) {
        // Legacy mode: the key is configured directly. (dataBlindKey is optional now; an
        // unset value behaves like an empty key, exactly as an unevaluable one always did.)
        KeyMode::Legacy => config
            .data_blind_key
            .as_ref()
            .map(|script| {
                script
                    .evaluator()
                    .eval()
                    .and_then(TryFromValue::try_from_value)
                    .unwrap_or_default()
            })
            .unwrap_or_default(),
        KeyMode::Misconfigured => {
            logger::error!("{LOG_LABEL}Key resolution is only partly configured; blocking the response");
            block_unprotected_response(headers_body_handler);
            return;
        }
        KeyMode::Resolved { key_id, service, access_key } => {
            let caller = Credentials {
                token: credentials.token.clone(),
                passphrase: credentials.passphrase.clone(),
            };
            match plan_resolved_key(client, cache, clock, key_id, service, access_key, &caller).await {
                Plan::Block => {
                    logger::warn!("{LOG_LABEL}No DataBlind key is available from the key service; blocking the response");
                    block_unprotected_response(headers_body_handler);
                    return;
                }
                Plan::Use { key, creds, .. } => {
                    // DataCrypt only ever sees override credentials the key service confirmed.
                    credentials.token = creds.token;
                    credentials.passphrase = creds.passphrase;
                    key
                }
            }
        }
    };
    // TEMP(testing): logging raw secret value — remove before release.
    // logger::info!("{LOG_LABEL}Resolved dataBlindKey: {key}");

    let mut tweak_eval = config.tweak.evaluator();
    tweak_eval.bind_payload(&headers_body_state);
    let tweak: String = tweak_eval
        .eval()
        .and_then(TryFromValue::try_from_value)
        .unwrap_or_default();
    // logger::info!("{LOG_LABEL}Resolved tweak: {tweak}");

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
            return;
        }
    };

    logger::info!(
        "{LOG_LABEL}Upstream MCP response parsed ({} bytes, content: {})",
        payload_bytes.len(),
        describe_data_for_log(&datacrypt_data)
    );

    let mut final_token: Option<String> = None;

    // HTTP response codes from each DataCrypt call, collected for later use (logged below for now).
    let mut filter_status_code: Option<u32> = None;
    let mut encrypt_status_code: Option<u32> = None;
    let mut nlp_status_code: Option<u32> = None;

    // Step 1: optional filtering (replaces the zt:filter-json operation).
    if let Some(filter_rule) = build_filter_rule(config) {
        logger::info!(
            "{LOG_LABEL}filterRule criteria: {}",
            serde_json::to_string(&filter_rule)
                .unwrap_or_else(|_| filter_rule.to_string())
        );
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
            Ok((status, token)) => {
                filter_status_code = Some(status);
                dictum.record_action("filter");
                log_datacrypt_response("filterRule", &token);
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
                logger::warn!("{LOG_LABEL}filterRule call failed: {err}");
                block_unprotected_response(headers_body_handler);
                return;
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
                Ok((status, token)) => {
                    encrypt_status_code = Some(status);
                    dictum.record_action("datacrypt");
                    if is_datacrypt_error(&token) {
                        logger::warn!("{LOG_LABEL}encrypt-json returned error: {token}");
                    } else {
                        log_datacrypt_response("encrypt-json", &token);
                    }
                    final_token = Some(token);
                }
                Err(err) => {
                    logger::warn!("{LOG_LABEL}encrypt-json call failed: {err}");
                    block_unprotected_response(headers_body_handler);
                    return;
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
                Ok((status, token)) => {
                    nlp_status_code = Some(status);
                    dictum.record_action("datacrypt-nlp");
                    if is_datacrypt_error(&token) {
                        logger::warn!("{LOG_LABEL}AI redaction returned error: {token}");
                    } else {
                        log_datacrypt_response("datacrypt-nlp", &token);
                    }
                    final_token = Some(token);
                }
                Err(err) => {
                    logger::warn!("{LOG_LABEL}AI redaction call failed: {err}");
                    block_unprotected_response(headers_body_handler);
                    return;
                }
            }
        }
    }

    logger::info!(
        "{LOG_LABEL}DataCrypt HTTP status codes -> filterRule: {}, encrypt-json: {}, datacrypt-nlp: {}",
        filter_status_code.map_or_else(|| "not called".to_string(), |code| code.to_string()),
        encrypt_status_code.map_or_else(|| "not called".to_string(), |code| code.to_string()),
        nlp_status_code.map_or_else(|| "not called".to_string(), |code| code.to_string()),
    );

    // Step 3: write the protected token back into result.content[0].text and replace the response body.
    let response_body = final_token.and_then(|token| {
        finalize_mcp_response(&mut mcp_envelope, &token)
            .map_err(|err| logger::warn!("{LOG_LABEL}Unable to finalize MCP response: {err}"))
            .ok()
    });

    if let Some(out) = response_body {
        if debug_logging_enabled(config) {
            logger::info!(
                "{LOG_LABEL}Outbound message (protected): {out}"
            );
        }
        logger::info!(
            "{LOG_LABEL}Setting response body ({} bytes)",
            out.len()
        );
        match headers_body_handler.set_body(out.as_bytes()) {
            Ok(_) => logger::info!("{LOG_LABEL}DataBlind encryption completed"),
            Err(err) => logger::warn!("{LOG_LABEL}Unable to set response body: {err:?}"),
        }
    } else {
        logger::warn!(
            "{LOG_LABEL}No DataBlind output produced; upstream response body left unchanged"
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
    cache_builder: CacheBuilder,
    clock: Clock,
) -> Result<()> {
    let config = RuntimeConfig::from_bytes(&bytes)?;

    // Refuse to start on a configuration that cannot work or could fall back to the
    // wrong key. The messages name the setting, never its value.
    let key_id = config.key_id.as_deref().unwrap_or("");
    validate_key_source(key_id, config.data_blind_key.is_some())
        .and_then(|_| {
            validate_mode_config(
                key_id,
                config.key_service_url.is_some(),
                config.policy_access_key.as_deref().unwrap_or(""),
            )
        })
        .map_err(|message| anyhow!("Invalid DataBlind key configuration: {message}"))?;

    // One in-memory cache per policy instance; it only ever holds the fetched key.
    let cache = cache_builder.new(KEY_CACHE_ID.to_string()).max_entries(1).build();

    // Warn-level so this appears even when policy logging is set to warn in API Manager.
    logger::warn!(
        "{LOG_LABEL}Policy loaded ({POLICY_INJECTION_POINT} injection point, handlers: on_request + on_response)"
    );
    warn_if_api_key_missing(
        "dataCryptApiKey",
        normalized_api_key(&config.data_crypt_api_key).as_deref(),
    );

    // Loud, alertable warning so an accidental debugLogging=true (e.g. in Prod) is visible in logs
    // and can be caught by a monitoring alert. Payload logging exposes potentially sensitive data.
    if debug_logging_enabled(&config) {
        logger::warn!(
            "{LOG_LABEL}SECURITY WARNING: debugLogging is ENABLED — request/response payloads will \
             be logged. Disable this in higher environments (e.g. Prod) to avoid logging sensitive data."
        );
    }

    let filter = on_request(|rs| request_filter(rs, &config))
        .on_response(|rs, request_data| {
        response_filter(rs, request_data, &config, &client, &cache, &clock)
    });

    launcher.launch(filter).await?;
    Ok(())
}
