// Copyright 2023 Salesforce, Inc. All rights reserved.
mod generated;

use anyhow::{anyhow, Result};
use flate2::read::GzDecoder;
use std::io::Read;

use pdk::hl::*;
use pdk::logger;
use pdk::script::{HandlerAttributesBinding, TryFromValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::generated::config::Config;

const LOG_LABEL: &str = "DATABLIND_POLICY 6.0.12 v1.5.7: ";
const POLICY_INJECTION_POINT: &str = "inbound";

// The zt:filter-json operation calls /Dev/filter. zt:encrypt-json calls /Dev/datacrypt.
// AI based redaction (when sensitive fields are not manually specified) uses /Dev/datacrypt-nlp.
const FILTER_PATH: &str = "/Dev/filter";
const DATACRYPT_PATH: &str = "/Dev/datacrypt";
const NLP_PATH: &str = "/Dev/datacrypt-nlp";

/// Override credentials read from the inbound request and shared with the response phase.
#[derive(Clone, Default)]
struct OverrideCredentials {
    token: String,
    passphrase: String,
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

/// Parses each configured JSON line. A single entry is used as-is; multiple entries become a JSON
/// array, mirroring the `read(..., 'application/json')` handling in the original policy template.
fn parse_json_lines(items: &[String]) -> Value {
    let parsed: Vec<Value> = items
        .iter()
        .map(|item| serde_json::from_str(item).unwrap_or_else(|_| Value::String(item.clone())))
        .collect();

    if parsed.len() == 1 {
        parsed.into_iter().next().unwrap_or(Value::Null)
    } else {
        Value::Array(parsed)
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

fn log_datacrypt_response(operation: &str, token: &str) {
    logger::info!("{LOG_LABEL}{operation} response JSON: {token}");
}

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

/// Reads `content[0].text` from an MCP-style response envelope and parses it as JSON.
fn extract_mcp_content_text(envelope: &Value) -> Result<Value> {
    let text = envelope
        .pointer("/content/0/text")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("MCP response missing content[0].text string"))?;

    let parsed = serde_json::from_str(text.trim())
        .map_err(|err| anyhow!("MCP content[0].text is not valid JSON: {err}"))?;
    Ok(normalize_data_for_datacrypt(parsed))
}

/// Writes a DataCrypt token back into `content[0].text` on the MCP envelope.
fn apply_mcp_content_text(envelope: &mut Value, token: &str) -> Result<()> {
    let content_item = envelope
        .pointer_mut("/content/0")
        .and_then(|value| value.as_object_mut())
        .ok_or_else(|| anyhow!("MCP response missing content[0] object"))?;

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

/// Performs a POST against the DataCrypt service and returns the resulting token.
async fn call_datacrypt(
    client: &HttpClient,
    service: &Service,
    path: &str,
    request: &DataCryptRequest,
    api_key: Option<&str>,
) -> Result<String> {
    let body = serde_json::to_vec(request)?;

    let mut headers: Vec<(&str, &str)> = vec![("Content-Type", "application/json")];
    if let Some(key) = api_key {
        headers.push(("x-api-key", key));
    }

    let response = client
        .request(service)
        .path(path)
        .headers(headers)
        .body(&body)
        .post()
        .await
        .map_err(|err| anyhow!("DataCrypt request failed: {err:?}"))?;

    let status = response.status_code();
    if status == 200 {
        let parsed: DataCryptResponse = serde_json::from_slice(response.body())?;
        Ok(parsed.token)
    } else {
        Err(anyhow!(
            "DataCrypt service returned status {status}: {}",
            String::from_utf8_lossy(response.body())
        ))
    }
}

/// Reads the override token and passphrase from the inbound request so they are available when the
/// upstream response is processed. These default to request headers in the policy definition.
async fn request_filter(state: RequestState, config: &Config) -> Flow<OverrideCredentials> {
    logger::info!("{LOG_LABEL}Processing inbound request headers for override credentials");
    let headers_state = state.into_headers_state().await;

    let mut token_eval = config.data_blind_token.evaluator();
    token_eval.bind_attributes(&HandlerAttributesBinding::partial(headers_state.handler()));
    let token: String = token_eval
        .eval()
        .and_then(TryFromValue::try_from_value)
        .unwrap_or_default();

    let mut passphrase_eval = config.data_blind_passphrase.evaluator();
    passphrase_eval.bind_attributes(&HandlerAttributesBinding::partial(headers_state.handler()));
    let passphrase: String = passphrase_eval
        .eval()
        .and_then(TryFromValue::try_from_value)
        .unwrap_or_default();

    let body_state = headers_state.into_body_state().await;
    log_message("Inbound message", body_state.handler().body());

    Flow::Continue(OverrideCredentials { token, passphrase })
}

/// Applies DataBlind protection to the upstream response when its status code is eligible.
async fn response_filter(
    state: ResponseState,
    request_data: RequestData<OverrideCredentials>,
    config: &Config,
    client: &HttpClient,
) {
    let credentials = match request_data {
        RequestData::Continue(credentials) => credentials,
        _ => OverrideCredentials::default(),
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

    let body_state = headers_state.into_body_state().await;
    let body_handler = body_state.handler();
    let payload_bytes = body_handler.body();
    log_message("Outbound message (upstream)", &payload_bytes);

    let key: String = config
        .data_blind_key
        .evaluator()
        .eval()
        .and_then(TryFromValue::try_from_value)
        .unwrap_or_default();

    let mut tweak_eval = config.tweak.evaluator();
    tweak_eval.bind_payload(&body_state);
    let tweak: String = tweak_eval
        .eval()
        .and_then(TryFromValue::try_from_value)
        .unwrap_or_default();

    // The response payload is the data to protect. When filter runs, each DataCrypt step feeds the
    // next. In MCP mode, content[0].text is parsed once up front and written back once at the end.
    let upstream_data = normalize_data_for_datacrypt(parse_response_json(&payload_bytes));
    let uses_mcp_response = config.policy_uses_mcp_response;
    let mut mcp_envelope = upstream_data.clone();

    let mut datacrypt_data = if uses_mcp_response {
        match extract_mcp_content_text(&mcp_envelope) {
            Ok(data) => {
                logger::info!(
                    "{LOG_LABEL}MCP content[0].text parsed for DataCrypt pipeline ({})",
                    describe_data_for_log(&data)
                );
                data
            }
            Err(err) => {
                logger::warn!("{LOG_LABEL}Unable to parse MCP content[0].text: {err}");
                return;
            }
        }
    } else {
        upstream_data.clone()
    };

    logger::info!(
        "{LOG_LABEL}Upstream response parsed ({} bytes, top-level type: {}, mcpResponse: {uses_mcp_response})",
        payload_bytes.len(),
        match &upstream_data {
            Value::Object(_) => "object",
            Value::Array(_) => "array",
            Value::String(_) => "string",
            _ => "other",
        }
    );

    let mut final_token: Option<String> = None;

    // Step 1: optional filtering (replaces the zt:filter-json operation).
    if let Some(rules) = config.filter_rule.as_ref().filter(|rules| !rules.is_empty()) {
        let request = DataCryptRequest {
            key: key.clone(),
            tweak: None,
            data: datacrypt_data.clone(),
            sensitive_fields: None,
            filter_rule: Some(parse_json_lines(rules)),
            over_ride_token: credentials.token.clone(),
            over_ride_pass_phrase: credentials.passphrase.clone(),
        };

        match call_datacrypt(
            client,
            &config.data_crypt_service,
            FILTER_PATH,
            &request,
            Some(config.data_crypt_api_key.as_str()),
        )
        .await
        {
            Ok(token) => {
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
            Err(err) => logger::warn!("{LOG_LABEL}filterRule call failed: {err}"),
        }
    }

    // Step 2: encryption. Use manually specified sensitive fields, or AI based redaction otherwise.
    if config.sensitive_fields_specified {
        let sensitive_fields = config
            .sensitive_fields_multi_line
            .as_ref()
            .filter(|fields| !fields.is_empty())
            .map(|fields| parse_json_lines(fields));

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
            DATACRYPT_PATH,
            &request,
            Some(config.data_crypt_api_key.as_str()),
        )
        .await
        {
            Ok(token) => {
                if is_datacrypt_error(&token) {
                    logger::warn!("{LOG_LABEL}encrypt-json returned error: {token}");
                } else {
                    log_datacrypt_response("encrypt-json", &token);
                }
                final_token = Some(token);
            }
            Err(err) => logger::warn!("{LOG_LABEL}encrypt-json call failed: {err}"),
        }
    } else {
        logger::info!(
            "{LOG_LABEL}Sensitive fields not specified, using AI to determine sensitive fields"
        );

        let api_key = config
            .data_blind_api_key
            .as_deref()
            .filter(|key| !key.is_empty())
            .unwrap_or(config.data_crypt_api_key.as_str());

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
            NLP_PATH,
            &request,
            Some(api_key),
        )
        .await
        {
            Ok(token) => {
                if is_datacrypt_error(&token) {
                    logger::warn!("{LOG_LABEL}AI redaction returned error: {token}");
                } else {
                    log_datacrypt_response("datacrypt-nlp", &token);
                }
                final_token = Some(token);
            }
            Err(err) => logger::warn!("{LOG_LABEL}AI redaction call failed: {err}"),
        }
    }

    // Step 3: replace the response body with the protected payload.
    let response_body = if uses_mcp_response {
        final_token.and_then(|token| {
            finalize_mcp_response(&mut mcp_envelope, &token)
                .map_err(|err| logger::warn!("{LOG_LABEL}Unable to finalize MCP response: {err}"))
                .ok()
        })
    } else {
        final_token
    };

    if let Some(out) = response_body {
        logger::info!(
            "{LOG_LABEL}Outbound message (protected): {out}"
        );
        logger::info!(
            "{LOG_LABEL}Setting response body ({} bytes)",
            out.len()
        );
        match body_handler.set_body(out.as_bytes()) {
            Ok(_) => logger::info!("{LOG_LABEL}DataBlind encryption completed"),
            Err(err) => logger::warn!("{LOG_LABEL}Unable to set response body: {err:?}"),
        }
    } else {
        logger::warn!(
            "{LOG_LABEL}No DataBlind output produced; upstream response body left unchanged"
        );
    }
}

#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    client: HttpClient,
) -> Result<()> {
    let config: Config = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow!(
            "Failed to parse configuration '{}'. Cause: {}",
            String::from_utf8_lossy(&bytes),
            err
        )
    })?;

    // Warn-level so this appears even when policy logging is set to warn in API Manager.
    logger::warn!(
        "{LOG_LABEL}Policy loaded ({POLICY_INJECTION_POINT} injection point, handlers: on_request + on_response)"
    );

    let filter = on_request(|rs| request_filter(rs, &config))
        .on_response(|rs, request_data| response_filter(rs, request_data, &config, &client));

    launcher.launch(filter).await?;
    Ok(())
}
