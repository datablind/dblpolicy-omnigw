// Copyright 2023 Salesforce, Inc. All rights reserved.
mod generated;

use anyhow::{anyhow, Result};

use pdk::hl::*;
use pdk::logger;
use pdk::script::{HandlerAttributesBinding, TryFromValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::generated::config::Config;

const LOG_LABEL: &str = "DATABLIND_POLICY 6.0.12: ";

// The zt:encrypt-json and zt:filter-json connector operations are replaced by REST calls to this
// path on the configured `dataCryptService`. The AI based redaction (when sensitive fields are not
// manually specified) is served by the NLP path on the same host.
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

/// Interprets a DataCrypt token as JSON when possible so it can feed a subsequent operation.
fn token_as_json(token: &str) -> Value {
    serde_json::from_str(token).unwrap_or_else(|_| Value::String(token.to_string()))
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

    // Removing the content-length header is required before modifying the body.
    headers_state.handler().remove_header("content-length");

    let body_state = headers_state.into_body_state().await;
    let body_handler = body_state.handler();
    let payload_bytes = body_handler.body();

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

    // The response payload is the data to protect. Fall back to a raw string if it is not JSON.
    let mut data: Value = serde_json::from_slice(&payload_bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&payload_bytes).to_string()));

    let mut datablind_out: Option<String> = None;

    // Step 1: optional filtering (replaces the zt:filter-json operation).
    if let Some(rules) = config.filter_rule.as_ref().filter(|rules| !rules.is_empty()) {
        let request = DataCryptRequest {
            key: key.clone(),
            tweak: None,
            data: data.clone(),
            sensitive_fields: None,
            filter_rule: Some(parse_json_lines(rules)),
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
                logger::info!("{LOG_LABEL}filterRule applied");
                data = token_as_json(&token);
                datablind_out = Some(token);
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

        let request = DataCryptRequest {
            key: key.clone(),
            tweak: Some(tweak.clone()),
            data: data.clone(),
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
            Ok(token) => datablind_out = Some(token),
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

        let request = DataCryptRequest {
            key: key.clone(),
            tweak: Some(tweak.clone()),
            data: data.clone(),
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
            Ok(token) => datablind_out = Some(token),
            Err(err) => logger::warn!("{LOG_LABEL}AI redaction call failed: {err}"),
        }
    }

    // Step 3: replace the response body with the protected payload.
    if let Some(out) = datablind_out {
        match body_handler.set_body(out.as_bytes()) {
            Ok(_) => logger::info!("{LOG_LABEL}DataBlind encryption completed"),
            Err(err) => logger::warn!("{LOG_LABEL}Unable to set response body: {err:?}"),
        }
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

    let filter = on_request(|rs| request_filter(rs, &config))
        .on_response(|rs, request_data| response_filter(rs, request_data, &config, &client));

    launcher.launch(filter).await?;
    Ok(())
}
