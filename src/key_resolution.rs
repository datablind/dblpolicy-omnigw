// Pure logic for key-resolution mode: fetching the app zone's DataBlind key from
// datablindcp at request time instead of holding it in the policy configuration.
//
// Nothing here does I/O or logging. The types that carry secrets (the key, the
// caller's override token and passphrase) redact them in `Debug` output, so an
// accidental `{:?}` can never put them in a log line.

use serde::{Deserialize, Serialize};
use std::fmt;

/// How long a fetched key may be reused. Revoking a policy access key therefore
/// takes effect within this window (a revoked token or workload is checked on
/// every request that carries override credentials and is never cached).
pub const KEY_CACHE_TTL_MS: u64 = 60_000;

/// Upper bound on the passphrase header value that is parsed at all.
pub const MAX_PASSPHRASE_LEN: usize = 512;

const POLICY_ACCESS_KEY_PREFIX: &str = "dbpk_";

/// Body of `POST <keyServiceUrl>/app-zone-key-resolve`.
#[derive(Serialize)]
pub struct ResolveRequest<'a> {
    pub key_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload_guid: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_token: Option<&'a str>,
}

/// `200 {"key": string, "workload_ok": bool}`.
#[derive(Deserialize, PartialEq)]
pub struct ResolveResponse {
    pub key: String,
    pub workload_ok: bool,
}

impl fmt::Debug for ResolveResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolveResponse")
            .field("key", &"<redacted>")
            .field("workload_ok", &self.workload_ok)
            .finish()
    }
}

#[derive(Debug, PartialEq)]
pub enum ResolveFailure {
    /// The service answered with a non-200 status.
    Rejected(u32),
    /// 200, but the body is not a usable `{key, workload_ok}`.
    Malformed,
    /// The call itself failed (network, timeout, ...).
    Transport,
}

/// The caller's override credentials exactly as they arrived in the headers.
#[derive(Clone, Default, PartialEq)]
pub struct Credentials {
    pub token: String,
    pub passphrase: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("token", &"<redacted>")
            .field("passphrase", &"<redacted>")
            .finish()
    }
}

/// 8-4-4-4-12 hexadecimal digits, either case, and nothing else.
pub fn is_uuid(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// The workload GUID in a `<guid>:<passphrase>` value. Split on the FIRST colon;
/// the prefix must be a UUID and the whole value at most MAX_PASSPHRASE_LEN.
pub fn workload_guid_from_passphrase(passphrase: &str) -> Option<&str> {
    if passphrase.len() > MAX_PASSPHRASE_LEN {
        return None;
    }
    let (prefix, _) = passphrase.split_once(':')?;
    is_uuid(prefix).then_some(prefix)
}

/// Interprets the key service's answer. Only a 200 with a valid body and a
/// non-empty key is usable.
pub fn parse_resolve_response(status: u32, body: &[u8]) -> Result<ResolveResponse, ResolveFailure> {
    if status != 200 {
        return Err(ResolveFailure::Rejected(status));
    }
    let parsed: ResolveResponse = serde_json::from_slice(body).map_err(|_| ResolveFailure::Malformed)?;
    if parsed.key.trim().is_empty() {
        return Err(ResolveFailure::Malformed);
    }
    Ok(parsed)
}

/// What to send to DataCrypt: the caller's credentials only when the workload
/// check passed, otherwise blanks (so the data stays protected).
pub fn effective_credentials(response: &ResolveResponse, caller: &Credentials) -> Credentials {
    if response.workload_ok {
        caller.clone()
    } else {
        Credentials::default()
    }
}

/// Whether the key service must also be asked about the caller's token/workload.
pub fn needs_workload_check(caller: &Credentials) -> bool {
    !caller.token.is_empty() && workload_guid_from_passphrase(&caller.passphrase).is_some()
}

#[derive(Serialize, Deserialize)]
struct CacheEntry {
    key: String,
    expires_at_ms: u64,
}

pub fn encode_cache_entry(key: &str, now_ms: u64) -> Vec<u8> {
    let entry = CacheEntry { key: key.to_string(), expires_at_ms: now_ms.saturating_add(KEY_CACHE_TTL_MS) };
    // A struct of a string and an integer always serializes.
    serde_json::to_vec(&entry).unwrap_or_default()
}

/// The cached key, unless it has expired or the entry is unusable.
pub fn decode_cache_entry(bytes: &[u8], now_ms: u64) -> Option<String> {
    let entry: CacheEntry = serde_json::from_slice(bytes).ok()?;
    // An entry that expires "at the end of time" (saturated) is still honoured only
    // while now is strictly before that instant, so u64::MAX is always expired.
    (now_ms < entry.expires_at_ms && !entry.key.trim().is_empty()).then_some(entry.key)
}

/// Startup validation. An empty `key_id` means legacy mode (always valid). The
/// error text names the field and never repeats a configured value.
pub fn validate_mode_config(key_id: &str, service_present: bool, access_key: &str) -> Result<(), String> {
    let key_id = key_id.trim();
    if key_id.is_empty() {
        return Ok(());
    }
    if !is_uuid(key_id) {
        return Err("keyId must be a UUID (the DataBlind app zone GUID)".to_string());
    }
    if !service_present {
        return Err("keyServiceUrl is required when keyId is set".to_string());
    }
    let access_key = access_key.trim();
    if access_key.is_empty() {
        return Err("policyAccessKey is required when keyId is set".to_string());
    }
    if !access_key.starts_with(POLICY_ACCESS_KEY_PREFIX) {
        return Err("policyAccessKey is not a DataBlind policy access key".to_string());
    }
    Ok(())
}

/// A policy must say where its key comes from: the configured DataBlind Key
/// (legacy) or a Key ID (key-resolution mode). Neither would silently run with
/// an empty key, so it is refused at startup. If both are set, the Key ID wins.
pub fn validate_key_source(key_id: &str, legacy_key_present: bool) -> Result<(), String> {
    if key_id.trim().is_empty() && !legacy_key_present {
        return Err("configure either DataBlind Key (5) or DataBlind Key ID (5a)".to_string());
    }
    Ok(())
}

/// What the response filter should do once the key (and the credential check)
/// have been looked up.
#[derive(PartialEq)]
pub enum Plan {
    /// Encrypt with `key`, sending DataCrypt `creds`. `cache_it` says whether the
    /// key was just fetched fresh and should be (re)stored in the cache.
    Use { key: String, creds: Credentials, cache_it: bool },
    /// No key could be obtained: the response must be blocked.
    Block,
}

impl fmt::Debug for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Plan::Use { creds, cache_it, .. } => f
                .debug_struct("Use")
                .field("key", &"<redacted>")
                .field("creds", creds)
                .field("cache_it", cache_it)
                .finish(),
            Plan::Block => f.write_str("Block"),
        }
    }
}

/// Decision matrix of key-resolution mode.
///
/// * `cached_key`: a still-valid cached key, if any.
/// * `outcome`: the key service's answer, or `None` when no call was made (a
///   valid cached key and nothing to check about the caller).
///
/// The caller's own override credentials are only ever passed on when the key
/// service confirmed them (`workload_ok`); in every other case DataCrypt gets
/// blanks, so the data stays protected. If no key is available at all, block.
pub fn plan(
    cached_key: Option<String>,
    outcome: Option<Result<ResolveResponse, ResolveFailure>>,
    caller: &Credentials,
) -> Plan {
    match outcome {
        // A fresh answer from the key service.
        Some(Ok(response)) => {
            let creds = effective_credentials(&response, caller);
            Plan::Use { key: response.key, creds, cache_it: true }
        }
        // The call failed: a still-valid cached key keeps protection working, but
        // nothing the caller sent can be trusted, so DataCrypt gets blanks.
        Some(Err(_)) => match cached_key {
            Some(key) => Plan::Use { key, creds: Credentials::default(), cache_it: false },
            None => Plan::Block,
        },
        // No call was made: there was nothing to check about the caller.
        None => match cached_key {
            Some(key) => Plan::Use { key, creds: Credentials::default(), cache_it: false },
            None => Plan::Block,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUID: &str = "d3ffbe14-e883-4ce0-907b-035f7fbe8840";
    const ACCESS_KEY: &str = "dbpk_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn creds(token: &str, passphrase: &str) -> Credentials {
        Credentials { token: token.to_string(), passphrase: passphrase.to_string() }
    }

    // ---- is_uuid ----

    #[test]
    fn uuid_accepts_canonical_and_uppercase() {
        assert!(is_uuid(GUID));
        assert!(is_uuid(&GUID.to_uppercase()));
    }

    #[test]
    fn uuid_rejects_empty_short_extra_chars_and_whitespace() {
        for bad in [
            "",
            "x",
            "123",
            "d3ffbe14e8834ce0907b035f7fbe8840",                  // no hyphens
            "d3ffbe14-e883-4ce0-907b-035f7fbe884",                // one char short
            "d3ffbe14-e883-4ce0-907b-035f7fbe88400",              // one char long
            "d3ffbe14-e883-4ce0-907b-035f7fbe884g",               // non-hex
            "d3ffbe14e-883-4ce0-907b-035f7fbe8840",               // hyphens in the wrong places
            " d3ffbe14-e883-4ce0-907b-035f7fbe8840",
            "d3ffbe14-e883-4ce0-907b-035f7fbe8840 ",
            "d3ffbe14-e883-4ce0-907b-035f7fbe8840\n",
            "d3ffbe14-e883-4ce0-907b-035f7fbe884\u{0660}",       // arabic-indic digit, not ASCII hex
        ] {
            assert!(!is_uuid(bad), "{:?} must not be a UUID", bad);
        }
    }

    // ---- workload_guid_from_passphrase ----

    #[test]
    fn guid_from_passphrase_valid_prefix() {
        assert_eq!(workload_guid_from_passphrase(&format!("{GUID}:pass")), Some(GUID));
    }

    #[test]
    fn guid_from_passphrase_splits_on_the_first_colon_only() {
        assert_eq!(workload_guid_from_passphrase(&format!("{GUID}:a:b:c")), Some(GUID));
    }

    #[test]
    fn guid_from_passphrase_allows_an_empty_passphrase_part() {
        // An empty passphrase is DataCrypt's problem, not a parsing failure.
        assert_eq!(workload_guid_from_passphrase(&format!("{GUID}:")), Some(GUID));
    }

    #[test]
    fn guid_from_passphrase_rejects_missing_or_malformed_prefix() {
        for bad in ["", "nocolon", ":pass", "not-a-uuid:pass", &format!("{GUID}x:pass"), &format!(" {GUID}:pass"), GUID] {
            assert_eq!(workload_guid_from_passphrase(bad), None, "{:?}", bad);
        }
    }

    #[test]
    fn guid_from_passphrase_rejects_over_long_value() {
        let at_limit = format!("{GUID}:{}", "x".repeat(MAX_PASSPHRASE_LEN - GUID.len() - 1));
        assert_eq!(at_limit.len(), MAX_PASSPHRASE_LEN);
        assert_eq!(workload_guid_from_passphrase(&at_limit), Some(GUID));

        let over = format!("{at_limit}x");
        assert_eq!(workload_guid_from_passphrase(&over), None);
    }

    // ---- parse_resolve_response ----

    #[test]
    fn parse_ok_response() {
        let parsed = parse_resolve_response(200, br#"{"key":"zone-key","workload_ok":true}"#).unwrap();
        assert_eq!(parsed, ResolveResponse { key: "zone-key".to_string(), workload_ok: true });
        let parsed = parse_resolve_response(200, br#"{"key":"zone-key","workload_ok":false}"#).unwrap();
        assert!(!parsed.workload_ok);
    }

    #[test]
    fn parse_ignores_unknown_fields() {
        assert!(parse_resolve_response(200, br#"{"key":"k","workload_ok":true,"extra":1}"#).is_ok());
    }

    #[test]
    fn parse_rejects_an_empty_or_blank_key() {
        for body in [&br#"{"key":"","workload_ok":true}"#[..], br#"{"key":"   ","workload_ok":true}"#] {
            assert_eq!(parse_resolve_response(200, body), Err(ResolveFailure::Malformed));
        }
    }

    #[test]
    fn parse_rejects_malformed_bodies() {
        for body in [
            &b""[..],
            b"not json",
            b"{}",
            br#"{"key":"k"}"#,                          // workload_ok missing: never assume true
            br#"{"workload_ok":true}"#,                 // key missing
            br#"{"key":5,"workload_ok":true}"#,         // wrong type
            br#"{"key":"k","workload_ok":"true"}"#,     // wrong type
            br#"["key"]"#,
        ] {
            assert_eq!(parse_resolve_response(200, body), Err(ResolveFailure::Malformed), "{:?}", String::from_utf8_lossy(body));
        }
    }

    #[test]
    fn parse_reports_every_non_200_status() {
        for status in [201, 204, 400, 401, 409, 413, 500, 502, 503] {
            assert_eq!(
                parse_resolve_response(status, br#"{"key":"k","workload_ok":true}"#),
                Err(ResolveFailure::Rejected(status)),
                "status {} must never be treated as success",
                status
            );
        }
    }

    // ---- credentials ----

    #[test]
    fn effective_credentials_keeps_the_callers_when_the_workload_check_passed() {
        let response = ResolveResponse { key: "k".to_string(), workload_ok: true };
        let caller = creds("token", &format!("{GUID}:pass"));
        assert_eq!(effective_credentials(&response, &caller), caller);
    }

    #[test]
    fn effective_credentials_are_blank_when_the_workload_check_failed() {
        let response = ResolveResponse { key: "k".to_string(), workload_ok: false };
        let result = effective_credentials(&response, &creds("token", &format!("{GUID}:pass")));
        assert_eq!(result, creds("", ""));
    }

    #[test]
    fn needs_workload_check_only_with_a_token_and_a_guid_prefix() {
        assert!(!needs_workload_check(&creds("", &format!("{GUID}:pass"))));
        assert!(needs_workload_check(&creds("token", &format!("{GUID}:pass"))));
        assert!(!needs_workload_check(&creds("token", "plain-passphrase")));
        assert!(!needs_workload_check(&creds("token", "")));
        assert!(!needs_workload_check(&creds("", "")));
    }

    // ---- cache entry ----

    #[test]
    fn cache_entry_round_trips_before_the_ttl() {
        let bytes = encode_cache_entry("zone-key", 1_000);
        assert_eq!(decode_cache_entry(&bytes, 1_000), Some("zone-key".to_string()));
        assert_eq!(decode_cache_entry(&bytes, 1_000 + KEY_CACHE_TTL_MS - 1), Some("zone-key".to_string()));
    }

    #[test]
    fn cache_entry_expires_exactly_at_the_ttl() {
        let bytes = encode_cache_entry("zone-key", 1_000);
        assert_eq!(decode_cache_entry(&bytes, 1_000 + KEY_CACHE_TTL_MS), None);
        assert_eq!(decode_cache_entry(&bytes, u64::MAX), None);
    }

    #[test]
    fn cache_entry_survives_awkward_keys() {
        for key in ["quote\"inside", "back\\slash", "unicode-é-✓", "new\nline", "a:b|c"] {
            let bytes = encode_cache_entry(key, 5);
            assert_eq!(decode_cache_entry(&bytes, 6), Some(key.to_string()), "{:?}", key);
        }
    }

    #[test]
    fn cache_entry_does_not_overflow_near_the_end_of_time() {
        let bytes = encode_cache_entry("k", u64::MAX - 1);
        // saturates instead of wrapping to a tiny expiry; it is simply "valid until the end of time".
        assert_eq!(decode_cache_entry(&bytes, u64::MAX - 1), Some("k".to_string()));
    }

    #[test]
    fn cache_entry_rejects_garbage_and_empty_keys() {
        assert_eq!(decode_cache_entry(b"", 0), None);
        assert_eq!(decode_cache_entry(b"not json", 0), None);
        assert_eq!(decode_cache_entry(br#"{"key":"","expires_at_ms":999999999}"#, 0), None);
        assert_eq!(decode_cache_entry(br#"{"key":"k"}"#, 0), None);
        assert_eq!(decode_cache_entry(br#"{"expires_at_ms":999999999}"#, 0), None);
    }

    // ---- startup validation ----

    #[test]
    fn mode_config_empty_key_id_is_legacy_mode_and_always_valid() {
        assert_eq!(validate_mode_config("", false, ""), Ok(()));
        assert_eq!(validate_mode_config("   ", false, ""), Ok(()));
    }

    #[test]
    fn mode_config_valid_resolution_config() {
        assert_eq!(validate_mode_config(GUID, true, ACCESS_KEY), Ok(()));
    }

    #[test]
    fn mode_config_rejects_each_missing_or_malformed_part() {
        assert!(validate_mode_config("not-a-uuid", true, ACCESS_KEY).is_err());
        assert!(validate_mode_config(GUID, false, ACCESS_KEY).is_err());
        assert!(validate_mode_config(GUID, true, "").is_err());
        assert!(validate_mode_config(GUID, true, "   ").is_err());
        assert!(validate_mode_config(GUID, true, "not-a-policy-key").is_err());
    }

    #[test]
    fn mode_config_errors_never_repeat_configured_values() {
        let secret_key_id = "secret-looking-key-id";
        let secret_access = "secret-looking-access-key";
        for result in [
            validate_mode_config(secret_key_id, true, ACCESS_KEY),
            validate_mode_config(GUID, true, secret_access),
            validate_mode_config(GUID, false, secret_access),
        ] {
            let message = result.unwrap_err();
            assert!(!message.contains(secret_key_id), "{}", message);
            assert!(!message.contains(secret_access), "{}", message);
            assert!(!message.contains(ACCESS_KEY), "{}", message);
        }
    }

    // ---- key source ----

    #[test]
    fn key_source_needs_a_legacy_key_or_a_key_id() {
        assert!(validate_key_source("", false).is_err());
        assert!(validate_key_source("   ", false).is_err());
        assert!(validate_key_source("", true).is_ok());
        assert!(validate_key_source(GUID, false).is_ok());
        assert!(validate_key_source(GUID, true).is_ok());
    }

    // ---- plan ----

    fn ok(key: &str, workload_ok: bool) -> Option<Result<ResolveResponse, ResolveFailure>> {
        Some(Ok(ResolveResponse { key: key.to_string(), workload_ok }))
    }

    fn caller() -> Credentials {
        creds("caller-token", &format!("{GUID}:caller-pass"))
    }

    #[test]
    fn plan_fresh_ok_uses_the_callers_credentials_and_caches_the_key() {
        assert_eq!(
            plan(None, ok("fresh-key", true), &caller()),
            Plan::Use { key: "fresh-key".to_string(), creds: caller(), cache_it: true }
        );
    }

    #[test]
    fn plan_fresh_workload_not_ok_blanks_the_credentials_but_still_caches_the_key() {
        assert_eq!(
            plan(None, ok("fresh-key", false), &caller()),
            Plan::Use { key: "fresh-key".to_string(), creds: Credentials::default(), cache_it: true }
        );
    }

    #[test]
    fn plan_a_fresh_key_replaces_a_stale_cached_one() {
        assert_eq!(
            plan(Some("old-key".to_string()), ok("new-key", true), &caller()),
            Plan::Use { key: "new-key".to_string(), creds: caller(), cache_it: true }
        );
    }

    #[test]
    fn plan_no_call_needed_uses_the_cached_key_with_blank_credentials() {
        // No token or no GUID prefix: nothing to validate, so nothing is forwarded.
        assert_eq!(
            plan(Some("cached-key".to_string()), None, &creds("tok", "no-guid-prefix")),
            Plan::Use { key: "cached-key".to_string(), creds: Credentials::default(), cache_it: false }
        );
    }

    #[test]
    fn plan_a_failed_call_falls_back_to_the_cached_key_with_blank_credentials() {
        for failure in [ResolveFailure::Rejected(401), ResolveFailure::Rejected(500), ResolveFailure::Malformed, ResolveFailure::Transport] {
            assert_eq!(
                plan(Some("cached-key".to_string()), Some(Err(failure)), &caller()),
                Plan::Use { key: "cached-key".to_string(), creds: Credentials::default(), cache_it: false }
            );
        }
    }

    #[test]
    fn plan_a_failed_call_without_a_cached_key_blocks() {
        for failure in [ResolveFailure::Rejected(401), ResolveFailure::Rejected(409), ResolveFailure::Malformed, ResolveFailure::Transport] {
            assert_eq!(plan(None, Some(Err(failure)), &caller()), Plan::Block);
        }
    }

    #[test]
    fn plan_without_a_key_and_without_a_call_blocks() {
        assert_eq!(plan(None, None, &caller()), Plan::Block);
    }

    #[test]
    fn plan_never_forwards_the_callers_credentials_unless_the_service_confirmed_them() {
        let outcomes: Vec<Option<Result<ResolveResponse, ResolveFailure>>> = vec![
            None,
            ok("k", false),
            Some(Err(ResolveFailure::Transport)),
            Some(Err(ResolveFailure::Rejected(500))),
        ];
        for outcome in outcomes {
            if let Plan::Use { creds, .. } = plan(Some("cached".to_string()), outcome, &caller()) {
                assert_eq!(creds, Credentials::default());
            }
        }
    }

    #[test]
    fn plan_debug_output_never_contains_the_key() {
        let printed = format!("{:?}", plan(None, ok("THE-ZONE-KEY", true), &caller()));
        assert!(!printed.contains("THE-ZONE-KEY"), "{}", printed);
    }

    // ---- request body and Debug redaction ----

    #[test]
    fn resolve_request_omits_absent_fields() {
        let minimal = serde_json::to_value(ResolveRequest { key_id: GUID, workload_guid: None, override_token: None }).unwrap();
        assert_eq!(minimal, serde_json::json!({ "key_id": GUID }));

        let full = serde_json::to_value(ResolveRequest { key_id: GUID, workload_guid: Some(GUID), override_token: Some("tok") }).unwrap();
        assert_eq!(full, serde_json::json!({ "key_id": GUID, "workload_guid": GUID, "override_token": "tok" }));
    }

    #[test]
    fn debug_output_never_contains_the_key_token_or_passphrase() {
        let response = ResolveResponse { key: "THE-ZONE-KEY".to_string(), workload_ok: true };
        let caller = creds("THE-TOKEN", "THE-PASSPHRASE");
        let printed = format!("{response:?} {caller:?} {:?}", Some(&caller));
        for secret in ["THE-ZONE-KEY", "THE-TOKEN", "THE-PASSPHRASE"] {
            assert!(!printed.contains(secret), "{}", printed);
        }
    }
}
