# DataBlind Policy Key Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the MCP DataBlind policy obtain the app zone's data key from datablindcp at request time (instead of holding it in configuration), while sending DataCrypt blank override credentials whenever the caller's workload/token check fails.

**Architecture:** A new `key_resolution` module holds all pure logic (passphrase parsing, request/response types, decision matrix, TTL cache entry) with host-run unit tests. `lib.rs` selects the mode (`keyId` set = key-resolution mode, otherwise the existing `dataBlindKey` path, unchanged), calls the datablindcp endpoint through the existing `HttpClient`, and feeds the resulting key and effective credentials into the existing DataCrypt calls. DataCrypt is not changed.

**Tech Stack:** Rust (edition 2018, `wasm32-wasip1`), Anypoint PDK 1.9.0 (`pdk::cache`, `Clock`, `HttpClient`), serde/serde_json, `pdk-test` + `httpmock` for the integration test.

**Spec:** `/Users/kanishkaranr/ZTensor/projects/datablindcp/docs/superpowers/specs/2026-11-09-datablind-workloads-key-resolution-design.md`. The server side is `/Users/kanishkaranr/ZTensor/projects/datablindcp/docs/superpowers/plans/2026-11-09-datablind-workloads-key-resolution.md` (Task 3 must be deployed first).

## Global Constraints

- DataCrypt contract unchanged: it still receives `key`, `overRideToken`, `overRidePassPhrase` (`DataCryptRequest` fields as today).
- Mode switch: `keyId` non-empty => key-resolution mode and `dataBlindKey` is **ignored**; `keyId` empty => legacy mode, behaviour identical to today.
- `keyId` is an app zone `guid` (UUID). Endpoint: `POST <keyServiceUrl>/app-zone-key-resolve`, header `x-policy-access-key: <policyAccessKey>`, JSON body `{"key_id": string, "workload_guid"?: string, "override_token"?: string}`, response `200 {"key": string, "workload_ok": bool}`.
- Passphrase header value is `<workload guid>:<passphrase>`; split on the **first** colon; the prefix must be a UUID or it is treated as "no workload".
- Key cache TTL: 60 seconds, stored with an expiry computed from `Clock` (`pdk::cache` has no TTL of its own).
- The workload verdict (`workload_ok`) is **never cached**: every request that carries override credentials asks the endpoint, so revoking a token or workload takes effect on the next request. (Deliberate simplification of the spec's per-(token,workload) verdict cache: no token ever sits in policy memory and no hashing dependency is needed.)
- Secrets (`policyAccessKey`, key, token, passphrase) are never logged, never included in errors, and the raw configuration is never echoed.
- Fail-closed rules: misconfiguration in key-resolution mode fails policy startup; no key obtainable => `block_unprotected_response`; endpoint failure with a still-valid cached key => continue with the cached key and **blank** credentials.

## Review Focus

- Passphrase header with no colon, empty prefix, non-UUID prefix, prefix only (`guid:`), multiple colons, or an absurdly long value -> no workload; credentials blanked; key still fetched.
- `workload_ok:false`, endpoint 401/409/5xx, timeout, malformed JSON, or empty `key` -> never sends the caller's token/passphrase to DataCrypt as valid; empty key never used.
- A replayed response from an older cache entry after TTL -> refetched, not served.
- Configuration with `keyId` but a missing `keyServiceUrl`/`policyAccessKey`, or a non-UUID `keyId` -> policy refuses to start.
- Configuration parse failure -> error text contains no configuration values.

---

## File map

- Modify `definition/gcl.yaml`: new properties, relax `required`.
- Create `src/key_resolution.rs`: pure logic + unit tests.
- Modify `src/lib.rs`: config validation, mode selection, cache/clock wiring, resolve call, effective credentials, safer parse error.
- Modify `tests/requests.rs` (+ `tests/common/mod.rs` if needed): end-to-end test.
- Modify `Cargo.toml`: version `1.8.18` -> `1.9.0`; `docs/SETUP.md`: new configuration section.

**Run tests with:** unit: `cargo test --lib` (host); full: `make test` (needs Docker); build/regenerate config: `make build`.

---

### Task 1: Configuration schema

**Files:**
- Modify: `definition/gcl.yaml`

**Interfaces:**
- Produces: generated config fields `key_id: Option<String>`, `key_service_url: Option<Service>`, `policy_access_key: Option<String>` (names follow the generator's snake_case of `keyId`, `keyServiceUrl`, `policyAccessKey`; confirm after `make build` in `src/generated/config.rs` and adjust later tasks' field names if the generator differs).

- [ ] **Step 1:** In `gcl.yaml` add after `dataBlindKey`: `keyId` (string, title "5a. DataBlind Key ID", description "App zone GUID. When set, the key is fetched from DataBlind at request time and DataBlind Key (5) is ignored"), `keyServiceUrl` (`format: service`, title "5b. DataBlind Key Service URI", description "Base URI of the datablindcp functions, e.g. https://<ref>.supabase.co/functions/v1"), `policyAccessKey` (string, title "5c. Policy Access Key", `"@context": {"@characteristics": [security:sensitive]}` exactly like `dataCryptApiKey`). Remove `dataBlindKey` from the `required` list; do not change its default.
- [ ] **Step 2: Verify** `make build` succeeds and `src/generated/config.rs` contains the three new fields as `Option`s.
- [ ] **Step 3: Commit** `feat(policy): keyId/keyServiceUrl/policyAccessKey configuration`

---

### Task 2: Pure key-resolution logic

**Files:**
- Create: `src/key_resolution.rs` (declare `mod key_resolution;` in `lib.rs`)

**Interfaces:**
- Produces:
  ```rust
  pub const KEY_CACHE_TTL_MS: u64 = 60_000;
  pub const MAX_PASSPHRASE_LEN: usize = 512;
  pub fn is_uuid(s: &str) -> bool;                                   // 8-4-4-4-12 hex, either case, nothing else
  pub fn workload_guid_from_passphrase(passphrase: &str) -> Option<&str>; // first-colon split, UUID prefix, len <= MAX_PASSPHRASE_LEN
  #[derive(Serialize)] pub struct ResolveRequest<'a> { pub key_id: &'a str, #[serde(skip_serializing_if="Option::is_none")] pub workload_guid: Option<&'a str>, #[serde(skip_serializing_if="Option::is_none")] pub override_token: Option<&'a str> }
  #[derive(Deserialize)] pub struct ResolveResponse { pub key: String, pub workload_ok: bool }
  pub fn parse_resolve_response(status: u32, body: &[u8]) -> Result<ResolveResponse, ResolveFailure>; // 200 + valid JSON + non-empty key only
  pub enum ResolveFailure { Rejected(u32), Malformed, Transport }
  pub struct Credentials { pub token: String, pub passphrase: String }
  pub fn effective_credentials(res: &ResolveResponse, caller: &Credentials) -> Credentials; // workload_ok ? caller.clone() : blank
  pub fn needs_workload_check(caller: &Credentials) -> bool;         // token non-empty && workload_guid_from_passphrase is Some
  pub fn encode_cache_entry(key: &str, now_ms: u64) -> Vec<u8>;      // JSON {key, expires_at_ms: now_ms + KEY_CACHE_TTL_MS}
  pub fn decode_cache_entry(bytes: &[u8], now_ms: u64) -> Option<String>; // None if expired, malformed, or empty key
  pub fn validate_mode_config(key_id: &str, service_present: bool, access_key: &str) -> Result<(), String>; // error text names the field, never a value
  ```

- [ ] **Step 1: Write failing tests** in a `#[cfg(test)] mod tests` of `key_resolution.rs`: `uuid_accepts_canonical_and_uppercase`, `uuid_rejects_empty_short_extra_chars_and_whitespace`; `guid_from_passphrase` cases: valid `"<uuid>:pass"`, `"<uuid>:a:b:c"` (returns the uuid), `"<uuid>:"` (still returns the uuid — empty passphrase is DataCrypt's problem), `"nocolon"`, `":pass"`, `"not-a-uuid:pass"`, a 513-char value -> `None`; `parse_resolve_response`: 200 valid, 200 `{"key":""}` -> `Malformed`, 200 invalid JSON -> `Malformed`, 401/409/500 -> `Rejected(status)`; `effective_credentials`: ok keeps both, not-ok gives two empty strings; `needs_workload_check` false for empty token, true for token + uuid prefix, false for token + no uuid; cache entry: round-trips before TTL, `None` at exactly `now + KEY_CACHE_TTL_MS`, `None` for garbage bytes and for empty key; `validate_mode_config`: empty key_id is `Ok` only when nothing else is required (legacy), non-UUID key_id errs, missing service errs, empty/whitespace access key errs, and no error string contains the supplied key id or access key.
- [ ] **Step 2: Run** `cargo test --lib key_resolution` -> FAIL (module missing).
- [ ] **Step 3: Implement** the items above in `key_resolution.rs`.
- [ ] **Step 4: Run** `cargo test --lib key_resolution` -> PASS.
- [ ] **Step 5: Commit** `feat(policy): key resolution pure logic`

---

### Task 3: Wire key resolution into the filters

**Files:**
- Modify: `src/lib.rs` (config validation in `RuntimeConfig::from_bytes`/`configure`, `request_filter`, `response_filter`, `configure` entrypoint)

**Interfaces:**
- Consumes: everything in Task 2; generated fields from Task 1.
- Produces in `lib.rs`:
  ```rust
  enum KeySource { Legacy, Resolved { key_id: String } }
  async fn resolve_key(client: &HttpClient, service: &Service, access_key: &str, req: &ResolveRequest<'_>) -> Result<ResolveResponse, ResolveFailure>;
  ```
  `configure` builds `cache_builder.new("datablind-key".to_string()).max_entries(8).build()` and obtains `Clock` the same way `/Users/kanishkaranr/ZTensor/projects/zt-auth-policy-omni/src/lib.rs` does; passes both into the filters.

- [ ] **Step 1: Write failing unit tests** for the decision logic that does not need a gateway (put it in `key_resolution.rs` as `pub fn plan(source_cached: Option<String>, outcome: Result<ResolveResponse, ResolveFailure>, caller: &Credentials) -> Plan` with `enum Plan { Use{key: String, creds: Credentials, cache_it: bool}, Block }`), tests: `fresh_ok_uses_caller_creds_and_caches_key`, `fresh_workload_not_ok_blanks_creds_and_caches_key`, `rejected_with_cached_key_uses_cached_key_blank_creds`, `rejected_without_cache_blocks`, `malformed_without_cache_blocks`, `transport_error_with_cache_blank_creds`, `no_call_needed_and_cached_key_uses_cache_with_caller_creds_blank` (a request without override credentials needs only the key; caller creds are empty anyway).
- [ ] **Step 2: Run** `cargo test --lib key_resolution::plan` -> FAIL.
- [ ] **Step 3: Implement** `plan`, then in `lib.rs`: (a) `validate_mode_config` at startup, returning an `Err` from `configure` on failure (policy does not start); (b) in `request_filter`, keep reading token/passphrase exactly as today and store them in `RequestContext`; (c) in `response_filter`, replace the key evaluation with: legacy mode -> the existing `data_blind_key` evaluation untouched; resolved mode -> read the cached key (`decode_cache_entry` with `Clock` now), call `resolve_key` only if `needs_workload_check(&credentials)` or the cache missed, `plan(...)`, on `Block` call `block_unprotected_response` and return, on `Use` store the key with `encode_cache_entry` when `cache_it`, then run the existing filter/encrypt/NLP DataCrypt calls using the planned key and credentials (replace the `credentials.token/passphrase` clones used in the three `DataCryptRequest`s with the planned ones); (d) `resolve_key` posts JSON with headers `Content-Type: application/json` and `x-policy-access-key`, uses the existing `join_service_path`, sets an explicit short timeout if the PDK `HttpClient` request builder offers one (check its API; if not, document that the gateway's upstream timeout applies), and never logs the response body or request headers; (e) change the config parse error in `RuntimeConfig::from_bytes` so it reports only the serde error cause and not `String::from_utf8_lossy(bytes)`.
- [ ] **Step 4: Run** `cargo test --lib` -> PASS; `make build` -> succeeds with no new warnings about unused secrets.
- [ ] **Step 5: Audit** `grep -n "logger::" src/lib.rs src/key_resolution.rs` and confirm no new line prints `access_key`, `key`, `token`, `passphrase`, request headers or response bodies.
- [ ] **Step 6: Commit** `feat(policy): fetch DataBlind key from datablindcp when keyId is configured`

---

### Task 4: Integration test, docs, version

**Files:**
- Modify: `tests/requests.rs`, `tests/common/mod.rs` (if needed), `docs/SETUP.md`, `Cargo.toml`

- [ ] **Step 1: Write failing integration tests** with `pdk-test` (Flex + three `HttpMock`s: upstream MCP backend, key service, DataCrypt; follow the pattern already in `tests/requests.rs`): `resolved_mode_workload_ok_forwards_credentials` (assert DataCrypt received the caller's token and the full `guid:pass`), `resolved_mode_workload_not_ok_sends_blank_credentials`, `key_service_down_without_cache_returns_500_blocked_body`, `legacy_mode_unchanged` (config with only `dataBlindKey`: key service mock receives zero requests and DataCrypt receives that key), `key_is_cached_within_ttl` (two requests without override credentials produce exactly one key-service call), and an assertion in each resolved-mode test that the key-service mock saw header `x-policy-access-key` and a body without any DataCrypt key.
- [ ] **Step 2: Run** `make test` -> FAIL for the new tests.
- [ ] **Step 3: Implement** only what the tests reveal as missing (fixtures/config helpers in `tests/common/mod.rs`; fixes in `lib.rs` if a test exposes a bug).
- [ ] **Step 4: Run** `make test` -> PASS.
- [ ] **Step 5:** Add a "Key resolution mode" section to `docs/SETUP.md` (the three new properties, how to get the key ID and access key from datablindcp, the passphrase format `<workloadGuid>:<passphrase>`, the 60 s revocation window for the cached key, and that DataBlind Key is ignored when Key ID is set). Bump `Cargo.toml` version to `1.9.0`.
- [ ] **Step 6: Commit** `feat(policy): key resolution integration tests, docs, 1.9.0`

---

## Self-review notes

- **Spec coverage:** config (T1), parsing and decision matrix (T2), cache and TTL (T2/T3), mode switch and fail-closed behaviour (T3), blank credentials on mismatch (T2/T3), no secret logging and safe parse error (T3), integration and docs (T4). Publishing the policy to Exchange is left to `release.sh`, run by the user.
- **Order:** T1 -> T2 -> T3 -> T4; T4's end-to-end check against the real datablindcp endpoint also needs the other plan's Task 3 deployed and its Task 11 rollout step 6 (live DataCrypt check) done.
