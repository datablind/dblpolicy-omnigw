// Where the data key for a request comes from.
//
// Normally the policy never holds the data key. The caller's override token names
// the DataBlind workload it was created for, and the policy sends the DataBlind
// service (the AWS Lambda behind dataCryptService) that GUID; the service asks
// datablindcp for the key of that workload's app zone. The GUID therefore selects
// which zone's key is used, and it comes from the caller, so datablindcp is what
// decides whether that workload may be used (it must exist, be active and have an
// app zone). The policy only reads the GUID out of the token and makes sure it is
// well-formed; it does not verify the token (the DataBlind service does), and it
// blocks the response when there is no usable GUID.
//
// Optionally an operator picks **Provide DataBlind Key** (the key mode setting) and
// enters a key. Then that key is sent to the service and used instead and nothing is
// fetched. That is also the only way to serve a request that has no override token,
// or whose token names no workload: the pass phrase never carries a workload.
//
// Nothing here does I/O or logging. Error texts never repeat the token, the pass
// phrase or the key.

/// Where the service gets the data key for one request.
#[derive(Debug, PartialEq, Eq)]
pub enum KeySource<'a> {
    /// The key set on the policy, sent to the service as it was entered.
    Key(&'a str),
    /// The workload whose app zone key the service fetches from datablindcp.
    Workload(&'a str),
}

/// Which of the two ways of getting the data key the operator chose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyMode {
    /// None: the key is fetched for the workload named in the override token.
    FromWorkload,
    /// Provide DataBlind Key: the key entered in the policy is used.
    Provided,
}

/// The mode from the key mode setting ("None (requires a workload ...)" or "Provide
/// DataBlind Key"). A choice that is missing or not recognised (a policy set up before
/// the setting existed) is read from the key itself: a key that is filled in is used.
/// An explicit None ignores a key that is still stored in the configuration.
pub fn resolve_key_mode(key_mode: Option<&str>, configured_key: Option<&str>) -> KeyMode {
    let choice = key_mode.map(|value| value.trim().to_ascii_lowercase());
    match choice.as_deref() {
        Some(value) if value.starts_with("none") => KeyMode::FromWorkload,
        Some(value) if value.starts_with("provide") => KeyMode::Provided,
        _ if configured_key.is_some_and(|key| !key.trim().is_empty()) => KeyMode::Provided,
        _ => KeyMode::FromWorkload,
    }
}

/// With Provide DataBlind Key, the configured key (it must not be empty or only
/// whitespace: that is a setup mistake and the request is refused). Otherwise the
/// workload GUID from the override token.
pub fn key_source<'a>(
    mode: KeyMode,
    configured_key: Option<&'a str>,
    token: &'a str,
) -> Result<KeySource<'a>, String> {
    match mode {
        KeyMode::Provided => match configured_key {
            Some(key) if !key.trim().is_empty() => Ok(KeySource::Key(key)),
            _ => Err("Provide DataBlind Key is selected but no key is entered".to_string()),
        },
        KeyMode::FromWorkload => workload_guid_from_token(token).map(KeySource::Workload),
    }
}

/// 8-4-4-4-12 hexadecimal digits, either case, and nothing else.
pub fn is_uuid(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == GUID_LEN
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

// A version 2 override token has no separators, only fixed positions:
//   `dbot2` + expiry (14 digits, yyyyMMddHHmmss) + workload GUID (36 characters, or
//   nothing) + HMAC (64 hexadecimal characters)
// The version is the first five characters. It cannot be read as "dbot" plus digits,
// because the expiry's digits follow it. A token of any other version is not read.
const TOKEN_PREFIX: &str = "dbot2";
const EXPIRY_LEN: usize = 14;
const GUID_LEN: usize = 36;
const MAC_HEX_LEN: usize = 64;

/// The workload GUID inside a version 2 override token, or why there is none. Only
/// the shape is checked: whether the token is genuine is for the DataBlind service.
pub fn workload_guid_from_token(token: &str) -> Result<&str, String> {
    let Some(rest) = token.strip_prefix(TOKEN_PREFIX) else {
        return Err("there is no version 2 override token".to_string());
    };
    // Cutting by position below must never land inside a multi-byte character.
    if !rest.is_ascii() || rest.len() < EXPIRY_LEN + MAC_HEX_LEN {
        return Err("the override token is malformed".to_string());
    }
    let (expiry, rest) = rest.split_at(EXPIRY_LEN);
    let (workload, mac) = rest.split_at(rest.len() - MAC_HEX_LEN);
    if !expiry.bytes().all(|b| b.is_ascii_digit()) || !mac.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("the override token is malformed".to_string());
    }
    match workload.len() {
        0 => Err("the override token names no workload".to_string()),
        GUID_LEN if is_uuid(workload) => Ok(workload),
        _ => Err("the override token is malformed".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUID: &str = "11111111-2222-4333-8444-555555555555";
    const EXPIRY: &str = "20261127055025";
    const MAC: &str = "2b79c5819fc19d5df3f1542febe1327c1f4c995732ee1f3648fef3afac1fb5c8";

    // A token exactly as DataBlind's token service produces it (see TokenApp).
    const REAL_TOKEN: &str = "dbot220261127055025a2e225a6-2960-4579-846b-058f11daf8692b79c5819fc19d5df3f1542febe1327c1f4c995732ee1f3648fef3afac1fb5c8";
    const REAL_GUID: &str = "a2e225a6-2960-4579-846b-058f11daf869";

    fn token(workload: &str) -> String {
        format!("{TOKEN_PREFIX}{EXPIRY}{workload}{MAC}")
    }

    #[test]
    fn is_uuid_accepts_either_case() {
        assert!(is_uuid(GUID));
        assert!(is_uuid(&GUID.to_uppercase()));
    }

    #[test]
    fn is_uuid_rejects_everything_else() {
        for bad in [
            "",
            "x",
            "11111111-2222-4333-8444-55555555555",   // one short
            "11111111-2222-4333-8444-5555555555555", // one long
            "11111111_2222_4333_8444_555555555555",  // wrong separators
            "g1111111-2222-4333-8444-555555555555",  // not hex
            " 11111111-2222-4333-8444-555555555555", // surrounding space
            "11111111-2222-4333-8444-555555555555\n",
            "11111111-2222-4333-8444-555555555555:pass",
        ] {
            assert!(!is_uuid(bad), "{:?}", bad);
        }
    }

    #[test]
    fn the_workload_is_read_from_a_real_token() {
        assert_eq!(REAL_TOKEN.len(), 119);
        assert_eq!(workload_guid_from_token(REAL_TOKEN), Ok(REAL_GUID));
    }

    #[test]
    fn the_workload_is_read_by_position() {
        assert_eq!(workload_guid_from_token(&token(GUID)), Ok(GUID));
        // Either case of the GUID and of the hexadecimal MAC is read.
        assert_eq!(
            workload_guid_from_token(&token(&GUID.to_uppercase())),
            Ok(GUID.to_uppercase().as_str())
        );
        let upper_mac = format!("{TOKEN_PREFIX}{EXPIRY}{GUID}{}", MAC.to_uppercase());
        assert_eq!(workload_guid_from_token(&upper_mac), Ok(GUID));
    }

    #[test]
    fn a_token_without_a_workload_names_none() {
        let message = workload_guid_from_token(&token("")).unwrap_err();
        assert!(message.contains("no workload"), "{}", message);
    }

    #[test]
    fn anything_that_is_not_a_version_2_token_is_refused() {
        let good = token(GUID);
        for bad in [
            "".to_string(),
            "pass".to_string(),
            format!("{GUID}:pass"),                       // the old pass phrase form is not read
            good.replacen("dbot2", "dbot3", 1),           // another version is not read
            good.replacen("dbot2", "DBOT2", 1),
            format!(" {good}"),
            format!("{good} "),
            good[..good.len() - 1].to_string(),           // MAC one short: the GUID boundary moves
            format!("{good}0"),                           // MAC one long
            format!("{TOKEN_PREFIX}{EXPIRY}{}{MAC}", &GUID[..35]),     // GUID one short
            format!("{TOKEN_PREFIX}{EXPIRY}{GUID}0{MAC}"),             // GUID one long
            format!("{TOKEN_PREFIX}{}{GUID}{MAC}", "2026112705502x"),  // expiry not digits
            format!("{TOKEN_PREFIX}{}{GUID}{MAC}", "2026112705502"),   // expiry one short
            format!("{TOKEN_PREFIX}{EXPIRY}{GUID}{}", "z".repeat(64)), // MAC not hexadecimal
            format!("{TOKEN_PREFIX}{EXPIRY}{}{MAC}", "11111111_2222_4333_8444_555555555555"),
            format!("{TOKEN_PREFIX}{EXPIRY}é{GUID}{MAC}"), // a multi-byte character must not panic
            TOKEN_PREFIX.to_string(),
        ] {
            assert!(workload_guid_from_token(&bad).is_err(), "{:?}", bad);
        }
    }

    #[test]
    fn errors_never_repeat_the_token() {
        let secret = "hunter2-secret-token-value";
        for input in [secret.to_string(), format!("{TOKEN_PREFIX}{secret}"), token("")] {
            let message = workload_guid_from_token(&input).unwrap_err();
            assert!(!message.contains(secret) && !message.contains(MAC), "{}", message);
        }
    }

    #[test]
    fn a_provided_key_is_used_and_the_token_is_not_needed() {
        let mode = KeyMode::Provided;
        assert_eq!(key_source(mode, Some("k3y"), ""), Ok(KeySource::Key("k3y")));
        assert_eq!(key_source(mode, Some("k3y"), "no-token"), Ok(KeySource::Key("k3y")));
        assert_eq!(key_source(mode, Some("k3y"), &token("")), Ok(KeySource::Key("k3y")));
        assert_eq!(key_source(mode, Some("k3y"), &token(GUID)), Ok(KeySource::Key("k3y")));
    }

    #[test]
    fn the_key_is_sent_as_entered() {
        assert_eq!(key_source(KeyMode::Provided, Some(" k3y "), ""), Ok(KeySource::Key(" k3y ")));
    }

    #[test]
    fn provide_key_without_a_key_is_refused_even_if_the_token_names_a_workload() {
        for key in [None, Some(""), Some("   "), Some("\n")] {
            let message = key_source(KeyMode::Provided, key, &token(GUID)).unwrap_err();
            assert!(message.contains("no key is entered"), "{:?} {}", key, message);
        }
    }

    #[test]
    fn from_workload_reads_the_workload_in_the_token_and_ignores_a_stored_key() {
        let token = token(GUID);
        // A key left over in the configuration after switching back to None is not used.
        for key in [None, Some(""), Some("   "), Some("stale-key")] {
            assert_eq!(
                key_source(KeyMode::FromWorkload, key, &token),
                Ok(KeySource::Workload(GUID)),
                "{:?}",
                key
            );
        }
    }

    #[test]
    fn from_workload_refuses_a_token_without_a_usable_workload() {
        for key in [None, Some("stale-key")] {
            let mode = KeyMode::FromWorkload;
            assert!(key_source(mode, key, "").is_err(), "{:?}", key); // no token at all
            assert!(key_source(mode, key, "pass").is_err(), "{:?}", key);
            assert!(key_source(mode, key, &token("")).is_err(), "{:?}", key); // a token naming no workload
            assert!(key_source(mode, key, &format!("{GUID}:pass")).is_err(), "{:?}", key); // the old form
        }
    }

    #[test]
    fn the_key_mode_follows_the_setting() {
        for none in [
            "None (requires a workload to fetch the DataBlind Key)",
            "None",
            " none ",
        ] {
            // An explicit None wins over a key that is still stored.
            assert_eq!(resolve_key_mode(Some(none), Some("stale-key")), KeyMode::FromWorkload, "{none}");
            assert_eq!(resolve_key_mode(Some(none), None), KeyMode::FromWorkload, "{none}");
        }
        for provide in ["Provide DataBlind Key", "provide datablind key"] {
            assert_eq!(resolve_key_mode(Some(provide), Some("k3y")), KeyMode::Provided, "{provide}");
            // Chosen but empty: still Provided, so the request is refused (see above).
            assert_eq!(resolve_key_mode(Some(provide), None), KeyMode::Provided, "{provide}");
            assert_eq!(resolve_key_mode(Some(provide), Some("  ")), KeyMode::Provided, "{provide}");
        }
    }

    #[test]
    fn without_a_key_mode_the_key_decides() {
        for missing in [None, Some(""), Some("something else")] {
            assert_eq!(resolve_key_mode(missing, Some("k3y")), KeyMode::Provided, "{:?}", missing);
            assert_eq!(resolve_key_mode(missing, None), KeyMode::FromWorkload, "{:?}", missing);
            assert_eq!(resolve_key_mode(missing, Some("  ")), KeyMode::FromWorkload, "{:?}", missing);
        }
    }

    #[test]
    fn errors_never_repeat_the_key() {
        let key = "super-secret-key-value";
        // A key is only ever in the error path if it was ignored, which it is not.
        assert!(key_source(KeyMode::Provided, Some(key), "").is_ok());
        let message = key_source(KeyMode::FromWorkload, Some(key), key).unwrap_err();
        assert!(!message.contains(key), "{}", message);
        let message = key_source(KeyMode::Provided, Some("  "), key).unwrap_err();
        assert!(!message.contains(key), "{}", message);
    }
}
