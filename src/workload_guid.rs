// The DataBlind workload this policy is registered as.
//
// The policy never holds or fetches the data key. It sends the DataBlind service
// (the AWS Lambda behind dataCryptService) the GUID of its own workload, and the
// service asks datablindcp for the key of that workload's app zone. The setting
// therefore pins which zone's key this policy instance uses, so it must be a
// well-formed GUID or the policy must not run.
//
// Nothing here does I/O or logging. Error texts name the setting and never repeat
// its value.

/// 8-4-4-4-12 hexadecimal digits, either case, and nothing else.
pub fn is_uuid(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// The configured workload GUID with surrounding whitespace removed, or why it
/// cannot be used.
pub fn checked_workload_guid(configured: &str) -> Result<&str, String> {
    let guid = configured.trim();
    if guid.is_empty() {
        return Err("workloadGuid is required (the GUID of this policy's DataBlind workload)".to_string());
    }
    if !is_uuid(guid) {
        return Err("workloadGuid must be a UUID (the GUID of this policy's DataBlind workload)".to_string());
    }
    Ok(guid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUID: &str = "11111111-2222-4333-8444-555555555555";

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
            assert!(!is_uuid(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_valid_guid_is_returned_trimmed() {
        assert_eq!(checked_workload_guid(GUID), Ok(GUID));
        assert_eq!(checked_workload_guid(&format!("  {GUID}\n")), Ok(GUID));
    }

    #[test]
    fn a_blank_or_malformed_guid_is_refused() {
        for bad in ["", "   ", "not-a-guid", "11111111-2222-4333-8444"] {
            assert!(checked_workload_guid(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn errors_name_the_setting_and_never_repeat_the_value() {
        let value = "super-secret-looking-but-not-a-guid";
        let message = checked_workload_guid(value).unwrap_err();
        assert!(message.contains("workloadGuid"));
        assert!(!message.contains(value));
    }
}
