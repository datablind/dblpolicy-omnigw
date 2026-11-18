// The DataBlind workload a request belongs to.
//
// The policy never holds or fetches the data key. The caller's pass phrase has the
// form `<workload GUID>:<passphrase>`, and the policy sends the DataBlind service
// (the AWS Lambda behind dataCryptService) the GUID part; the service asks
// datablindcp for the key of that workload's app zone. The GUID therefore selects
// which zone's key is used, and it comes from the caller, so datablindcp is what
// decides whether that workload may be used (it must exist, be active and have an
// app zone). The policy only makes sure the value is a well-formed GUID, and
// blocks the response when it is not.
//
// Nothing here does I/O or logging. Error texts never repeat the pass phrase.

/// 8-4-4-4-12 hexadecimal digits, either case, and nothing else.
pub fn is_uuid(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// The workload GUID in front of the first `:` of the caller's pass phrase, or why
/// there is none. Nothing is trimmed: a pass phrase that does not start with a GUID
/// followed by `:` is refused as received.
pub fn workload_guid_from_passphrase(passphrase: &str) -> Result<&str, String> {
    let Some((guid, _)) = passphrase.split_once(':') else {
        return Err(
            "the pass phrase must have the form <workload GUID>:<passphrase>".to_string(),
        );
    };
    if !is_uuid(guid) {
        return Err("the pass phrase does not start with a workload GUID".to_string());
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
    fn the_guid_is_the_part_before_the_first_colon() {
        assert_eq!(workload_guid_from_passphrase(&format!("{GUID}:pass")), Ok(GUID));
        // Everything after the first colon belongs to the passphrase, colons included.
        assert_eq!(workload_guid_from_passphrase(&format!("{GUID}:a:b:c")), Ok(GUID));
        // An empty passphrase part is the DataBlind service's to judge, not ours.
        assert_eq!(workload_guid_from_passphrase(&format!("{GUID}:")), Ok(GUID));
        assert_eq!(
            workload_guid_from_passphrase(&format!("{}:pass", GUID.to_uppercase())),
            Ok(GUID.to_uppercase().as_str())
        );
    }

    #[test]
    fn a_pass_phrase_without_a_leading_guid_is_refused() {
        for bad in [
            "".to_string(),
            "pass".to_string(),
            GUID.to_string(),                           // no colon
            format!(":{GUID}"),                         // colon first
            format!(" {GUID}:pass"),                    // leading space
            format!("{GUID} :pass"),                    // space before the colon
            format!("{}:pass", &GUID[..35]),            // one short
            format!("{GUID}0:pass"),                    // one long
            "not-a-guid:pass".to_string(),
            format!("pass:{GUID}"),                     // GUID in the wrong place
        ] {
            assert!(workload_guid_from_passphrase(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn errors_never_repeat_the_pass_phrase() {
        let secret = "hunter2-secret-passphrase";
        for input in [secret.to_string(), format!("{secret}:{secret}")] {
            let message = workload_guid_from_passphrase(&input).unwrap_err();
            assert!(!message.contains(secret), "{message}");
        }
    }
}
