use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct FilterConditions0Config {
    #[serde(alias = "field")]
    pub field: Option<String>,
    #[serde(alias = "matchType")]
    pub match_type: Option<String>,
    #[serde(alias = "value")]
    pub value: Option<String>,
}
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(
        alias = "dataBlindPassphrase",
        deserialize_with = "de_data_blind_passphrase_0"
    )]
    pub data_blind_passphrase: pdk::script::Script,
    #[serde(alias = "dataBlindToken", deserialize_with = "de_data_blind_token_1")]
    pub data_blind_token: pdk::script::Script,
    #[serde(alias = "dataCryptApiKey")]
    pub data_crypt_api_key: String,
    #[serde(
        alias = "dataCryptService",
        deserialize_with = "pdk::serde::deserialize_service"
    )]
    pub data_crypt_service: pdk::hl::Service,
    #[serde(alias = "debugLogging")]
    pub debug_logging: Option<bool>,
    #[serde(alias = "eligibleHttpCodes", deserialize_with = "de_eligible_http_codes_2")]
    pub eligible_http_codes: pdk::script::Script,
    #[serde(alias = "encryptMode")]
    pub encrypt_mode: Option<String>,
    #[serde(alias = "filterConditions")]
    pub filter_conditions: Option<Vec<FilterConditions0Config>>,
    #[serde(alias = "filterMode")]
    pub filter_mode: Option<String>,
    #[serde(alias = "filterOperator")]
    pub filter_operator: Option<String>,
    #[serde(alias = "keyId")]
    pub key_id: String,
    #[serde(
        alias = "keyServiceUrl",
        deserialize_with = "pdk::serde::deserialize_service"
    )]
    pub key_service_url: pdk::hl::Service,
    #[serde(alias = "policyAccessKey")]
    pub policy_access_key: String,
    #[serde(alias = "sensitiveFieldsMultiLine")]
    pub sensitive_fields_multi_line: Option<String>,
    #[serde(alias = "tweak", deserialize_with = "de_tweak_3")]
    pub tweak: pdk::script::Script,
}
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    let config: Config = serde_json::from_slice(abi.get_configuration())
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to parse configuration '{}'. Cause: {}",
                String::from_utf8_lossy(abi.get_configuration()), err
            )
        })?;
    abi.service_create(config.data_crypt_service)?;
    abi.service_create(config.key_service_url)?;
    abi.setup()?;
    Ok(())
}
fn de_data_blind_passphrase_0<'de, D>(
    deserializer: D,
) -> Result<pdk::script::Script, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let exp: pdk::script::Expression = serde::de::Deserialize::deserialize(
        deserializer,
    )?;
    pdk::script::ScriptingEngine::script(&exp)
        .input(pdk::script::Input::Attributes)
        .input(pdk::script::Input::Payload(pdk::script::Format::PlainText))
        .compile()
        .map_err(serde::de::Error::custom)
}
fn de_data_blind_token_1<'de, D>(
    deserializer: D,
) -> Result<pdk::script::Script, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let exp: pdk::script::Expression = serde::de::Deserialize::deserialize(
        deserializer,
    )?;
    pdk::script::ScriptingEngine::script(&exp)
        .input(pdk::script::Input::Attributes)
        .input(pdk::script::Input::Payload(pdk::script::Format::PlainText))
        .compile()
        .map_err(serde::de::Error::custom)
}
fn de_eligible_http_codes_2<'de, D>(
    deserializer: D,
) -> Result<pdk::script::Script, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let exp: pdk::script::Expression = serde::de::Deserialize::deserialize(
        deserializer,
    )?;
    pdk::script::ScriptingEngine::script(&exp)
        .input(pdk::script::Input::Attributes)
        .input(pdk::script::Input::Payload(pdk::script::Format::PlainText))
        .compile()
        .map_err(serde::de::Error::custom)
}
fn de_tweak_3<'de, D>(deserializer: D) -> Result<pdk::script::Script, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let exp: pdk::script::Expression = serde::de::Deserialize::deserialize(
        deserializer,
    )?;
    pdk::script::ScriptingEngine::script(&exp)
        .input(pdk::script::Input::Attributes)
        .input(pdk::script::Input::Payload(pdk::script::Format::Json))
        .compile()
        .map_err(serde::de::Error::custom)
}
