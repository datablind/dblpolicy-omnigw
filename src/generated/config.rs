use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "dataBlindApiKey")]
    pub data_blind_api_key: Option<String>,
    #[serde(alias = "dataBlindApiUri")]
    pub data_blind_api_uri: Option<String>,
    #[serde(alias = "dataBlindKey", deserialize_with = "de_data_blind_key_0")]
    pub data_blind_key: pdk::script::Script,
    #[serde(
        alias = "dataBlindPassphrase",
        deserialize_with = "de_data_blind_passphrase_1"
    )]
    pub data_blind_passphrase: pdk::script::Script,
    #[serde(alias = "dataBlindToken", deserialize_with = "de_data_blind_token_2")]
    pub data_blind_token: pdk::script::Script,
    #[serde(alias = "dataCryptApiKey")]
    pub data_crypt_api_key: String,
    #[serde(
        alias = "dataCryptService",
        deserialize_with = "pdk::serde::deserialize_service"
    )]
    pub data_crypt_service: pdk::hl::Service,
    #[serde(alias = "eligibleHttpCodes", deserialize_with = "de_eligible_http_codes_3")]
    pub eligible_http_codes: pdk::script::Script,
    #[serde(alias = "filterRule")]
    pub filter_rule: Option<Vec<String>>,
    #[serde(alias = "proxyHost")]
    pub proxy_host: Option<String>,
    #[serde(alias = "proxyPassword")]
    pub proxy_password: Option<String>,
    #[serde(alias = "proxyPort")]
    pub proxy_port: Option<String>,
    #[serde(alias = "proxyUsername", default, deserialize_with = "de_proxy_username_4")]
    pub proxy_username: Option<pdk::script::Script>,
    #[serde(alias = "sensitiveFieldsMultiLine")]
    pub sensitive_fields_multi_line: Option<Vec<String>>,
    #[serde(alias = "sensitiveFieldsSpecified")]
    pub sensitive_fields_specified: bool,
    #[serde(alias = "tweak", deserialize_with = "de_tweak_5")]
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
    abi.setup()?;
    Ok(())
}
fn de_data_blind_key_0<'de, D>(deserializer: D) -> Result<pdk::script::Script, D::Error>
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
fn de_data_blind_passphrase_1<'de, D>(
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
fn de_data_blind_token_2<'de, D>(
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
fn de_eligible_http_codes_3<'de, D>(
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
fn de_proxy_username_4<'de, D>(
    deserializer: D,
) -> Result<Option<pdk::script::Script>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let exp: Option<pdk::script::Expression> = serde::de::Deserialize::deserialize(
        deserializer,
    )?;
    exp.map(|exp| {
            pdk::script::ScriptingEngine::script(&exp)
                .input(pdk::script::Input::Attributes)
                .input(pdk::script::Input::Payload(pdk::script::Format::PlainText))
                .compile()
                .map_err(serde::de::Error::custom)
        })
        .transpose()
}
fn de_tweak_5<'de, D>(deserializer: D) -> Result<pdk::script::Script, D::Error>
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
