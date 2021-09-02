use crate::config::{DataType, GenerateConfig, SinkConfig, SinkContext};
use crate::http::HttpClient;
use crate::sinks::datadog::logs::log_api::LogApi;
use crate::sinks::datadog::Region;
use crate::sinks::util::encoding::EncodingConfigWithDefault;
use crate::sinks::util::{BatchConfig, Compression, TowerRequestConfig};
use crate::sinks::{Healthcheck, VectorSink};
use crate::tls::{MaybeTlsSettings, TlsConfig};
use futures::FutureExt;
use indoc::indoc;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceBuilder;

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct DatadogLogsConfig {
    pub(crate) endpoint: Option<String>,
    // Deprecated, replaced by the site option
    region: Option<Region>,
    site: Option<String>,
    // Deprecated name
    #[serde(alias = "api_key")]
    default_api_key: String,
    #[serde(
        skip_serializing_if = "crate::serde::skip_serializing_if_default",
        default
    )]
    pub(crate) encoding: EncodingConfigWithDefault<Encoding>,
    tls: Option<TlsConfig>,

    #[serde(default)]
    compression: Option<Compression>,

    #[serde(default)]
    batch: BatchConfig,

    #[serde(default)]
    request: TowerRequestConfig,
}

#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone, Derivative)]
#[serde(rename_all = "snake_case")]
#[derivative(Default)]
pub enum Encoding {
    #[derivative(Default)]
    Json,
}

impl GenerateConfig for DatadogLogsConfig {
    fn generate_config() -> toml::Value {
        toml::from_str(indoc! {r#"
            default_api_key = "${DATADOG_API_KEY_ENV_VAR}"
        "#})
        .unwrap()
    }
}

impl DatadogLogsConfig {
    fn get_uri(&self) -> http::Uri {
        let endpoint = self
            .endpoint
            .clone()
            .or_else(|| {
                self.site
                    .as_ref()
                    .map(|s| format!("https://http-intake.logs.{}/v1/input", s))
            })
            .unwrap_or_else(|| match self.region {
                Some(Region::Eu) => "https://http-intake.logs.datadoghq.eu/v1/input".to_string(),
                None | Some(Region::Us) => {
                    "https://http-intake.logs.datadoghq.com/v1/input".to_string()
                }
            });
        http::Uri::try_from(endpoint).expect("URI not valid")
    }
}

// TODO re-introduce a proper healthcheck
async fn nop_healthcheck() -> crate::Result<()> {
    Ok(())
}

#[async_trait::async_trait]
#[typetag::serde(name = "datadog_logs")]
impl SinkConfig for DatadogLogsConfig {
    async fn build(&self, cx: SinkContext) -> crate::Result<(VectorSink, Healthcheck)> {
        let tls_settings = MaybeTlsSettings::from_config(
            &Some(self.tls.clone().unwrap_or_else(TlsConfig::enabled)),
            false,
        )?;

        let request_settings = self.request.unwrap_with(&TowerRequestConfig::default());
        let client = HttpClient::new(tls_settings, cx.proxy())?;
        let client = ServiceBuilder::new()
            .rate_limit(
                request_settings.rate_limit_num,
                request_settings.rate_limit_duration,
            )
            // TODO types are bungled here somehow
            // .retry(LogApiRetry)
            // .layer(AdaptiveConcurrencyLimitLayer::new(
            //     request_settings.concurrency,
            //     request_settings.adaptive_concurrency,
            //     LogApiRetry,
            // ))
            .timeout(request_settings.timeout)
            .service(client);

        // let healthcheck = healthcheck(
        //     service.clone(),
        //     client.clone(),
        //     self.default_api_key.clone(),
        // )
        // .boxed();
        let healthcheck = nop_healthcheck().boxed();

        let default_api_key: Arc<str> = Arc::from(self.default_api_key.clone().as_str());
        let log_api = LogApi::new();
        let log_api = if let Some(batch_timeout) = self.batch.timeout_secs {
            log_api.batch_timeout(Duration::from_secs(batch_timeout))
        } else {
            log_api
        };
        let log_api = log_api
            .bytes_stored_limit(
                self.batch
                    .max_bytes
                    .map(|bytes| bytes as u64)
                    .unwrap_or_else(|| bytesize::mib(5_u32) as u64),
            )
            .compression(self.compression.unwrap_or_default())
            .datadog_uri(self.get_uri())
            .default_api_key(default_api_key)
            .encoding(self.encoding.clone())
            .http_client(client)
            .log_schema(vector_core::config::log_schema())
            .build()?;
        let sink = VectorSink::Stream(Box::new(log_api));

        Ok((sink, healthcheck))
    }

    fn input_type(&self) -> DataType {
        DataType::Log
    }

    fn sink_type(&self) -> &'static str {
        "datadog_logs"
    }
}

#[cfg(test)]
mod test {
    use crate::sinks::datadog::logs::DatadogLogsConfig;

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<DatadogLogsConfig>();
    }
}
