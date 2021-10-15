use super::Region;
use crate::sinks::elasticsearch::ElasticSearchEncoder;
use crate::sinks::util::encoding::EncodingConfigFixed;
use crate::sinks::util::StreamSink;
use crate::{
    config::{DataType, GenerateConfig, SinkConfig, SinkContext, SinkDescription},
    event::Event,
    sinks::elasticsearch::ElasticSearchConfig,
    sinks::util::{http::RequestConfig, BatchConfig, Compression, TowerRequestConfig},
    sinks::{Healthcheck, VectorSink},
};
use async_trait::async_trait;
use futures::stream::{BoxStream, StreamExt};
use indoc::indoc;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SematextLogsConfig {
    region: Option<Region>,
    // Deprecated name
    #[serde(alias = "host")]
    endpoint: Option<String>,
    token: String,

    #[serde(
        skip_serializing_if = "crate::serde::skip_serializing_if_default",
        default
    )]
    pub encoding: EncodingConfigFixed<ElasticSearchEncoder>,

    #[serde(default)]
    request: TowerRequestConfig,

    #[serde(default)]
    batch: BatchConfig,
}

inventory::submit! {
    SinkDescription::new::<SematextLogsConfig>("sematext_logs")
}

impl GenerateConfig for SematextLogsConfig {
    fn generate_config() -> toml::Value {
        toml::from_str(indoc! {r#"
            region = "us"
            token = "${SEMATEXT_TOKEN}"
        "#})
        .unwrap()
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "sematext_logs")]
impl SinkConfig for SematextLogsConfig {
    async fn build(&self, cx: SinkContext) -> crate::Result<(VectorSink, Healthcheck)> {
        let endpoint = match (&self.endpoint, &self.region) {
            (Some(host), None) => host.clone(),
            (None, Some(Region::Us)) => "https://logsene-receiver.sematext.com".to_owned(),
            (None, Some(Region::Eu)) => "https://logsene-receiver.eu.sematext.com".to_owned(),
            (None, None) => "https://logsene-receiver.sematext.com".to_owned(),
            (Some(_), Some(_)) => {
                return Err("Only one of `region` and `host` can be set.".into());
            }
        };

        let (sink, healthcheck) = ElasticSearchConfig {
            endpoint,
            compression: Compression::None,
            doc_type: Some("logs".to_string()),
            index: Some(self.token.clone()),
            batch: self.batch,
            request: RequestConfig {
                tower: self.request,
                ..Default::default()
            },
            encoding: self.encoding.clone(),
            ..Default::default()
        }
        .build(cx)
        .await?;

        let stream = sink.into_stream();
        let mapped_stream = MapTimestampStream { inner: stream };

        Ok((VectorSink::Stream(Box::new(mapped_stream)), healthcheck))
    }

    fn input_type(&self) -> DataType {
        DataType::Log
    }

    fn sink_type(&self) -> &'static str {
        "sematext_logs"
    }
}

struct MapTimestampStream {
    inner: Box<dyn StreamSink + Send>,
}

#[async_trait]
impl StreamSink for MapTimestampStream {
    async fn run(self: Box<Self>, input: BoxStream<'_, Event>) -> Result<(), ()> {
        let mapped_input = input.map(|event| map_timestamp(event)).boxed();
        self.inner.run(mapped_input).await
    }
}

/// Used to map `timestamp` to `@timestamp`.
fn map_timestamp(mut event: Event) -> Event {
    let log = event.as_mut_log();

    if let Some(ts) = log.remove(crate::config::log_schema().timestamp_key()) {
        log.insert("@timestamp", ts);
    }

    if let Some(host) = log.remove(crate::config::log_schema().host_key()) {
        log.insert("os.host", host);
    }

    event
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::SinkConfig,
        sinks::util::test::{build_test_server, load_sink},
        test_util::components::{self, HTTP_SINK_TAGS},
        test_util::{next_addr, random_lines_with_stream},
    };
    use futures::StreamExt;
    use indoc::indoc;

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<SematextLogsConfig>();
    }

    #[tokio::test]
    async fn smoke() {
        let (mut config, cx) = load_sink::<SematextLogsConfig>(indoc! {r#"
            region = "us"
            token = "mylogtoken"
        "#})
        .unwrap();

        // Make sure we can build the config
        let _ = config.build(cx.clone()).await.unwrap();

        let addr = next_addr();
        // Swap out the host so we can force send it
        // to our local server
        config.endpoint = Some(format!("http://{}", addr));
        config.region = None;

        let (sink, _) = config.build(cx).await.unwrap();

        let (mut rx, _trigger, server) = build_test_server(addr);
        tokio::spawn(server);

        let (expected, events) = random_lines_with_stream(100, 10, None);
        components::run_sink(sink, events, &HTTP_SINK_TAGS).await;

        let output = rx.next().await.unwrap();

        // A stream of `serde_json::Value`
        let json = serde_json::Deserializer::from_slice(&output.1[..])
            .into_iter::<serde_json::Value>()
            .map(|v| v.expect("decoding json"));

        let mut expected_message_idx = 0;
        for (i, val) in json.enumerate() {
            // Every even message is the index which contains the token for sematext
            // Every odd message is the actual message in JSON format.
            if i % 2 == 0 {
                // Fetch {index: {_index: ""}}
                let token = val
                    .get("index")
                    .unwrap()
                    .get("_index")
                    .unwrap()
                    .as_str()
                    .unwrap();

                assert_eq!(token, "mylogtoken");
            } else {
                let message = val.get("message").unwrap().as_str().unwrap();
                assert_eq!(message, &expected[expected_message_idx]);
                expected_message_idx += 1;
            }
        }
    }
}
