use std::io;

use bytes::Bytes;
use codecs::decoding::{DeserializerConfig, FramingConfig};
use vector_config::{configurable_component, NamedComponent};
use vector_core::{
    config::{log_schema, LogNamespace},
    event::{Event, LogEvent},
};

use crate::{
    config::{Output, Resource, SourceConfig, SourceContext},
    serde::default_decoding,
    sources::demo_mode,
};

use super::FileDescriptorConfig;

/// Configuration for the `stdin` source.
#[configurable_component(source("stdin"))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct StdinConfig {
    /// The maximum buffer size, in bytes, of incoming messages.
    ///
    /// Messages larger than this are truncated.
    #[serde(default = "crate::serde::default_max_length")]
    pub max_length: usize,

    /// Overrides the name of the log field used to add the current hostname to each event.
    ///
    /// The value will be the current hostname for wherever Vector is running.
    ///
    /// By default, the [global `log_schema.host_key` option][global_host_key] is used.
    ///
    /// [global_host_key]: https://vector.dev/docs/reference/configuration/global-options/#log_schema.host_key
    pub host_key: Option<String>,

    #[configurable(derived)]
    pub framing: Option<FramingConfig>,

    #[configurable(derived)]
    #[serde(default = "default_decoding")]
    pub decoding: DeserializerConfig,
}

impl FileDescriptorConfig for StdinConfig {
    fn host_key(&self) -> Option<String> {
        self.host_key.clone()
    }

    fn framing(&self) -> Option<FramingConfig> {
        self.framing.clone()
    }

    fn decoding(&self) -> DeserializerConfig {
        self.decoding.clone()
    }

    fn description(&self) -> String {
        Self::NAME.to_string()
    }
}

impl Default for StdinConfig {
    fn default() -> Self {
        StdinConfig {
            max_length: crate::serde::default_max_length(),
            host_key: Default::default(),
            framing: None,
            decoding: default_decoding(),
        }
    }
}

impl_generate_config_from_default!(StdinConfig);

#[async_trait::async_trait]
impl SourceConfig for StdinConfig {
    async fn build(&self, cx: SourceContext) -> crate::Result<crate::sources::Source> {
        self.source(io::BufReader::new(io::stdin()), cx.shutdown, cx.out)
    }

    fn outputs(&self, _global_log_namespace: LogNamespace) -> Vec<Output> {
        vec![Output::default(self.decoding.output_type())]
    }

    fn resources(&self) -> Vec<Resource> {
        vec![Resource::Fd(0)]
    }

    fn can_acknowledge(&self) -> bool {
        false
    }

    fn generate_demo_data(&self) -> Event {
        let mut event = LogEvent::default();

        let host_key = self
            .host_key()
            .unwrap_or_else(|| log_schema().host_key().to_string());
        let hostname = crate::get_hostname().ok();

        let source_type = Bytes::from_static(Self::NAME.as_bytes());

        event.try_insert(log_schema().source_type_key(), source_type.clone());
        event.try_insert(log_schema().timestamp_key(), chrono::Utc::now());

        if let Some(hostname) = &hostname {
            event.try_insert(host_key.as_str(), hostname.clone());
        }

        event.insert("message", demo_mode::random_message());
        Event::Log(event)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::{
        config::log_schema, shutdown::ShutdownSignal,
        test_util::components::assert_source_compliance, test_util::components::SOURCE_TAGS,
        SourceSender,
    };
    use futures::StreamExt;

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<StdinConfig>();
    }

    #[tokio::test]
    async fn stdin_decodes_line() {
        assert_source_compliance(&SOURCE_TAGS, async {
            let (tx, rx) = SourceSender::new_test();
            let config = StdinConfig::default();
            let buf = Cursor::new("hello world\nhello world again");

            config
                .source(buf, ShutdownSignal::noop(), tx)
                .unwrap()
                .await
                .unwrap();

            let mut stream = rx;

            let event = stream.next().await;
            assert_eq!(
                Some("hello world".into()),
                event.map(|event| event.as_log()[log_schema().message_key()]
                    .to_string_lossy()
                    .into_owned())
            );

            let event = stream.next().await;
            assert_eq!(
                Some("hello world again".into()),
                event.map(|event| event.as_log()[log_schema().message_key()]
                    .to_string_lossy()
                    .into_owned())
            );

            let event = stream.next().await;
            assert!(event.is_none());
        })
        .await;
    }
}
