use crate::sinks::util::{StreamSink, SinkBuilderExt, Compression};
use futures::stream::BoxStream;
use crate::event::{Event, LogEvent};
use vector_core::partition::{NullPartitioner};
use std::num::NonZeroUsize;

use futures::{StreamExt, TryFutureExt};
use crate::sinks::elasticsearch::request_builder::ElasticsearchRequestBuilder;
use crate::buffers::Acker;
use crate::sinks::elasticsearch::service::{ElasticSearchService, ElasticSearchResponse, ElasticSearchRequest};
use crate::sinks::elasticsearch::{BulkAction, Encoding, ElasticSearchCommonMode};
use crate::transforms::metric_to_log::MetricToLog;
use vector_core::stream::BatcherSettings;
use async_trait::async_trait;
use crate::sinks::util::encoding::{EncodingConfigWithDefault, EncodingConfigFixed};
use rusoto_credential::{ProvideAwsCredentials, AwsCredentials};
use futures::future;
use crate::sinks::elasticsearch::encoder::{ProcessedEvent, ElasticSearchEncoder};
use vector_core::ByteSizeOf;
use crate::event::Value;
use crate::{rusoto, Error};

use std::sync::Arc;
use crate::rusoto::AwsCredentialsProvider;
use tower::util::BoxService;

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct PartitionKey {
    pub index: String,
    pub bulk_action: BulkAction,
}

pub struct BatchedEvents {
    pub key: PartitionKey,
    pub events: Vec<ProcessedEvent>,
}

impl ByteSizeOf for BatchedEvents {
    fn allocated_bytes(&self) -> usize {
        self.events.size_of()
    }
}

pub struct ElasticSearchSink {
    pub batch_settings: BatcherSettings,
    pub request_builder: ElasticsearchRequestBuilder,
    pub compression: Compression,
    pub service: BoxService<ElasticSearchRequest, ElasticSearchResponse, Error>,
    pub acker: Acker,
    pub metric_to_log: MetricToLog,
    pub mode: ElasticSearchCommonMode,
    pub id_key_field: Option<String>,
}

impl ElasticSearchSink {
    pub async fn run_inner(self: Box<Self>, input: BoxStream<'_, Event>) -> Result<(), ()> {
        let request_builder_concurrency_limit = NonZeroUsize::new(50);

        let mode = self.mode;
        let id_key_field = self.id_key_field;

        let sink = input
            .scan(self.metric_to_log, |metric_to_log, event| {
                future::ready(Some(match event {
                    Event::Metric(metric) => metric_to_log.transform_one(metric),
                    Event::Log(log) => Some(log)
                }))
            })
            .filter_map(|x| async move { x })
            .filter_map(move |log| {
                future::ready(process_log(log, &mode, &id_key_field))
            })
            .batched(NullPartitioner::new(), self.batch_settings)
            .map(|(_, batch)|{
                batch
            })
            .request_builder(
                request_builder_concurrency_limit,
                self.request_builder,
            ).filter_map(|request| async move {
            match request {
                Err(e) => {
                    error!("Failed to build Elasticsearch request: {:?}.", e);
                    None
                }
                Ok(req) => Some(req),
            }
        })
            .into_driver(self.service, self.acker);

        sink.run().await
    }
}

async fn get_aws_credentials(provider: &AwsCredentialsProvider) -> Option<AwsCredentials> {
    Some(match provider.credentials().await {
        Ok(creds) => creds,
        Err(err) => {
            error!(message = "Failed to obtain AWS credentials", error=?err);
            return None;
        }
    })
}

pub fn process_log(
    mut log: LogEvent,
    mode: &ElasticSearchCommonMode,
    id_key_field: &Option<String>
) -> Option<ProcessedEvent> {
    let index = mode.index(&log)?;
    let bulk_action = mode.bulk_action(&log)?;

    if let Some(cfg) = mode.as_data_stream_config() {
        cfg.sync_fields(&mut log);
        cfg.remap_timestamp(&mut log);
    };
    let id = if let Some(Value::Bytes(key)) =
    id_key_field.as_ref().and_then(|key| log.remove(key)) {
        Some(String::from_utf8_lossy(&key).into_owned())
    } else {
        None
    };
    Some(ProcessedEvent {
        index,
        bulk_action,
        log,
        id
    })
}


#[async_trait]
impl StreamSink for ElasticSearchSink {
    async fn run(self: Box<Self>, input: BoxStream<'_, Event>) -> Result<(), ()> {
        self.run_inner(input).await
    }
}
