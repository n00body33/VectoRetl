#![cfg(test)]

use super::*;
use crate::config::{SinkConfig, SinkContext};
use crate::rusoto::RegionOrEndpoint;
use crate::sinks::aws_kinesis_firehose::config::{
    KinesisFirehoseDefaultBatchSettings, MAX_PAYLOAD_EVENTS, MAX_PAYLOAD_SIZE,
};
use crate::sinks::util::encoding::EncodingConfig;
use crate::sinks::util::encoding::StandardEncodings;
use crate::sinks::util::{BatchConfig, Compression};

#[test]
fn generate_config() {
    crate::test_util::test_generate_config::<KinesisFirehoseSinkConfig>();
}

#[tokio::test]
async fn check_batch_size() {
    // Sink builder should limit the batch size to the upper bound.
    let mut batch = BatchConfig::<KinesisFirehoseDefaultBatchSettings>::default();
    batch.max_bytes = Some(MAX_PAYLOAD_SIZE + 1);

    let config = KinesisFirehoseSinkConfig {
        stream_name: String::from("test"),
        region: RegionOrEndpoint::with_endpoint("http://localhost:4566".into()),
        encoding: EncodingConfig::from(StandardEncodings::Json),
        compression: Compression::None,
        batch,
        request: Default::default(),
        assume_role: None,
        auth: Default::default(),
    };

    let cx = SinkContext::new_test();
    let res = config.build(cx).await;
    assert!(res.is_ok());
}

#[tokio::test]
async fn check_batch_events() {
    let mut batch = BatchConfig::<KinesisFirehoseDefaultBatchSettings>::default();
    batch.max_events = Some(MAX_PAYLOAD_EVENTS + 1);

    let config = KinesisFirehoseSinkConfig {
        stream_name: String::from("test"),
        region: RegionOrEndpoint::with_endpoint("http://localhost:4566".into()),
        encoding: EncodingConfig::from(StandardEncodings::Json),
        compression: Compression::None,
        batch,
        request: Default::default(),
        assume_role: None,
        auth: Default::default(),
    };

    let cx = SinkContext::new_test();
    let res = config.build(cx).await;
    assert!(res.is_ok());
}
