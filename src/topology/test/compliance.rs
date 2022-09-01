use std::sync::Mutex;

use async_trait::async_trait;
use futures_util::{stream::BoxStream, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot::{channel, Receiver, Sender};
use vector_core::{
    config::{AcknowledgementsConfig, Input},
    event::{Event, EventArray, EventContainer, LogEvent},
    sink::{StreamSink, VectorSink},
};

use crate::{
    config::{unit_test::UnitTestSourceConfig, ConfigBuilder, SinkConfig, SinkContext},
    sinks::Healthcheck,
    test_util::{
        components::assert_transform_compliance,
        mock::transforms::{NoopTransformConfig, TransformType},
        start_topology,
    },
    topology::RunningTopology,
};

#[derive(Debug, Serialize, Deserialize)]
struct OneshotSinkConfig {
    #[serde(skip)]
    tx: Mutex<Option<Sender<EventArray>>>,
}

#[async_trait]
#[typetag::serde(name = "oneshot")]
impl SinkConfig for OneshotSinkConfig {
    fn input(&self) -> Input {
        Input::all()
    }

    fn sink_type(&self) -> &'static str {
        "oneshot"
    }

    fn acknowledgements(&self) -> &AcknowledgementsConfig {
        &AcknowledgementsConfig::DEFAULT
    }

    async fn build(&self, _cx: SinkContext) -> crate::Result<(VectorSink, Healthcheck)> {
        let tx = {
            let mut guard = self.tx.lock().expect("who cares if the lock is poisoned");
            guard.take()
        };
        let sink = Box::new(OneshotSink { tx });

        let healthcheck = Box::pin(async { Ok(()) });

        Ok((VectorSink::Stream(sink), healthcheck))
    }
}

struct OneshotSink {
    tx: Option<Sender<EventArray>>,
}

#[async_trait]
impl StreamSink<EventArray> for OneshotSink {
    async fn run(mut self: Box<Self>, mut input: BoxStream<'_, EventArray>) -> Result<(), ()> {
        let tx = self.tx.take().expect("cannot take rx more than once");
        let events = input
            .next()
            .await
            .expect("must always get an item in oneshot sink");
        let _ = tx.send(events);

        Ok(())
    }
}

async fn create_topology(
    event: Event,
    transform_type: TransformType,
) -> (RunningTopology, Receiver<EventArray>) {
    let mut builder = ConfigBuilder::default();

    let (tx, rx) = channel();

    builder.add_source(
        "in",
        UnitTestSourceConfig {
            events: vec![event],
        },
    );
    builder.add_transform(
        "transform",
        &["in"],
        NoopTransformConfig::from(transform_type),
    );
    builder.add_sink(
        "out",
        &["transform"],
        OneshotSinkConfig {
            tx: Mutex::new(Some(tx)),
        },
    );

    let config = builder.build().expect("building config should not fail");
    let (topology, _) = start_topology(config, false).await;

    (topology, rx)
}

#[tokio::test]
async fn test_function_transform_single_event() {
    assert_transform_compliance(async {
        let original_event = Event::Log(LogEvent::from("function transform being tested"));

        let (topology, rx) = create_topology(original_event.clone(), TransformType::Function).await;
        topology.stop().await;

        let events = rx.await.expect("must get back event from rx");
        let mut events = events.into_events().collect::<Vec<_>>();
        assert_eq!(events.len(), 1);

        let event = events.remove(0);
        assert_eq!(original_event, event);
    })
    .await;
}

#[tokio::test]
async fn test_sync_transform_single_event() {
    assert_transform_compliance(async {
        let original_event = Event::Log(LogEvent::from("function transform being tested"));

        let (topology, rx) =
            create_topology(original_event.clone(), TransformType::Synchronous).await;
        topology.stop().await;

        let events = rx.await.expect("must get back event from rx");
        let mut events = events.into_events().collect::<Vec<_>>();
        assert_eq!(events.len(), 1);

        let event = events.remove(0);
        assert_eq!(original_event, event);
    })
    .await;
}

#[tokio::test]
async fn test_task_transform_single_event() {
    assert_transform_compliance(async {
        let original_event = Event::Log(LogEvent::from("function transform being tested"));

        let (topology, rx) = create_topology(original_event.clone(), TransformType::Task).await;
        topology.stop().await;

        let events = rx.await.expect("must get back event from rx");
        let mut events = events.into_events().collect::<Vec<_>>();
        assert_eq!(events.len(), 1);

        let event = events.remove(0);
        assert_eq!(original_event, event);
    })
    .await;
}
