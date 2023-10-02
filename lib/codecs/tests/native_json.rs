use bytes::BytesMut;
use codecs::decoding::format::Deserializer;
use codecs::encoding::format::Serializer;
use codecs::{NativeJsonDeserializerConfig, NativeJsonSerializerConfig};
use vector_core::buckets;
use vector_core::config::LogNamespace;
use vector_core::event::{Event, Metric};
use vector_core::event::{MetricKind, MetricValue};

fn assert_roundtrip(
    input_event: Event,
    serializer: &mut dyn Serializer<Error = vector_common::Error>,
    deserializer: &dyn Deserializer,
) {
    let mut bytes_mut = BytesMut::new();
    serializer
        .encode(input_event.clone(), &mut bytes_mut)
        .unwrap();
    let bytes = bytes_mut.freeze();
    let events = deserializer.parse(bytes, LogNamespace::Vector).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0], input_event);

    let json_value = serde_json::to_value(input_event.as_metric()).unwrap();
    assert_eq!(json_value, expected_json_value);
}

#[test]
fn histogram_metric_roundtrip() {
    let histogram_event = Event::from(Metric::new(
        "histogram",
        MetricKind::Absolute,
        MetricValue::AggregatedHistogram {
            count: 1,
            sum: 1.0,
            buckets: buckets!(f64::NEG_INFINITY => 0 ,2.0 => 1, f64::INFINITY => 0),
        },
    ));

    let expected_json_value = serde_json::from_str(
        r#"
        {
            "aggregated_histogram":  {
                "buckets": [
                     {
                        "count": 0,
                        "upper_limit": -1.7976931348623157e308
                    },
                     {
                        "count": 1,
                        "upper_limit": 2.0
                    },
                     {
                        "count": 0,
                        "upper_limit": 1.7976931348623157e308
                    }
                ],
                "count": 1,
                "sum": 1.0
            },
            "kind": "absolute",
            "name": "histogram"
        }"#,
    )
    .unwrap();

    assert_roundtrip(
        histogram_event,
        &mut NativeJsonSerializerConfig.build(),
        &NativeJsonDeserializerConfig::default().build(),
    )
}
