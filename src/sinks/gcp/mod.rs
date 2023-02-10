use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use vector_config::configurable_component;

pub mod chronicle_unstructured;
pub mod cloud_storage;
pub mod pubsub;
pub mod stackdriver_logs;
pub mod stackdriver_metrics;

/// A monitored resource.
///
/// Monitored resources in GCP allow associating logs and metrics specifically with native resources
/// within Google Cloud Platform. This takes the form of a "type" field which identifies the
/// resource, and a set of type-specific labels to uniquely identify a resource of that type.
///
/// See [Monitored resource types][mon_docs] for more information.
///
/// [mon_docs]: https://cloud.google.com/monitoring/api/resources
#[configurable_component]
#[derive(Clone, Debug, Default)]
pub struct GcpTypedResource {
    /// The monitored resource type.
    ///
    /// For example, the type of a Compute Engine VM instance is `gce_instance`.
    #[configurable(metadata(docs::examples = "global", docs::examples = "gce_instance"))]
    pub r#type: String,

    /// Type-specific labels.
    #[serde(flatten)]
    #[configurable(metadata(
        docs::additional_props_description = "Values for all of the labels listed in the associated monitored resource descriptor.\n\nFor example, Compute Engine VM instances use the labels `projectId`, `instanceId`, and `zone`."
    ))]
    #[configurable(metadata(docs::examples = "label_examples()"))]
    pub labels: HashMap<String, String>,
}

fn label_examples() -> HashMap<String, String> {
    let mut example = HashMap::new();
    example.insert("type".to_string(), "global".to_string());
    example.insert("projectId".to_string(), "vector-123456".to_string());
    example.insert("instanceId".to_string(), "Twilight".to_string());
    example.insert("zone".to_string(), "us-central1-a".to_string());

    example
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
#[serde(rename_all = "UPPERCASE")]
pub enum GcpMetricKind {
    Cumulative,
    Gauge,
}

#[derive(Serialize, Debug, Clone, Copy)]
#[serde(rename_all = "UPPERCASE")]
pub enum GcpValueType {
    Int64,
}

#[derive(Serialize, Debug, Clone, Copy)]
pub struct GcpPoint {
    pub interval: GcpInterval,
    pub value: GcpPointValue,
}

#[derive(Serialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub struct GcpInterval {
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_datetime"
    )]
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(serialize_with = "serialize_datetime")]
    pub end_time: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub struct GcpPointValue {
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_int64_value"
    )]
    pub int64_value: Option<i64>,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GcpMetric {
    pub r#type: String,
    pub labels: HashMap<String, String>,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GcpResource {
    pub r#type: String,
    pub labels: HashMap<String, String>,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GcpSerie<'a> {
    pub metric: GcpMetric,
    pub resource: GcpResource,
    pub metric_kind: GcpMetricKind,
    pub value_type: GcpValueType,
    pub points: &'a [GcpPoint],
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GcpSeries<'a> {
    time_series: &'a [GcpSerie<'a>],
}

fn serialize_int64_value<S>(value: &Option<i64>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(value.as_ref().expect("always defined").to_string().as_str())
}

fn serialize_datetime<S>(
    value: &chrono::DateTime<chrono::Utc>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(
        value
            .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
            .as_str(),
    )
}

fn serialize_optional_datetime<S>(
    value: &Option<chrono::DateTime<chrono::Utc>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serialize_datetime(value.as_ref().expect("always defined"), serializer)
}
