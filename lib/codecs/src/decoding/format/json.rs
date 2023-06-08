use std::convert::TryInto;

use bytes::Bytes;
use chrono::Utc;
use derivative::Derivative;
use lookup::PathPrefix;
use serde::{Deserialize, Serialize};
use smallvec::{smallvec, SmallVec};
use vector_config::configurable_component;
use vector_core::{
    config::{log_schema, DataType, LogNamespace},
    event::Event,
    schema,
};
use vrl::value::Kind;

use super::Deserializer;

/// Config used to build a `JsonDeserializer`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct JsonDeserializerConfig {
    #[serde(
        default,
        skip_serializing_if = "vector_core::serde::skip_serializing_if_default"
    )]
    /// Options for the JSON deserializer.
    pub json: JsonDeserializerOptions,
}

/// JSON-specific decoding options.
#[configurable_component]
#[derive(Debug, Clone, PartialEq, Eq, Derivative)]
#[derivative(Default)]
pub struct JsonDeserializerOptions {
    /// Determines whether or not to replace invalid UTF-8 sequences instead of returning an error.
    ///
    /// When true, invalid UTF-8 sequences are replaced with the [`U+FFFD REPLACEMENT CHARACTER`][U+FFFD].
    ///
    /// [U+FFFD]: https://en.wikipedia.org/wiki/Specials_(Unicode_block)#Replacement_character
    #[serde(
        default = "default_lossy",
        skip_serializing_if = "vector_core::serde::skip_serializing_if_default"
    )]
    #[derivative(Default(value = "default_lossy()"))]
    lossy: bool,
}

fn default_lossy() -> bool {
    true
}

impl JsonDeserializerConfig {
    /// Build the `JsonDeserializer` from this configuration.
    pub fn build(&self) -> JsonDeserializer {
        Into::<JsonDeserializer>::into(self)
    }

    /// Return the type of event build by this deserializer.
    pub fn output_type(&self) -> DataType {
        DataType::Log
    }

    /// The schema produced by the deserializer.
    pub fn schema_definition(&self, log_namespace: LogNamespace) -> schema::Definition {
        match log_namespace {
            LogNamespace::Legacy => {
                let mut definition =
                    schema::Definition::empty_legacy_namespace().unknown_fields(Kind::json());

                if let Some(timestamp_key) = log_schema().timestamp_key() {
                    definition = definition.try_with_field(
                        timestamp_key,
                        // The JSON decoder will try to insert a new `timestamp`-type value into the
                        // "timestamp_key" field, but only if that field doesn't already exist.
                        Kind::json().or_timestamp(),
                        Some("timestamp"),
                    );
                }
                definition
            }
            LogNamespace::Vector => {
                schema::Definition::new_with_default_metadata(Kind::json(), [log_namespace])
            }
        }
    }
}

impl JsonDeserializerConfig {
    /// Creates a new `JsonDeserializerConfig`.
    pub fn new() -> Self {
        Default::default()
    }

    /// Creates a new `JsonDeserializerConfig` with the given options.
    pub fn new_with_options(options: JsonDeserializerOptions) -> Self {
        Self { json: options }
    }
}

/// Deserializer that builds `Event`s from a byte frame containing JSON.
#[derive(Debug, Clone, Derivative)]
#[derivative(Default)]
pub struct JsonDeserializer {
    #[derivative(Default(value = "default_lossy()"))]
    lossy: bool,
}

impl JsonDeserializer {
    /// Creates a new `JsonDeserializer`.
    pub fn new() -> Self {
        Default::default()
    }

    /// Creates a new `JsonDeserializer` with the given lossy option.
    pub fn new_with_lossy(lossy: bool) -> Self {
        Self { lossy }
    }
}

impl Deserializer for JsonDeserializer {
    fn parse(
        &self,
        bytes: Bytes,
        log_namespace: LogNamespace,
    ) -> vector_common::Result<SmallVec<[Event; 1]>> {
        // It's common to receive empty frames when parsing NDJSON, since it
        // allows multiple empty newlines. We proceed without a warning here.
        if bytes.is_empty() {
            return Ok(smallvec![]);
        }

        let json: serde_json::Value = match self.lossy {
            true => serde_json::from_str(&String::from_utf8_lossy(&bytes)),
            false => serde_json::from_slice(&bytes),
        }
        .map_err(|error| format!("Error parsing JSON: {:?}", error))?;

        // If the root is an Array, split it into multiple events
        let mut events = match json {
            serde_json::Value::Array(values) => values
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<SmallVec<[Event; 1]>, _>>()?,
            _ => smallvec![json.try_into()?],
        };

        let events = match log_namespace {
            LogNamespace::Vector => events,
            LogNamespace::Legacy => {
                let timestamp = Utc::now();

                if let Some(timestamp_key) = log_schema().timestamp_key() {
                    for event in &mut events {
                        let log = event.as_mut_log();
                        if !log.contains((PathPrefix::Event, timestamp_key)) {
                            log.insert((PathPrefix::Event, timestamp_key), timestamp);
                        }
                    }
                }

                events
            }
        };

        Ok(events)
    }
}

impl From<&JsonDeserializerConfig> for JsonDeserializer {
    fn from(config: &JsonDeserializerConfig) -> Self {
        Self {
            lossy: config.json.lossy,
        }
    }
}

#[cfg(test)]
mod tests {
    use vector_core::config::log_schema;

    use super::*;

    #[test]
    fn deserialize_json() {
        let input = Bytes::from(r#"{ "foo": 123 }"#);
        let deserializer = JsonDeserializer::new();

        for namespace in [LogNamespace::Legacy, LogNamespace::Vector] {
            let events = deserializer.parse(input.clone(), namespace).unwrap();
            let mut events = events.into_iter();

            {
                let event = events.next().unwrap();
                let log = event.as_log();
                assert_eq!(log["foo"], 123.into());
                assert_eq!(
                    log.get((
                        lookup::PathPrefix::Event,
                        log_schema().timestamp_key().unwrap()
                    ))
                    .is_some(),
                    namespace == LogNamespace::Legacy
                );
            }

            assert_eq!(events.next(), None);
        }
    }

    #[test]
    fn deserialize_json_array() {
        let input = Bytes::from(r#"[{ "foo": 123 }, { "bar": 456 }]"#);
        let deserializer = JsonDeserializer::new();
        for namespace in [LogNamespace::Legacy, LogNamespace::Vector] {
            let events = deserializer.parse(input.clone(), namespace).unwrap();
            let mut events = events.into_iter();

            {
                let event = events.next().unwrap();
                let log = event.as_log();
                assert_eq!(log["foo"], 123.into());
                assert_eq!(
                    log.get((
                        lookup::PathPrefix::Event,
                        log_schema().timestamp_key().unwrap()
                    ))
                    .is_some(),
                    namespace == LogNamespace::Legacy
                );
            }

            {
                let event = events.next().unwrap();
                let log = event.as_log();
                assert_eq!(log["bar"], 456.into());
                assert_eq!(
                    log.get((PathPrefix::Event, log_schema().timestamp_key().unwrap()))
                        .is_some(),
                    namespace == LogNamespace::Legacy
                );
            }

            assert_eq!(events.next(), None);
        }
    }

    #[test]
    fn deserialize_skip_empty() {
        let input = Bytes::from("");
        let deserializer = JsonDeserializer::new();

        for namespace in [LogNamespace::Legacy, LogNamespace::Vector] {
            let events = deserializer.parse(input.clone(), namespace).unwrap();
            assert!(events.is_empty());
        }
    }

    #[test]
    fn deserialize_error_invalid_json() {
        let input = Bytes::from("{ foo");
        let deserializer = JsonDeserializer::new();

        for namespace in [LogNamespace::Legacy, LogNamespace::Vector] {
            assert!(deserializer.parse(input.clone(), namespace).is_err());
        }
    }

    #[test]
    fn deserialize_lossy_replace_invalid_utf8() {
        let input = Bytes::from(b"{ \"foo\": \"Hello \xF0\x90\x80World\" }".as_slice());
        let deserializer = JsonDeserializer::new();

        for namespace in [LogNamespace::Legacy, LogNamespace::Vector] {
            let events = deserializer.parse(input.clone(), namespace).unwrap();
            let mut events = events.into_iter();

            {
                let event = events.next().unwrap();
                let log = event.as_log();
                assert_eq!(log["foo"], b"Hello \xEF\xBF\xBDWorld".into());
                assert_eq!(
                    log.get((
                        lookup::PathPrefix::Event,
                        log_schema().timestamp_key().unwrap()
                    ))
                    .is_some(),
                    namespace == LogNamespace::Legacy
                );
            }

            assert_eq!(events.next(), None);
        }
    }

    #[test]
    fn deserialize_non_lossy_error_invalid_utf8() {
        let input = Bytes::from(b"{ \"foo\": \"Hello \xF0\x90\x80World\" }".as_slice());
        let deserializer = JsonDeserializer::new_with_lossy(false);

        for namespace in [LogNamespace::Legacy, LogNamespace::Vector] {
            assert!(deserializer.parse(input.clone(), namespace).is_err());
        }
    }
}
