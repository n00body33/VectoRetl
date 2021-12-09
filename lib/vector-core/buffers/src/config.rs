use crate::{
    topology::{
        builder::TopologyBuilder,
        channel::{BufferReceiver, BufferSender},
    },
    Acker, Bufferable, DiskV1Buffer, DiskV2Buffer, MemoryV2Buffer, WhenFull,
};
use serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, path::PathBuf};
use tracing::Span;

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum BufferTypeKind {
    Memory,
    #[serde(rename = "disk")]
    DiskV1,
    #[serde(rename = "disk_v2")]
    DiskV2,
}

const ALL_FIELDS: [&str; 4] = ["type", "max_events", "max_size", "when_full"];

struct BufferTypeVisitor;

impl BufferTypeVisitor {
    fn visit_map_impl<'de, A>(mut map: A) -> Result<BufferType, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut kind: Option<BufferTypeKind> = None;
        let mut max_events: Option<usize> = None;
        let mut max_size: Option<usize> = None;
        let mut when_full: Option<WhenFull> = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "type" => {
                    if kind.is_some() {
                        return Err(de::Error::duplicate_field("type"));
                    }
                    kind = Some(map.next_value()?);
                }
                "max_events" => {
                    if max_events.is_some() {
                        return Err(de::Error::duplicate_field("max_events"));
                    }
                    max_events = Some(map.next_value()?);
                }
                "max_size" => {
                    if max_size.is_some() {
                        return Err(de::Error::duplicate_field("max_size"));
                    }
                    max_size = Some(map.next_value()?);
                }
                "when_full" => {
                    if when_full.is_some() {
                        return Err(de::Error::duplicate_field("when_full"));
                    }
                    when_full = Some(map.next_value()?);
                }
                other => {
                    return Err(de::Error::unknown_field(other, &ALL_FIELDS));
                }
            }
        }
        let kind = kind.unwrap_or(BufferTypeKind::Memory);
        let when_full = when_full.unwrap_or_default();
        match kind {
            BufferTypeKind::Memory => {
                if max_size.is_some() {
                    return Err(de::Error::unknown_field(
                        "max_size",
                        &["type", "max_events", "when_full"],
                    ));
                }
                Ok(BufferType::Memory {
                    max_events: max_events.unwrap_or_else(memory_buffer_default_max_events),
                    when_full,
                })
            }
            BufferTypeKind::DiskV1 => {
                if max_events.is_some() {
                    return Err(de::Error::unknown_field(
                        "max_events",
                        &["type", "max_size", "when_full"],
                    ));
                }
                Ok(BufferType::DiskV1 {
                    max_size: max_size.ok_or_else(|| de::Error::missing_field("max_size"))?,
                    when_full,
                })
            }
            BufferTypeKind::DiskV2 => {
                if max_events.is_some() {
                    return Err(de::Error::unknown_field(
                        "max_events",
                        &["type", "max_size", "when_full"],
                    ));
                }
                Ok(BufferType::DiskV2 {
                    max_size: max_size.ok_or_else(|| de::Error::missing_field("max_size"))?,
                    when_full,
                })
            }
        }
    }
}

impl<'de> de::Visitor<'de> for BufferTypeVisitor {
    type Value = BufferType;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("enum BufferType")
    }

    fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        BufferTypeVisitor::visit_map_impl(map)
    }
}

impl<'de> Deserialize<'de> for BufferType {
    fn deserialize<D>(deserializer: D) -> Result<BufferType, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(BufferTypeVisitor)
    }
}

struct BufferConfigVisitor;

impl<'de> de::Visitor<'de> for BufferConfigVisitor {
    type Value = BufferConfig;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("enum BufferType")
    }

    fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let stage = BufferTypeVisitor::visit_map_impl(map)?;
        Ok(BufferConfig {
            stages: vec![stage],
        })
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut stages = Vec::new();
        while let Some(stage) = seq.next_element()? {
            stages.push(stage);
        }
        Ok(BufferConfig { stages })
    }
}

impl<'de> Deserialize<'de> for BufferConfig {
    fn deserialize<D>(deserializer: D) -> Result<BufferConfig, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(BufferConfigVisitor)
    }
}

impl Serialize for BufferConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.stages.len() {
            0 => Err(ser::Error::custom(
                "buffer config cannot be empty when serializing",
            )),
            1 => self.stages.first().unwrap().serialize(serializer),
            _ => self.stages.serialize(serializer),
        }
    }
}

const fn memory_buffer_default_max_events() -> usize {
    500
}

/// A specific type of buffer stage.
#[derive(Copy, Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum BufferType {
    /// A buffer stage backed by an in-memory channel.
    Memory {
        #[serde(default = "memory_buffer_default_max_events")]
        max_events: usize,
        #[serde(default)]
        when_full: WhenFull,
    },
    /// A buffer stage backed by an on-disk database, powered by LevelDB.
    DiskV1 {
        max_size: usize,
        #[serde(default)]
        when_full: WhenFull,
    },
    /// A buffer stage backed by disk.
    DiskV2 {
        max_size: usize,
        #[serde(default)]
        when_full: WhenFull,
    },
}

impl BufferType {
    fn add_to_builder<T>(&self, builder: &mut TopologyBuilder<T>, data_dir: PathBuf, id: String)
    where
        T: Bufferable + Clone,
    {
        match *self {
            BufferType::Memory {
                when_full,
                max_events,
            } => {
                builder.stage(MemoryV2Buffer::new(max_events), when_full);
            }
            BufferType::DiskV1 {
                when_full,
                max_size,
            } => {
                builder.stage(DiskV1Buffer::new(id, data_dir, max_size), when_full);
            }
            BufferType::DiskV2 {
                when_full,
                max_size,
            } => {
                builder.stage(DiskV2Buffer::new(id, data_dir, max_size), when_full);
            }
        }
    }
}

/// A buffer configuration.
///
/// Buffers are compromised of stages(*) that form a buffer _topology_, with input items being
/// subject to configurable behavior when each stage reaches configured limits.  Buffers are
/// configured for sinks, where backpressure from the sink can be handled by the buffer.  This
/// allows absorbing temporary load, or potentially adding write-ahead-log behavior to a sink to
/// increase the durability of a given Vector pipeline.
///
/// While we use the term "buffer topology" here, a buffer topology is referred to by the more
/// common "buffer" or "buffers" shorthand.  This is related to buffers originally being a single
/// component, where you could only choose which buffer type to use.  As we expand buffer
/// functionality to allow chaining buffers together, you'll see "buffer topology" used in internal
/// documentation to correctly reflect the internal structure.
#[derive(Clone, Debug, PartialEq)]
pub struct BufferConfig {
    stages: Vec<BufferType>,
}

impl Default for BufferConfig {
    fn default() -> Self {
        Self {
            stages: vec![BufferType::Memory {
                max_events: memory_buffer_default_max_events(),
                when_full: WhenFull::default(),
            }],
        }
    }
}

impl BufferConfig {
    /// Gets all of the configured stages for this buffer.
    pub fn stages(&self) -> &[BufferType] {
        &self.stages
    }

    /// Builds the buffer components represented by this configuration.
    ///
    /// The caller gets back a `Sink` and `Stream` implementation that represent a way to push items
    /// into the buffer, as well as pop items out of the buffer, respectively.  The `Acker` is
    /// provided to callers in order to update the buffer when popped items have been processed and
    /// can be dropped or deleted, depending on the underlying buffer implementation.
    ///
    /// # Errors
    ///
    /// If the buffer is configured with anything other than a single stage, an error variant will
    /// be thrown.
    ///
    /// If a disk buffer stage is configured and the data directory provided is `None`, an error
    /// variant will be thrown.
    #[allow(clippy::needless_pass_by_value)]
    pub async fn build<T>(
        &self,
        data_dir: PathBuf,
        buffer_id: String,
        span: Span,
    ) -> Result<(BufferSender<T>, BufferReceiver<T>, Acker), String>
    where
        T: Bufferable + Clone,
    {
        let mut builder = TopologyBuilder::new();

        for stage in self.stages.iter().cloned() {
            stage.add_to_builder(&mut builder, data_dir.clone(), buffer_id.clone());
        }

        builder
            .build(span)
            .await
            .map_err(|e| format!("error while building buffer topology: {}", e))
    }
}

#[cfg(test)]
mod test {
    use crate::{BufferConfig, BufferType, WhenFull};

    fn check_single_stage(source: &str, expected: BufferType) {
        let config: BufferConfig = serde_yaml::from_str(source).unwrap();
        assert_eq!(config.stages.len(), 1);
        let actual = config.stages.first().unwrap();
        assert_eq!(actual, &expected);
    }

    fn check_multiple_stages(source: &str, expected_stages: &[BufferType]) {
        let config: BufferConfig = serde_yaml::from_str(source).unwrap();
        assert_eq!(config.stages.len(), expected_stages.len());
        for (actual, expected) in config.stages().iter().zip(expected_stages) {
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn parse_empty() {
        let source = "";
        let error = serde_yaml::from_str::<BufferConfig>(source).unwrap_err();
        assert_eq!(error.to_string(), "EOF while parsing a value");
    }

    #[test]
    fn parse_only_invalid_keys() {
        let source = "foo: 314";
        let error = serde_yaml::from_str::<BufferConfig>(source).unwrap_err();
        assert_eq!(
            error.to_string(),
            "unknown field `foo`, expected one of `type`, `max_events`, `max_size`, `when_full` at line 1 column 4"
        );
    }

    #[test]
    fn parse_partial_invalid_keys() {
        let source = r#"max_size: 100
max_events: 42
"#;
        let error = serde_yaml::from_str::<BufferConfig>(source).unwrap_err();
        assert_eq!(
            error.to_string(),
            "unknown field `max_size`, expected one of `type`, `max_events`, `when_full` at line 1 column 9"
        );
    }

    #[test]
    fn parse_without_type_tag() {
        check_single_stage(
            r#"
          max_events: 100
          "#,
            BufferType::Memory {
                max_events: 100,
                when_full: WhenFull::Block,
            },
        );
    }

    #[test]
    fn parse_multiple_stages() {
        check_multiple_stages(
            r#"
          - max_events: 42
          - max_events: 100
            when_full: drop_newest
          "#,
            &[
                BufferType::Memory {
                    max_events: 42,
                    when_full: WhenFull::Block,
                },
                BufferType::Memory {
                    max_events: 100,
                    when_full: WhenFull::DropNewest,
                },
            ],
        );
    }

    #[test]
    fn ensure_field_defaults_for_all_types() {
        check_single_stage(
            r#"
          type: memory
          "#,
            BufferType::Memory {
                max_events: 500,
                when_full: WhenFull::Block,
            },
        );

        check_single_stage(
            r#"
          type: memory
          max_events: 100
          "#,
            BufferType::Memory {
                max_events: 100,
                when_full: WhenFull::Block,
            },
        );

        check_single_stage(
            r#"
          type: memory
          when_full: drop_newest
          "#,
            BufferType::Memory {
                max_events: 500,
                when_full: WhenFull::DropNewest,
            },
        );

        check_single_stage(
            r#"
          type: disk
          max_size: 1024
          "#,
            BufferType::DiskV1 {
                max_size: 1024,
                when_full: WhenFull::Block,
            },
        );
    }
}
