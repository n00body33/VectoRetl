#![deny(missing_docs)]

use super::{EncodingConfiguration, TimestampFormat};
use crate::{
    codecs::encoding::{Framer, FramingConfig, Serializer, SerializerConfig},
    event::{Event, PathComponent},
};
use core::fmt::Debug;
use serde::{Deserialize, Serialize};

/// Trait used to migrate from a sink-specific `Codec` enum to the new
/// `Box<dyn FramingConfig>`/`Box<dyn SerializerConfig>` encoding configuration.
pub trait EncodingConfigMigrator {
    /// The sink-specific encoding type to be migrated.
    type Codec;

    /// Returns the framing/serializer configuration that is functionally equivalent to the given
    /// legacy codec.
    fn migrate(
        codec: &Self::Codec,
    ) -> (
        Option<Box<dyn FramingConfig>>,
        Option<Box<dyn SerializerConfig>>,
    );
}

/// This adapter serves to migrate sinks from the old sink-specific `EncodingConfig<T>` to the new
/// `Box<dyn FramingConfig>`/`Box<dyn SerializerConfig>` encoding configuration - while keeping
/// backwards-compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EncodingConfigAdapter<
    LegacyEncodingConfig: EncodingConfiguration + Debug + Clone + 'static,
    Migrator: EncodingConfigMigrator<Codec = <LegacyEncodingConfig as EncodingConfiguration>::Codec>
        + Debug
        + Clone,
> {
    /// The encoding configuration.
    Encoding(EncodingConfig),
    /// The legacy sink-specific encoding configuration.
    LegacyEncodingConfig(LegacyEncodingConfigWrapper<LegacyEncodingConfig>, Migrator),
}

impl<
        LegacyEncodingConfig: EncodingConfiguration + Debug + Clone + 'static,
        Migrator: EncodingConfigMigrator<Codec = <LegacyEncodingConfig as EncodingConfiguration>::Codec>
            + Debug
            + Clone,
    > EncodingConfigAdapter<LegacyEncodingConfig, Migrator>
{
    /// Create a new encoding configuration.
    pub fn new(
        framing: Option<Box<dyn FramingConfig>>,
        encoding: Option<Box<dyn SerializerConfig>>,
    ) -> Self {
        Self::Encoding(EncodingConfig {
            framing,
            encoding: encoding.map(|encoding| EncodingWithTransformationConfig {
                encoding,
                filter: None,
                timestamp_format: None,
            }),
        })
    }

    /// Create a legacy sink-specific encoding configuration.
    pub fn legacy(encoding: LegacyEncodingConfig, migrator: Migrator) -> Self {
        Self::LegacyEncodingConfig(LegacyEncodingConfigWrapper { encoding }, migrator)
    }
}

impl<
        LegacyEncodingConfig: EncodingConfiguration + Debug + Clone,
        Migrator: EncodingConfigMigrator<Codec = <LegacyEncodingConfig as EncodingConfiguration>::Codec>
            + Debug
            + Clone,
    > EncodingConfigAdapter<LegacyEncodingConfig, Migrator>
{
    /// Build a `Transformer` that applies the encoding rules to an event before serialization.
    pub fn transformer(&self) -> Transformer {
        match self {
            Self::Encoding(config) => {
                let only_fields = config.encoding.as_ref().and_then(|encoding| {
                    encoding.filter.as_ref().and_then(|filter| match filter {
                        OnlyOrExceptFieldsConfig::OnlyFields(fields) => {
                            Some(fields.only_fields.clone())
                        }
                        _ => None,
                    })
                });
                let except_fields = config.encoding.as_ref().and_then(|encoding| {
                    encoding.filter.as_ref().and_then(|filter| match filter {
                        OnlyOrExceptFieldsConfig::ExceptFields(fields) => {
                            Some(fields.except_fields.clone())
                        }
                        _ => None,
                    })
                });
                let timestamp_format = config
                    .encoding
                    .as_ref()
                    .and_then(|encoding| encoding.timestamp_format);

                Transformer {
                    only_fields,
                    except_fields,
                    timestamp_format,
                }
            }
            Self::LegacyEncodingConfig(config, _) => Transformer {
                only_fields: config.encoding.only_fields().as_ref().map(|fields| {
                    fields
                        .iter()
                        .map(|field| {
                            field
                                .iter()
                                .map(|component| component.clone().into_static())
                                .collect()
                        })
                        .collect()
                }),
                except_fields: config.encoding.except_fields().clone(),
                timestamp_format: *config.encoding.timestamp_format(),
            },
        }
    }

    /// Build the framer and serializer for this configuration.
    pub fn encoding(
        &self,
    ) -> crate::Result<(Option<Box<dyn Framer>>, Option<Box<dyn Serializer>>)> {
        let (framer, serializer) = match self {
            Self::Encoding(config) => {
                let framer = match &config.framing {
                    Some(framing) => Some(framing.build()?),
                    None => None,
                };
                let serializer = match &config.encoding {
                    Some(encoding) => Some(encoding.encoding.build()?),
                    None => None,
                };

                (framer, serializer)
            }
            Self::LegacyEncodingConfig(config, _) => {
                let migration = Migrator::migrate(config.encoding.codec());
                let framer = match migration.0 {
                    Some(framing) => Some(framing.build()?),
                    None => None,
                };
                let serializer = match migration.1 {
                    Some(serializer) => Some(serializer.build()?),
                    None => None,
                };

                (framer, serializer)
            }
        };

        Ok((framer, serializer))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyEncodingConfigWrapper<EncodingConfig> {
    encoding: EncodingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodingConfig {
    framing: Option<Box<dyn FramingConfig>>,
    encoding: Option<EncodingWithTransformationConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodingWithTransformationConfig {
    #[serde(flatten)]
    encoding: Box<dyn SerializerConfig>,
    #[serde(flatten)]
    filter: Option<OnlyOrExceptFieldsConfig>,
    timestamp_format: Option<TimestampFormat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OnlyOrExceptFieldsConfig {
    OnlyFields(OnlyFieldsConfig),
    ExceptFields(ExceptFieldsConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnlyFieldsConfig {
    only_fields: Vec<Vec<PathComponent<'static>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptFieldsConfig {
    except_fields: Vec<String>,
}

pub struct Transformer {
    only_fields: Option<Vec<Vec<PathComponent<'static>>>>,
    except_fields: Option<Vec<String>>,
    timestamp_format: Option<TimestampFormat>,
}

impl Transformer {
    pub fn transform(&self, event: &mut Event) {
        self.apply_rules(event);
    }
}

impl EncodingConfiguration for Transformer {
    type Codec = ();

    fn codec(&self) -> &Self::Codec {
        &()
    }

    fn schema(&self) -> &Option<String> {
        &None
    }

    fn only_fields(&self) -> &Option<Vec<Vec<PathComponent>>> {
        &self.only_fields
    }

    fn except_fields(&self) -> &Option<Vec<String>> {
        &self.except_fields
    }

    fn timestamp_format(&self) -> &Option<TimestampFormat> {
        &self.timestamp_format
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_encoding_with_transformation() {
        let string = r#"
            {
                "encoding": {
                    "codec": "text",
                    "timestamp_format": "unix",
                    "except_fields": ["ignore_me"]
                }
            }
        "#;

        let config = serde_json::from_str::<EncodingConfig>(string).unwrap();
        let encoding = config.encoding.unwrap();

        assert_eq!(encoding.timestamp_format.unwrap(), TimestampFormat::Unix);
        assert_eq!(
            match encoding.filter.unwrap() {
                OnlyOrExceptFieldsConfig::ExceptFields(config) => config.except_fields,
                _ => panic!(),
            },
            vec!["ignore_me".to_owned()]
        );
    }
}
