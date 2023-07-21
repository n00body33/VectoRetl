use std::{collections::HashMap, fmt::Write};

use crate::encoding::BuildError;
use bytes::BytesMut;
use chrono::SecondsFormat;
use lookup::lookup_v2::ConfigTargetPath;
use tokio_util::codec::Encoder;
use vector_core::{
    config::DataType,
    event::{Event, LogEvent, Value},
    schema,
};

/// Device event identity.
#[derive(Debug, Clone)]
pub struct DeviceSettings {
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub event_class_id: String,
}

impl DeviceSettings {
    /// Creates a new `DeviceSettings`.
    pub const fn new(
        vendor: String,
        product: String,
        version: String,
        event_class_id: String,
    ) -> Self {
        Self {
            vendor,
            product,
            version,
            event_class_id,
        }
    }
}

/// Config used to build a `CefSerializer`.
#[crate::configurable_component]
#[derive(Debug, Clone)]
pub struct CefSerializerConfig {
    /// The CEF Serializer Options.
    pub cef: CefSerializerOptions,
}

impl CefSerializerConfig {
    /// Creates a new `CefSerializerConfig`.
    pub const fn new(cef: CefSerializerOptions) -> Self {
        Self { cef }
    }

    /// Build the `CefSerializer` from this configuration.
    pub fn build(&self) -> Result<CefSerializer, BuildError> {
        let device_vendor = if let Some(device_vendor) = self.cef.device_vendor.clone() {
            escape_header(device_vendor)
        } else {
            String::from("Datadog")
        };
        if device_vendor.len() > 63 {
            return Err(format!(
                "device_vendor exceed 63 characters limit: actual {}",
                device_vendor.len()
            )
            .into());
        };

        let device_product = if let Some(device_product) = self.cef.device_product.clone() {
            escape_header(device_product)
        } else {
            String::from("Vector")
        };
        if device_product.len() > 63 {
            return Err(format!(
                "device_product exceed 63 characters limit: actual {}",
                device_product.len()
            )
            .into());
        };

        let device_version = if let Some(device_version) = self.cef.device_version.clone() {
            device_version
        } else {
            String::from("0") // Major version. TODO(nabokihms): find a way to get the actual vector version.
        };
        if device_version.len() > 31 {
            return Err(format!(
                "device_version exceed 31 characters limit: actual {}",
                device_version.len()
            )
            .into());
        };

        let device_event_class_id =
            if let Some(device_event_class_id) = self.cef.device_event_class_id.clone() {
                escape_header(device_event_class_id)
            } else {
                String::from("Telemetry Event")
            };
        if device_event_class_id.len() > 1023 {
            return Err(format!(
                "device_event_class_id exceed 1023 characters limit: actual {}",
                device_event_class_id.len()
            )
            .into());
        };

        for key in self.cef.extensions.keys() {
            if !key.chars().all(|c| c.is_ascii_alphabetic()) {
                // TODO (nabokihms): Output all invalid keys
                return Err(format!("extension keys can only contain ascii alphabetical characters: invalid key '{}'", key).into());
            }
        }

        let device = DeviceSettings::new(
            device_vendor,
            device_product,
            device_version,
            device_event_class_id,
        );

        Ok(CefSerializer::new(
            self.cef.version.clone(),
            device,
            self.cef.severity.clone(),
            self.cef.name.clone(),
            self.cef.extensions.clone(),
        ))
    }

    /// The data type of events that are accepted by `CefSerializer`.
    pub fn input_type(&self) -> DataType {
        DataType::Log
    }

    /// The schema required by the serializer.
    pub fn schema_requirement(&self) -> schema::Requirement {
        // While technically we support `Value` variants that can't be losslessly serialized to
        // CEF, we don't want to enforce that limitation to users yet.
        schema::Requirement::empty()
    }
}

/// CEF version.
#[crate::configurable_component]
#[derive(Debug, Default, Clone)]
pub enum Version {
    #[default]
    /// CEF specification version 0.1.
    V0,
    /// CEF specification version 1.x.
    V1,
}

impl Version {
    fn as_str(&self) -> &'static str {
        match self {
            Version::V0 => "0",
            Version::V1 => "1",
        }
    }
}

/// Config used to build a `CefSerializer`.
#[crate::configurable_component]
#[derive(Debug, Clone)]
pub struct CefSerializerOptions {
    /// CEF Version. Can be either 0 or 1.
    /// Equals to "0" by default.
    pub version: Version,

    /// Identifies the vendor of the product.
    /// The part of a unique device identifier. No two products can use the same pair of devide vendor and device product combination.
    /// The value length must be lower or equal to 63.
    pub device_vendor: Option<String>,

    /// Identifies the product of a vendor.
    /// The part of a unique device identifier. No two products can use the same pair of devide vendor and device product combination.
    /// The value length must be lower or equal to 63.
    pub device_product: Option<String>,

    /// Identifies the version of the problem. In combination with device product and vendor, it composes the unique id of device that sends messages.
    /// The value length must be lower or equal to 31.
    pub device_version: Option<String>,

    /// Unique identifier for each event-type. Identifies the type of event reported.
    /// The value length must be lower or equal to 1023.
    pub device_event_class_id: Option<String>,

    /// This is a path that points to filed of a log event that reflects importance of the event.
    /// Reflects importance of the event.
    ///
    /// It must point to a number from 0 to 10.
    /// 0 = Lowest, 10 = Highest.
    /// Equals to "cef.severity" by default.
    pub severity: ConfigTargetPath,

    /// This is a path that points to the human-readable description of a log event.
    /// The value length must be lower or equal to 512.
    /// Equals to "cef.name" by default.
    pub name: ConfigTargetPath,

    /// The collection fo key-value pairs. Keys are the keys of the extensions, and values are path that point to the extension values of a log event.
    /// The event can have any number of key-value pairs in any order.
    #[configurable(metadata(
        docs::additional_props_description = "This is a path that points to the extension value of a log event."
    ))]
    pub extensions: HashMap<String, ConfigTargetPath>,
    // TODO(nabokihms): use Template instead of ConfigTargetPath.
    // Templates are in the src/ package, and codes are in the lib/codecs.
}

impl Default for CefSerializerOptions {
    fn default() -> Self {
        Self {
            version: Version::default(),
            device_vendor: None,
            device_product: None,
            device_version: None,
            device_event_class_id: None,
            severity: ConfigTargetPath::try_from("cef.severity".to_string()).unwrap(),
            name: ConfigTargetPath::try_from("cef.name".to_string()).unwrap(),
            extensions: HashMap::new(),
        }
    }
}

/// Serializer that converts an `Event` to bytes using the CEF format.
/// CEF:<version>|<device_vendor>|<device_product>|<device_version>|<device_event_class>|<name>|<severity>|<encoded_fields>
#[derive(Debug, Clone)]
pub struct CefSerializer {
    version: Version,
    device: DeviceSettings,
    severity: ConfigTargetPath,
    name: ConfigTargetPath,
    extensions: HashMap<String, ConfigTargetPath>,
}

impl CefSerializer {
    /// Creates a new `CefSerializer`.
    pub const fn new(
        version: Version,
        device: DeviceSettings,
        severity: ConfigTargetPath,
        name: ConfigTargetPath,
        extensions: HashMap<String, ConfigTargetPath>,
    ) -> Self {
        Self {
            version,
            device,
            severity,
            name,
            extensions,
        }
    }
}

impl Encoder<Event> for CefSerializer {
    type Error = vector_common::Error;

    fn encode(&mut self, event: Event, buffer: &mut BytesMut) -> Result<(), Self::Error> {
        let log = event.into_log();

        let severity: u8 = match get_log_event_value(&log, &self.severity).parse() {
            Err(err) => {
                return Err(format!("severity must be a number: {}", err).into());
            }
            Ok(severity) => {
                if severity > 10 {
                    return Err(format!(
                        "severity must be a number from 0 to 10: actual {}",
                        severity
                    )
                    .into());
                };
                severity
            }
        };

        let name: String = escape_header(get_log_event_value(&log, &self.name));
        if name.len() > 512 {
            return Err(format!("name exceed 512 characters limit: actual {}", name.len()).into());
        };

        let mut formatted_extensions = Vec::new();
        for (extension, field) in &self.extensions {
            let value = get_log_event_value(&log, field);
            if value.is_empty() {
                continue;
            }
            let value = escape_extension(value);
            formatted_extensions.push(format!("{}={}", extension, value));
        }

        buffer.write_fmt(format_args!(
            "CEF:{}|{}|{}|{}|{}|{}|{}",
            &self.version.as_str(),
            &self.device.vendor,
            &self.device.product,
            &self.device.version,
            &self.device.event_class_id,
            severity,
            name,
        ))?;
        if !formatted_extensions.is_empty() {
            formatted_extensions.sort();

            buffer.write_char('|')?;
            buffer.write_str(formatted_extensions.join(" ").as_str())?;
        }

        Ok(())
    }
}

fn get_log_event_value(log: &LogEvent, field: &ConfigTargetPath) -> String {
    match log.get(field) {
        Some(Value::Bytes(bytes)) => String::from_utf8_lossy(bytes).to_string(),
        Some(Value::Integer(int)) => int.to_string(),
        Some(Value::Float(float)) => float.to_string(),
        Some(Value::Boolean(bool)) => bool.to_string(),
        // TODO(nabokihms): support other timestamp options.
        Some(Value::Timestamp(timestamp)) => timestamp.to_rfc3339_opts(SecondsFormat::AutoSi, true),
        Some(Value::Null) => String::from(""),
        // Other value types: Array, Regex, Object are not supported by the CEF format.
        Some(_) => String::from(""),
        None => String::from(""),
    }
}

fn escape_header(mut s: String) -> String {
    s = s.replace('\\', r#"\\"#);
    s = s.replace('|', r#"\|"#);
    String::from_utf8_lossy(s.as_bytes()).to_string()
}

fn escape_extension(mut s: String) -> String {
    s = s.replace('\\', r#"\\"#);
    s = s.replace('=', r#"\="#);
    String::from_utf8_lossy(s.as_bytes()).to_string()
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use chrono::DateTime;
    use ordered_float::NotNan;
    use vector_common::btreemap;
    use vector_core::event::{Event, LogEvent, Value};

    use super::*;

    #[test]
    fn build_error_on_invalid_extension() {
        let extensions = HashMap::from([(
            String::from("foo.test"),
            ConfigTargetPath::try_from("foo".to_string()).unwrap(),
        )]);
        let opts: CefSerializerOptions = CefSerializerOptions {
            extensions,
            ..CefSerializerOptions::default()
        };
        let config = CefSerializerConfig::new(opts);
        let err = config.build().unwrap_err();
        assert_eq!(
            err.to_string(),
            "extension keys can only contain ascii alphabetical characters: invalid key 'foo.test'"
        );
    }

    #[test]
    fn try_escape_header() {
        let s1 = String::from(r#"Test | test"#);
        let s2 = String::from(r#"Test \ test"#);
        let s3 = String::from(r#"Test test"#);
        let s4 = String::from(r#"Test \| \| test"#);

        let s1 = escape_header(s1);
        let s2 = escape_header(s2);
        let s3: String = escape_header(s3);
        let s4: String = escape_header(s4);

        assert_eq!(s1, r#"Test \| test"#);
        assert_eq!(s2, r#"Test \\ test"#);
        assert_eq!(s3, r#"Test test"#);
        assert_eq!(s4, r#"Test \\\| \\\| test"#);
    }

    #[test]
    fn try_escape_extension() {
        let s1 = String::from(r#"Test=test"#);
        let s2 = String::from(r#"Test = test"#);
        let s3 = String::from(r#"Test test"#);
        let s4 = String::from(r#"Test \| \| test"#);

        let s1 = escape_extension(s1);
        let s2 = escape_extension(s2);
        let s3: String = escape_extension(s3);
        let s4: String = escape_extension(s4);

        assert_eq!(s1, r#"Test\=test"#);
        assert_eq!(s2, r#"Test \= test"#);
        assert_eq!(s3, r#"Test test"#);
        assert_eq!(s4, r#"Test \\| \\| test"#);
    }

    // TODO(nabokihms): more tests for edge cases.

    #[test]
    fn serialize_extensions() {
        let event = Event::Log(LogEvent::from(btreemap! {
            "cef" => Value::from(btreemap! {
                "severity" => Value::from(1),
                "name" => Value::from("Event name"),
            }),
            "foo" => Value::from("bar"),
            "int" => Value::from(123),
            "comma" => Value::from("abc,bcd"),
            "float" => Value::Float(NotNan::new(3.1415925).unwrap()),
            "space" => Value::from("sp ace"),
            "time" => Value::Timestamp(DateTime::parse_from_rfc3339("2023-02-27T15:04:49.363+08:00").unwrap().into()),
            "quote" => Value::from("the \"quote\" should be escaped"),
            "bool" => Value::from(true),
            "other" => Value::from("data"),
        }));

        let extensions = HashMap::from([
            (
                String::from("foo"),
                ConfigTargetPath::try_from("foo".to_string()).unwrap(),
            ),
            (
                String::from("int"),
                ConfigTargetPath::try_from("int".to_string()).unwrap(),
            ),
            (
                String::from("comma"),
                ConfigTargetPath::try_from("comma".to_string()).unwrap(),
            ),
            (
                String::from("float"),
                ConfigTargetPath::try_from("float".to_string()).unwrap(),
            ),
            (
                String::from("missing"),
                ConfigTargetPath::try_from("missing".to_string()).unwrap(),
            ),
            (
                String::from("space"),
                ConfigTargetPath::try_from("space".to_string()).unwrap(),
            ),
            (
                String::from("time"),
                ConfigTargetPath::try_from("time".to_string()).unwrap(),
            ),
            (
                String::from("quote"),
                ConfigTargetPath::try_from("quote".to_string()).unwrap(),
            ),
            (
                String::from("bool"),
                ConfigTargetPath::try_from("bool".to_string()).unwrap(),
            ),
        ]);

        let opts: CefSerializerOptions = CefSerializerOptions {
            extensions,
            ..CefSerializerOptions::default()
        };

        let config = CefSerializerConfig::new(opts);
        let mut serializer = config.build().unwrap();
        let mut bytes = BytesMut::new();

        serializer.encode(event, &mut bytes).unwrap();

        assert_eq!(
            bytes.freeze(),
            b"CEF:0|Datadog|Vector|0|Telemetry Event|1|Event name|bool=true comma=abc,bcd float=3.1415925 foo=bar int=123 quote=the \"quote\" should be escaped space=sp ace time=2023-02-27T07:04:49.363Z".as_slice()
        );
    }
}
