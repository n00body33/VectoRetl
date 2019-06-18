use crate::event::ValueKind;
use chrono::{TimeZone, Utc};
use std::convert::TryFrom;

/// `Conversion` is a place-holder for a type conversion operation, to
/// convert from a plain (`String`) `ValueKind` into another type. Every
/// variant of `ValueKind` is represented here.
#[derive(Clone)]
pub enum Conversion {
    String,
    Integer,
    Float,
    Boolean,
    Timestamp(String),
}

impl TryFrom<&str> for Conversion {
    type Error = String;
    /// Convert the string into a type conversion. The following
    /// conversion names are supported:
    ///
    ///  * `"string"` => As-is (null)
    ///  * `"int"` or `"integer"` => Signed integer
    ///  * `"float"` => Floating point number
    ///  * `"bool"` or `"boolean"` => Boolean
    ///  * `"timestamp"` => Timestamp using the default format
    ///  * `"timestamp|FORMAT"` => Timestamp using the given format
    ///
    /// Timestamp parsing does not yet support time zones.
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "string" => Ok(Conversion::String),
            "integer" | "int" => Ok(Conversion::Integer),
            "float" => Ok(Conversion::Float),
            "bool" | "boolean" => Ok(Conversion::Boolean),
            "timestamp" => Ok(Conversion::Timestamp("%m/%d/%Y:%H:%M:%S".into())),
            _ if s.starts_with("timestamp|") => Ok(Conversion::Timestamp(s[10..].into())),
            _ => Err(format!("Invalid type conversion specifier: {:?}", s)),
        }
    }
}

macro_rules! parse_simple {
    ($value:expr, $ty:ty, $tyname:literal, $vtype:ident) => {
        String::from_utf8_lossy(&$value)
            .parse::<$ty>()
            .map_err(|err| format!("Invalid {} {:?}: {}", $tyname, $value, err))
            .map(|value| ValueKind::$vtype(value))
    };
}

impl Conversion {
    /// Use this `Conversion` variant to turn the given `value` into a
    /// new `ValueKind`. This will fail in unexpected ways if the
    /// `value` is not currently a `ValueKind::String`.
    pub fn convert(&self, value: ValueKind) -> Result<ValueKind, String> {
        let value = value.into_bytes();
        match self {
            Conversion::String => Ok(value.into()),
            Conversion::Integer => parse_simple!(value, i64, "integer", Integer),
            Conversion::Float => parse_simple!(value, f64, "floating point number", Float),
            Conversion::Boolean => parse_bool(&String::from_utf8_lossy(&value))
                .map_err(|err| format!("Invalid boolean {:?}: {}", value, err))
                .map(|value| ValueKind::Boolean(value)),
            Conversion::Timestamp(format) => Utc
                .datetime_from_str(&String::from_utf8_lossy(&value), &format)
                .map_err(|err| format!("Invalid timestamp {:?}: {}", value, err))
                .map(|value| ValueKind::Timestamp(value)),
        }
    }
}

/// Parse a string into a native `bool`. The built in `bool::from_str`
/// only handles two cases, `"true"` and `"false"`. We want to be able
/// to convert from a more diverse set of strings. In particular, the
/// following set of source strings are allowed:
///
///  * `"true"`, `"t"`, `"yes"`, `"y"` (all case-insensitive), and
///  non-zero integers all convert to `true`.
///
///  * `"false"`, `"f"`, `"no"`, `"n"` (all case-insensitive), and `"0"`
///  all convert to `false`.
///
/// Anything else results in a parse error.
fn parse_bool(s: &str) -> Result<bool, &'static str> {
    match s {
        "true" | "t" | "yes" | "y" => Ok(true),
        "false" | "f" | "no" | "n" | "0" => Ok(false),
        _ => {
            if let Ok(n) = s.parse::<isize>() {
                Ok(n != 0)
            } else {
                // Do the case conversion only if simple matches fail,
                // since this operation can be expensive.
                match s.to_lowercase().as_str() {
                    "true" | "t" | "yes" | "y" => Ok(true),
                    "false" | "f" | "no" | "n" => Ok(false),
                    _ => Err("Invalid boolean"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_bool, Conversion};
    use crate::event::ValueKind;
    use chrono::prelude::*;
    use std::convert::TryFrom;

    fn dateref() -> ValueKind {
        ValueKind::Timestamp(Utc.from_utc_datetime(&NaiveDateTime::from_timestamp(981173106, 0)))
    }

    fn convert(fmt: &str, value: &str) -> Result<ValueKind, String> {
        Conversion::try_from(fmt)
            .expect(&format!("Invalid conversion {:?}", fmt))
            .convert(value.into())
    }

    #[test]
    fn timestamp_conversion() {
        assert_eq!(convert("timestamp", "02/03/2001:04:05:06"), Ok(dateref()));
    }

    #[test]
    fn timestamp_param_conversion() {
        assert_eq!(
            convert("timestamp|%Y-%m-%d %H:%M:%S", "2001-02-03 04:05:06"),
            Ok(dateref())
        );
    }

    // These should perhaps each go into an individual test function to be
    // able to determine what part failed, but that would end up really
    // spamming the test logs.

    #[test]
    fn parse_bool_true() {
        assert_eq!(parse_bool("true"), Ok(true));
        assert_eq!(parse_bool("True"), Ok(true));
        assert_eq!(parse_bool("t"), Ok(true));
        assert_eq!(parse_bool("T"), Ok(true));
        assert_eq!(parse_bool("yes"), Ok(true));
        assert_eq!(parse_bool("YES"), Ok(true));
        assert_eq!(parse_bool("y"), Ok(true));
        assert_eq!(parse_bool("Y"), Ok(true));
        assert_eq!(parse_bool("1"), Ok(true));
        assert_eq!(parse_bool("23456"), Ok(true));
        assert_eq!(parse_bool("-8"), Ok(true));
    }

    #[test]
    fn parse_bool_false() {
        assert_eq!(parse_bool("false"), Ok(false));
        assert_eq!(parse_bool("fAlSE"), Ok(false));
        assert_eq!(parse_bool("f"), Ok(false));
        assert_eq!(parse_bool("F"), Ok(false));
        assert_eq!(parse_bool("no"), Ok(false));
        assert_eq!(parse_bool("NO"), Ok(false));
        assert_eq!(parse_bool("n"), Ok(false));
        assert_eq!(parse_bool("N"), Ok(false));
        assert_eq!(parse_bool("0"), Ok(false));
        assert_eq!(parse_bool("000"), Ok(false));
    }

    #[test]
    fn parse_bool_errors() {
        assert!(parse_bool("X").is_err());
        assert!(parse_bool("yes or no").is_err());
        assert!(parse_bool("123.4").is_err());
    }
}
