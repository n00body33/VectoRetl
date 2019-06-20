use crate::event::ValueKind;
use chrono::{DateTime, TimeZone, Utc};
use std::str::FromStr;

/// `Conversion` is a place-holder for a type conversion operation, to
/// convert from a plain (`String`) `ValueKind` into another type. Every
/// variant of `ValueKind` is represented here.
#[derive(Clone)]
pub enum Conversion {
    String,
    Integer,
    Float,
    Boolean,
    Timestamp,
    TimestampFmt(String),
    TimestampTZFmt(String),
}

impl FromStr for Conversion {
    type Err = String;
    /// Convert the string into a type conversion. The following
    /// conversion names are supported:
    ///
    ///  * `"string"` => As-is (null)
    ///  * `"int"` or `"integer"` => Signed integer
    ///  * `"float"` => Floating point number
    ///  * `"bool"` or `"boolean"` => Boolean
    ///  * `"timestamp"` => Timestamp, guessed using a set of formats
    ///  * `"timestamp|FORMAT"` => Timestamp using the given format
    ///
    /// Timestamp parsing does not yet support time zones.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "string" => Ok(Conversion::String),
            "integer" | "int" => Ok(Conversion::Integer),
            "float" => Ok(Conversion::Float),
            "bool" | "boolean" => Ok(Conversion::Boolean),
            "timestamp" => Ok(Conversion::Timestamp),
            _ if s.starts_with("timestamp|") => {
                let fmt = &s[10..];
                // DateTime<Utc> can only convert timestamps without
                // time zones, and DateTime<FixedOffset> can only
                // convert with tone zones, so this has to distinguish
                // between the two types of formats.
                if format_has_zone(fmt) {
                    Ok(Conversion::TimestampTZFmt(fmt.into()))
                } else {
                    Ok(Conversion::TimestampFmt(fmt.into()))
                }
            }
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
    /// `value` is not currently a `ValueKind::Bytes`.
    pub fn convert(&self, value: ValueKind) -> Result<ValueKind, String> {
        let value = value.into_bytes();
        match self {
            Conversion::String => Ok(value.into()),
            Conversion::Integer => parse_simple!(value, i64, "integer", Integer),
            Conversion::Float => parse_simple!(value, f64, "floating point number", Float),
            Conversion::Boolean => parse_bool(&String::from_utf8_lossy(&value))
                .map_err(|err| format!("Invalid boolean {:?}: {}", value, err))
                .map(|value| ValueKind::Boolean(value)),
            Conversion::Timestamp => parse_timestamp(&String::from_utf8_lossy(&value))
                .map_err(|err| format!("Invalid timestamp {:?}: {}", value, err))
                .map(|value| ValueKind::Timestamp(value)),
            Conversion::TimestampFmt(format) => Utc
                .datetime_from_str(&String::from_utf8_lossy(&value), &format)
                .map_err(|err| format!("Invalid timestamp {:?}: {}", value, err))
                .map(|value| ValueKind::Timestamp(value)),
            Conversion::TimestampTZFmt(format) => {
                DateTime::parse_from_str(&String::from_utf8_lossy(&value), &format)
                    .map_err(|err| format!("Invalid timestamp {:?}: {}", value, err))
                    .map(|value| ValueKind::Timestamp(datetime_to_utc(value)))
            }
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

/// Does the format specifier have a time zone option?
fn format_has_zone(fmt: &str) -> bool {
    fmt.find("%Z").is_some()
        || fmt.find("%z").is_some()
        || fmt.find("%:z").is_some()
        || fmt.find("%#z").is_some()
        || fmt.find("%+").is_some()
}

/// Convert a timestamp with a non-UTC time zone into UTC
fn datetime_to_utc<TZ: TimeZone>(ts: DateTime<TZ>) -> DateTime<Utc> {
    Utc.timestamp(ts.timestamp(), ts.timestamp_subsec_nanos())
}

/// The list of allowed "automatic" timestamp formats
const TIMESTAMP_FORMATS: &[&str] = &[
    "%s",              // UNIX timestamp
    "%F %T",           // YYYY-MM-DD HH:MM:SS
    "%v %T",           // DD-Mmm-YYYY HH:MM:SS
    "%FT%TZ",          // ISO 8601 / RFC 3339
    "%FT%T",           // ISO 8601 / RFC 3339 without TZ UTC
    "%m/%d/%Y:%T",     // ???
    "%a, %d %b %Y %T", // RFC 822/2822 without TZ
    "%a %d %b %T %Y",  // `date` command output without TZ
    "%A %d %B %T %Y",  // `date` command output without TZ, long names
    "%a %b %e %T %Y",  // ctime format
];

/// The list of allowed "automatic" timestamp formats with time zones
const TIMESTAMP_TZ_FORMATS: &[&str] = &[
    "%+",                 // ISO 8601 / RFC 3339
    "%a %d %b %T %Z %Y",  // `date` command output
    "%a %d %b %T %z %Y",  // `date` command output, numeric TZ
    "%a %d %b %T %#z %Y", // `date` command output, numeric TZ
];

/// Parse a string into a timestamp using one of a set of formats
fn parse_timestamp(s: &str) -> Result<DateTime<Utc>, &'static str> {
    for format in TIMESTAMP_FORMATS {
        if let Ok(result) = Utc.datetime_from_str(s, format) {
            return Ok(result);
        }
    }
    if let Ok(result) = DateTime::parse_from_rfc3339(s) {
        return Ok(datetime_to_utc(result));
    }
    if let Ok(result) = DateTime::parse_from_rfc2822(s) {
        return Ok(datetime_to_utc(result));
    }
    for format in TIMESTAMP_TZ_FORMATS {
        if let Ok(result) = DateTime::parse_from_str(s, format) {
            return Ok(datetime_to_utc(result));
        }
    }
    Err("No matching timestamp format found")
}

#[cfg(test)]
mod tests {
    use super::{parse_bool, parse_timestamp, Conversion};
    use crate::event::ValueKind;
    use chrono::prelude::*;

    fn dateref() -> DateTime<Utc> {
        Utc.from_utc_datetime(&NaiveDateTime::from_timestamp(981173106, 0))
    }

    fn convert(fmt: &str, value: &str) -> Result<ValueKind, String> {
        fmt.parse::<Conversion>()
            .expect(&format!("Invalid conversion {:?}", fmt))
            .convert(value.into())
    }

    #[test]
    fn timestamp_conversion() {
        assert_eq!(
            convert("timestamp", "02/03/2001:04:05:06"),
            Ok(dateref().into())
        );
    }

    #[test]
    fn timestamp_param_conversion() {
        assert_eq!(
            convert("timestamp|%Y-%m-%d %H:%M:%S", "2001-02-03 04:05:06"),
            Ok(dateref().into())
        );
    }

    #[test]
    fn parse_timestamp_auto() {
        assert_eq!(parse_timestamp("2001-02-03 04:05:06"), Ok(dateref()));
        assert_eq!(parse_timestamp("02/03/2001:04:05:06"), Ok(dateref()));
        assert_eq!(parse_timestamp("2001-02-03T04:05:06"), Ok(dateref()));
        assert_eq!(parse_timestamp("2001-02-03T04:05:06Z"), Ok(dateref()));
        assert_eq!(parse_timestamp("Sat, 3 Feb 2001 04:05:06"), Ok(dateref()));
        assert_eq!(parse_timestamp("Sat Feb 3 04:05:06 2001"), Ok(dateref()));
        assert_eq!(parse_timestamp("3-Feb-2001 04:05:06"), Ok(dateref()));
        assert_eq!(parse_timestamp("2001-02-02T22:05:06-06:00"), Ok(dateref()));
        assert_eq!(
            parse_timestamp("Sat, 03 Feb 2001 07:05:06 +0300"),
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
