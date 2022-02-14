mod arithmetic;
mod convert;
mod error;
pub mod kind;
mod r#macro;
// mod path;
// mod regex;
mod serde;
mod target;





pub use error::VrlValueError;
pub use kind::{Collection, Field, Index, Kind};


pub use self::arithmetic::VrlValueArithmetic;
pub use self::convert::VrlValueConvert;
pub use self::kind::VrlValueKind;

//TODO: maybe get rid of this?
pub use value::Value;

//
// #[cfg(test)]
// mod test {
//     use bytes::Bytes;
//     use chrono::DateTime;
//     use indoc::indoc;
//     use ordered_float::NotNan;
//     use regex::Regex;
//     use vector_common::btreemap;
//
//     use super::Value;
//
//     #[test]
//     fn test_display_string() {
//         assert_eq!(
//             Value::Bytes(Bytes::from("Hello, world!")).to_string(),
//             r#""Hello, world!""#
//         );
//     }
//
//     #[test]
//     fn test_display_string_with_backslashes() {
//         assert_eq!(
//             Value::Bytes(Bytes::from(r#"foo \ bar \ baz"#)).to_string(),
//             r#""foo \\ bar \\ baz""#
//         );
//     }
//
//     #[test]
//     fn test_display_string_with_quotes() {
//         assert_eq!(
//             Value::Bytes(Bytes::from(r#""Hello, world!""#)).to_string(),
//             r#""\"Hello, world!\"""#
//         );
//     }
//
//     #[test]
//     fn test_display_string_with_newlines() {
//         assert_eq!(
//             Value::Bytes(Bytes::from(indoc! {"
//                 Some
//                 new
//                 lines
//             "}))
//             .to_string(),
//             r#""Some\nnew\nlines\n""#
//         );
//     }
//
//     #[test]
//     fn test_display_integer() {
//         assert_eq!(Value::Integer(123).to_string(), "123");
//     }
//
//     #[test]
//     fn test_display_float() {
//         assert_eq!(
//             Value::Float(NotNan::new(123.45).unwrap()).to_string(),
//             "123.45"
//         );
//     }
//
//     #[test]
//     fn test_display_boolean() {
//         assert_eq!(Value::Boolean(true).to_string(), "true");
//     }
//
//     #[test]
//     fn test_display_object() {
//         assert_eq!(
//             Value::Object(btreemap! {
//                 "foo" => "bar"
//             })
//             .to_string(),
//             r#"{ "foo": "bar" }"#
//         );
//     }
//
//     #[test]
//     fn test_display_array() {
//         assert_eq!(
//             Value::Array(
//                 vec!["foo", "bar"]
//                     .into_iter()
//                     .map(std::convert::Into::into)
//                     .collect()
//             )
//             .to_string(),
//             r#"["foo", "bar"]"#
//         );
//     }
//
//     #[test]
//     fn test_display_timestamp() {
//         assert_eq!(
//             Value::Timestamp(
//                 DateTime::parse_from_rfc3339("2000-10-10T20:55:36Z")
//                     .unwrap()
//                     .into()
//             )
//             .to_string(),
//             "t'2000-10-10T20:55:36Z'"
//         );
//     }
//
//     #[test]
//     fn test_display_regex() {
//         assert_eq!(
//             Value::Regex(Regex::new(".*").unwrap().into()).to_string(),
//             "r'.*'"
//         );
//     }
//
//     #[test]
//     fn test_display_null() {
//         assert_eq!(Value::Null.to_string(), "null");
//     }
// }
