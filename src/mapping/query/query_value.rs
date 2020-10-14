use super::dynamic_regex::DynamicRegex;
use crate::event::Value;

#[derive(PartialEq, Debug, Clone)]
pub(in crate::mapping) enum QueryValue {
    Value(Value),

    #[allow(dead_code)]
    Regex(DynamicRegex),
}

impl QueryValue {
    pub(in crate::mapping) fn from_value<T: Into<Value>>(value: T) -> Self {
        From::from(value.into())
    }

    pub fn kind(&self) -> &str {
        match self {
            QueryValue::Value(value) => value.kind(),
            QueryValue::Regex(_) => "regex",
        }
    }
}

impl From<Value> for QueryValue {
    fn from(value: Value) -> Self {
        Self::Value(value)
    }
}

impl From<DynamicRegex> for QueryValue {
    fn from(value: DynamicRegex) -> Self {
        Self::Regex(value)
    }
}

impl From<QueryValue> for Value {
    fn from(value: QueryValue) -> Self {
        use QueryValue::*;

        match value {
            Value(v) => v,
            Regex(_r) => unimplemented!(), // r.into(),
        }
    }
}
