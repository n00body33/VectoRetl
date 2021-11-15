use super::expander::ExpanderConfig;
use crate::conditions::{not::NotConfig, AnyCondition};
use crate::config::{DataType, ExpandType, TransformConfig, TransformContext};
use crate::transforms::filter::FilterConfig;
use crate::transforms::Transform;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// This transform is made to do the following trick
///
/// ```
///                                 +--> filter (if condition) --> ..transforms --+
/// event -- (expand in parallel) --+                                             +--> next pipe
///                                 +--> filter (if !condition) ------------------+
/// ```

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BypassConfig {
    condition: AnyCondition,
    inner: Box<dyn TransformConfig>,
}

impl BypassConfig {
    pub fn new(condition: AnyCondition, inner: Box<dyn TransformConfig>) -> Self {
        Self { condition, inner }
    }

    fn truthy_path(&self) -> Box<dyn TransformConfig> {
        let mut result: IndexMap<String, Box<dyn TransformConfig>> = IndexMap::new();
        result.insert(
            "filter".to_string(),
            Box::new(FilterConfig::from(self.condition.clone())),
        );
        result.insert("transforms".to_string(), self.inner.clone());
        Box::new(ExpanderConfig::serial(result))
    }

    fn falsy_path(&self) -> Box<dyn TransformConfig> {
        Box::new(FilterConfig::from(AnyCondition::Map(Box::new(
            NotConfig::from(self.condition.clone()),
        ))))
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "pipeline_bypass")]
impl TransformConfig for BypassConfig {
    async fn build(&self, _context: &TransformContext) -> crate::Result<Transform> {
        Err("this transform must be expanded".into())
    }

    fn expand(
        &mut self,
    ) -> crate::Result<Option<(IndexMap<String, Box<dyn TransformConfig>>, ExpandType)>> {
        let mut result = IndexMap::new();
        result.insert("truthy".to_string(), self.truthy_path());
        result.insert("falsy".to_string(), self.falsy_path());
        Ok(Some((result, ExpandType::Parallel { aggregates: true })))
    }

    fn input_type(&self) -> DataType {
        DataType::Any
    }

    fn output_type(&self) -> DataType {
        DataType::Any
    }

    fn transform_type(&self) -> &'static str {
        "pipeline_bypass"
    }
}
