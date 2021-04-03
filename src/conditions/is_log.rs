use crate::{
    conditions::{Condition, ConditionConfig, ConditionDescription},
    Event,
};
use serde::{Deserialize, Serialize};
use structures::str::immutable::ImStr;

//------------------------------------------------------------------------------

#[derive(Deserialize, Serialize, Debug, Default, Clone)]
pub struct IsLogConfig {}

inventory::submit! {
    ConditionDescription::new::<IsLogConfig>("is_log")
}

impl_generate_config_from_default!(IsLogConfig);

#[typetag::serde(name = "is_log")]
impl ConditionConfig for IsLogConfig {
    fn build(&self) -> crate::Result<Box<dyn Condition>> {
        Ok(Box::new(IsLog {}))
    }
}

//------------------------------------------------------------------------------

#[derive(Clone)]
pub struct IsLog {}

impl Condition for IsLog {
    fn check(&self, e: &Event) -> bool {
        matches!(e, Event::Log(_))
    }

    fn check_with_context(&self, e: &Event) -> Result<(), ImStr> {
        if self.check(e) {
            Ok(())
        } else {
            Err("event is not a log type".into())
        }
    }
}

//------------------------------------------------------------------------------

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        event::metric::{Metric, MetricKind, MetricValue},
        Event,
    };

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<IsLogConfig>();
    }

    #[test]
    fn is_log_basic() {
        let cond = IsLogConfig {}.build().unwrap();

        assert_eq!(cond.check(&Event::from("just a log")), true);
        assert_eq!(
            cond.check(&Event::from(Metric::new(
                "test metric",
                MetricKind::Incremental,
                MetricValue::Counter { value: 1.0 },
            ))),
            false
        );
    }
}
