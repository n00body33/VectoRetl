use vector_config::configurable_component;

use crate::{
    conditions::{Condition, Conditional, ConditionalConfig},
    event::Event,
};

/// A condition that asserts whether or not an event is a log.
#[configurable_component]
#[derive(Clone, Debug, Default)]
pub(crate) struct IsLogConfig {}

impl_generate_config_from_default!(IsLogConfig);

impl ConditionalConfig for IsLogConfig {
    fn build(&self, _enrichment_tables: &enrichment::TableRegistry) -> crate::Result<Condition> {
        Ok(Condition::is_log())
    }
}

#[derive(Debug, Clone)]
pub struct IsLog {}

impl Conditional for IsLog {
    fn check(&self, e: Event) -> (bool, Event) {
        (matches!(e, Event::Log(_)), e)
    }

    fn check_with_context(&self, e: Event) -> (Result<(), String>, Event) {
        let (result, event) = self.check(e);
        if result {
            (Ok(()), event)
        } else {
            (Err("event is not a log type".to_string()), event)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::event::{
        metric::{Metric, MetricKind, MetricValue},
        Event,
    };

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<IsLogConfig>();
    }

    #[test]
    fn is_log_basic() {
        let cond = IsLogConfig {}.build(&Default::default()).unwrap();

        assert!(cond.check(Event::from("just a log")).0);
        assert!(
            !cond
                .check(Event::from(Metric::new(
                    "test metric",
                    MetricKind::Incremental,
                    MetricValue::Counter { value: 1.0 },
                )))
                .0,
        );
    }
}
