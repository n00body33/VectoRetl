use super::InternalEvent;
use metrics::counter;

#[derive(Debug)]
pub struct AggregateEventRecorded;

impl InternalEvent for AggregateEventRecorded {
    fn emit_metrics(&self) {
        counter!("aggregate_events_recorded_total", 1);
    }
}

#[derive(Debug)]
pub struct AggregateFlushed;

impl InternalEvent for AggregateFlushed {
    fn emit_metrics(&self) {
        counter!("aggregate_flushes_total", 1);
    }
}
