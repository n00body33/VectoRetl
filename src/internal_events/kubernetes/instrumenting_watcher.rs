// ## skip check-events ##

use std::fmt::Debug;

use metrics::counter;
use vector_core::internal_event::InternalEvent;

#[derive(Debug)]
pub(crate) struct WatchRequestInvoked;

impl InternalEvent for WatchRequestInvoked {
    fn emit_metrics(&self) {
        counter!("k8s_watch_requests_invoked_total", 1);
    }
}

#[derive(Debug)]
pub(crate) struct WatchRequestInvocationFailed<E> {
    pub error: E,
}

impl<E: Debug> InternalEvent for WatchRequestInvocationFailed<E> {
    fn emit_logs(&self) {
        error!(message = "Watch invocation failed.", error = ?self.error, internal_log_rate_secs = 5);
    }

    fn emit_metrics(&self) {
        counter!("k8s_watch_requests_failed_total", 1);
    }
}

#[derive(Debug)]
pub(crate) struct WatchStreamFailed<E> {
    pub(crate) error: E,
}

impl<E: Debug> InternalEvent for WatchStreamFailed<E> {
    fn emit_logs(&self) {
        error!(message = "Watch stream failed.", error = ?self.error, internal_log_rate_secs = 5);
    }

    fn emit_metrics(&self) {
        counter!("k8s_watch_stream_failed_total", 1);
    }
}

#[derive(Debug)]
pub(crate) struct WatchStreamItemObtained;

impl InternalEvent for WatchStreamItemObtained {
    fn emit_metrics(&self) {
        counter!("k8s_watch_stream_items_obtained_total", 1);
    }
}
