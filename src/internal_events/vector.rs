// ## skip check-events ##

use super::prelude::{error_stage, error_type};
use metrics::counter;
use prost::DecodeError;
use vector_core::internal_event::InternalEvent;

#[derive(Debug)]
pub struct VectorEventReceived {
    pub(crate) byte_size: usize,
}

impl InternalEvent for VectorEventReceived {
    fn emit_logs(&self) {
        trace!(
            message = "Events received.",
            count = 1,
            byte_size = self.byte_size
        );
    }

    fn emit_metrics(&self) {
        counter!("component_received_events_total", 1);
        counter!(
            "component_received_event_bytes_total",
            self.byte_size as u64
        );
        // deprecated
        counter!("events_in_total", 1);
        counter!("processed_bytes_total", self.byte_size as u64);
    }
}

#[derive(Debug)]
pub(crate) struct VectorProtoDecodeError<'a> {
    pub(crate) error: &'a DecodeError,
}

impl<'a> InternalEvent for VectorProtoDecodeError<'a> {
    fn emit_logs(&self) {
        error!(
            message = "Failed to decode protobuf message.",
            error = ?self.error,
            error_type = error_type::PARSER_FAILED,
            stage = error_stage::PROCESSING,
        );
    }

    fn emit_metrics(&self) {
        counter!(
            "component_errors_total", 1,
            "error" => self.error.to_string(),
            "error_type" => error_type::PARSER_FAILED,
            "stage" => error_stage::PROCESSING,
        );
        // decoding
        counter!("protobuf_decode_errors_total", 1);
    }
}
