use metrics::counter;
use vector_core::internal_event::InternalEvent;

#[derive(Debug)]
pub struct DatadogAgentRequestReceived {
    pub byte_size: usize,
    pub count: usize,
}

impl InternalEvent for DatadogAgentRequestReceived {
    fn emit_logs(&self) {
        debug!(message = "Received requests.", count = ?self.count);
    }

    fn emit_metrics(&self) {
        counter!("events_in_total", self.count as u64,);
        counter!("processed_bytes_total", self.byte_size as u64,);
    }
}

#[derive(Debug)]
pub struct DatadogAgentTraceDecoded {
    pub byte_size: usize,
    pub count: usize,
}

impl InternalEvent for DatadogAgentTraceDecoded {
    fn emit_logs(&self) {
        debug!(message = "Decoded traces.", count = ?self.count);
    }

    fn emit_metrics(&self) {
        counter!("decoded_traces_in_total", self.count as u64,);
        counter!("decoded_traces_bytes_total", self.byte_size as u64,);
    }
}

#[derive(Debug)]
pub struct DatadogAgentLogDecoded {
    pub byte_size: usize,
    pub count: usize,
}

impl InternalEvent for DatadogAgentLogDecoded {
    fn emit_logs(&self) {
        debug!(message = "Decoded logs.", count = ?self.count);
    }

    fn emit_metrics(&self) {
        counter!("decoded_logs_in_total", self.count as u64,);
        counter!("decoded_logs_bytes_total", self.byte_size as u64,);
    }
}
