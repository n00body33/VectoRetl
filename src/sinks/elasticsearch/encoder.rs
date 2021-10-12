use crate::sinks::util::encoding::{Encoder, LogEncoder};
use crate::event::{Event, LogEvent};
use std::io::Write;
use crate::transforms::metric_to_log::MetricToLog;
use crate::sinks::elasticsearch::{ElasticSearchCommonMode, maybe_set_id};
use serde_json::json;
use count_write::CountWrite;
use serde::{Serialize, Deserialize};
use crate::internal_events::ElasticSearchEventEncoded;
use vector_core::event::EventRef;
use crate::sinks::elasticsearch::request_builder::ProcessedEvent;

// pub struct LogEncoding<T> {
//     metric_to_log: MetricToLog,
//     log_encoder: T
// }

pub struct ElasticSearchEncoder{

}

impl Encoder<Vec<ProcessedEvent>> for ElasticSearchEncoder {
    fn encode_input(&self, input: Vec<ProcessedEvent>, writer: &mut dyn Write) -> std::io::Result<usize> {
        todo!()
    }
}

// pub struct ElasticSearchEncoder {
//     encoding: Encoding,
//     mode: ElasticSearchCommonMode,
//     id_key: Option<String>,
//     doc_type: String,
// }
//
// impl Encoder for ElasticSearchEncoder {
//     fn encode_event(&self, mut event: Event, writer: &mut dyn Write) -> std::io::Result<()> {
//         //TODO: make sure this is a Log
//
//         //TODO: take care of this error
//         let index = self.mode.index(&event).unwrap();
//
//         if let Some(cfg) = self.mode.as_data_stream_config() {
//             cfg.sync_fields(event.as_mut_log());
//             cfg.remap_timestamp(event.as_mut_log());
//         };
//
//         //TODO: take care of this error
//         let bulk_action = self.mode.bulk_action(event).unwrap();
//
//         let mut action = json!({
//             bulk_action.as_str(): {
//                 "_index": index,
//                 "_type": self.doc_type,
//             }
//         });
//
//         maybe_set_id(
//             self.id_key.as_ref(),
//             action.pointer_mut(bulk_action.as_json_pointer()).unwrap(),
//             &mut log,
//         );
//
//         let mut writer = CountWrite::from(writer);
//
//         serde_json::to_writer(&mut writer, &action)?;
//         writer.write_all(&[b'\n'])?;
//
//         //TODO: make sure this is taken care of
//         // self.encoding.apply_rules(&mut event);
//
//         serde_json::to_writer(&mut writer, &event.into_log())?;
//         writer.write_all(&[b'\n'])?;
//
//         emit!(&ElasticSearchEventEncoded {
//             byte_size: writer.count() as usize,
//             index,
//         });
//
//         Ok(())
//     }
// }
