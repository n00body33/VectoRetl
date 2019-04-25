#![allow(clippy::new_without_default, clippy::needless_pass_by_value)]

#[macro_use]
extern crate tokio_trace;

#[macro_use]
extern crate prost_derive;

pub mod buffers;
pub mod metrics;
pub mod record;
pub mod sinks;
pub mod sources;
pub mod test_util;
pub mod topology;
pub mod transforms;

pub use crate::record::Record;
