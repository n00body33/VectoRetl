use crate::config::SinkDescription;

mod config;
mod encoding;
mod healthcheck;
mod model;
mod service;
mod sink;

pub use config::*;
pub use encoding::*;
pub(crate) use model::*;
pub use service::*;
pub use sink::*;

pub(crate) use super::{Healthcheck, VectorSink};

#[cfg(test)]
pub(crate) mod tests;

inventory::submit! {
    SinkDescription::new::<NewRelicConfig>("new_relic")
}
