//! `GreptimeDB` log sink for vector.
//!
//! This sink writes Vector's log data into
//! [GreptimeDB](https://github.com/greptimeteam/greptimedb), a cloud-native
//! time-series database. It uses GreptimeDB's logs http API

mod config;
mod http_request_builder;
mod sink;
#[cfg(all(test, feature = "greptimedb-logs-integration-tests"))]
mod integration_tests;
