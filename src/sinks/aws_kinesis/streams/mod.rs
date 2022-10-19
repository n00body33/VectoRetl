mod config;
mod integration_tests;
mod record;

use aws_sdk_kinesis::{error::PutRecordsError, model::PutRecordsRequestEntry, Client};

pub use super::{
    record::{Record, SendRecord},
    request_builder,
    service::{KinesisResponse, KinesisService},
    sink,
};

pub use self::config::KinesisSinkConfig;

pub type KinesisError = PutRecordsError;
pub type KinesisRecord = PutRecordsRequestEntry;
pub type KinesisClient = Client;
