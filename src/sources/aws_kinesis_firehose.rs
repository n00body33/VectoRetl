use crate::{
    config::{log_schema, DataType, GlobalOptions, SinkDescription, SourceConfig},
    event::Event,
    internal_events::{AwsKinesisFirehoseRequestError, AwsKinesisFirehoseRequestReceived},
    shutdown::ShutdownSignal,
    sources::util::{ErrorMessage, HttpSource},
    tls::TlsConfig,
    Pipeline,
};
use async_trait::async_trait;
use bytes::{buf::BufExt, Bytes};
use chrono::serde::ts_milliseconds;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{error, fmt, io::Read, net::SocketAddr};
use warp::http::{HeaderMap, StatusCode};

// TODO:
// * Try to refactor reading encoded records to stream contents rather than copying into
//   intermediate buffers
// * Try avoiding intermediate collections while processing request
// * Return the response structure AWS expects
// * Allow control of setting AWS metadata fields from headers?
//   * Should fail if metadata fields cannot be set?
// * Move EncodingConfig into shared config
// * Handle additional codecs by reusing http source components

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AwsKinesisFirehoseConfig {
    address: SocketAddr,
    access_key: Option<String>,
    encoding: EncodingConfig<Encoding>,
    tls: Option<TlsConfig>,
}

inventory::submit! {
    SinkDescription::new_without_default::<AwsKinesisFirehoseConfig>("aws_kinesis_firehose")
}

#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
struct EncodingConfig<E> {
    codec: E,
}

#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
enum Encoding {
    Text,
    Ndjson,
    Json,
    AwsCloudWatchLogsSubscription,
}

#[derive(Clone)]
struct AwsKinesisFirehoseSource {
    access_key: Option<String>,
    encoding: EncodingConfig<Encoding>,
}

impl HttpSource for AwsKinesisFirehoseSource {
    fn build_event(&self, body: Bytes, header_map: HeaderMap) -> Result<Vec<Event>, ErrorMessage> {
        let request_id = get_header(&header_map, "X-Amz-Firehose-Request-Id")?;
        let source_arn = get_header(&header_map, "X-Amz-Firehose-Source-Arn")?;

        emit!(AwsKinesisFirehoseRequestReceived {
            request_id,
            source_arn,
        });

        validate_access_key(
            self.access_key.as_deref(),
            get_header(&header_map, "X-Amz-Firehose-Access-Key")?,
        )
        .map_err(|err| {
            let err = RequestError::AccessKey(err);
            emit!(AwsKinesisFirehoseRequestError {
                request_id,
                error: &err,
            });
            ErrorMessage::new(StatusCode::UNAUTHORIZED, err.to_string())
        })?;

        match get_header(&header_map, "X-Amz-Firehose-Protocol-Version")? {
            Some("1.0") => decode_message(body, request_id, source_arn, &self.encoding),
            Some(version) => {
                let error = RequestError::Protocol(ProtocolError::Invalid(version.to_string()));
                emit!(AwsKinesisFirehoseRequestError {
                    request_id,
                    error: &error
                });
                Err(ErrorMessage::new(
                    StatusCode::BAD_REQUEST,
                    error.to_string(),
                ))
            }
            None => {
                let error = RequestError::Protocol(ProtocolError::Missing);
                emit!(AwsKinesisFirehoseRequestError {
                    request_id,
                    error: &error
                });
                Err(ErrorMessage::new(
                    StatusCode::BAD_REQUEST,
                    error.to_string(),
                ))
            }
        }
    }
}

#[typetag::serde(name = "aws_kinesis_firehose")]
#[async_trait]
impl SourceConfig for AwsKinesisFirehoseConfig {
    fn build(
        &self,
        _name: &str,
        _globals: &GlobalOptions,
        _shutdown: ShutdownSignal,
        _out: Pipeline,
    ) -> crate::Result<super::Source> {
        unimplemented!()
    }

    async fn build_async(
        &self,
        _: &str,
        _: &GlobalOptions,
        shutdown: ShutdownSignal,
        out: Pipeline,
    ) -> crate::Result<super::Source> {
        let source = AwsKinesisFirehoseSource {
            access_key: self.access_key.clone(),
            encoding: self.encoding.clone(),
        };
        source.run(self.address, "", &self.tls, out, shutdown)
    }

    fn output_type(&self) -> DataType {
        DataType::Log
    }

    fn source_type(&self) -> &'static str {
        "aws_kinesis_firehose"
    }
}

#[derive(Clone, Debug)]
pub enum ProtocolError {
    Missing,
    Invalid(String),
}

#[derive(Clone, Debug)]
pub enum AccessKeyError {
    Missing,
    Invalid,
}

#[derive(Clone, Debug)]
pub enum RequestError {
    Protocol(ProtocolError),
    AccessKey(AccessKeyError),
    RequestParse(String),
    RecordDecode(usize, String),
    RecordParse(usize, String),
}

impl error::Error for RequestError {}
impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RequestError::AccessKey(AccessKeyError::Missing) => {
                write!(f, "X-Amz-Firehose-Access-Key header missing")
            }
            RequestError::AccessKey(AccessKeyError::Invalid) => write!(
                f,
                "X-Amz-Firehose-Access-Key header does not match configured access key"
            ),
            RequestError::Protocol(ProtocolError::Missing) => {
                write!(f, "X-Amz-Firehose-Protocol-Version header missing")
            }
            RequestError::Protocol(ProtocolError::Invalid(ref s)) => {
                write!(f, "Unsupported Firehose protocol version: {}", s)
            }
            RequestError::RequestParse(ref s) => {
                write!(f, "Could not parse Firehose request as JSON: {}", s)
            }
            RequestError::RecordDecode(ref i, ref s) => {
                write!(f, "Could not decode record with index {}: {}", i, s)
            }
            RequestError::RecordParse(ref i, ref s) => {
                write!(f, "Could not parse record with index {}: {}", i, s)
            }
        }
    }
}

/// if there is a configured access key, validate that the request key matches it
fn validate_access_key(
    access_key: Option<&str>,
    request_access_key: Option<&str>,
) -> Result<(), AccessKeyError> {
    match access_key {
        Some(access_key) => match request_access_key {
            Some(request_access_key) => {
                if request_access_key == access_key {
                    Ok(())
                } else {
                    Err(AccessKeyError::Invalid)
                }
            }
            None => Err(AccessKeyError::Missing),
        },
        None => Ok(()),
    }
}

fn decode_message(
    body: Bytes,
    request_id: Option<&str>,
    source_arn: Option<&str>,
    encoding: &EncodingConfig<Encoding>,
) -> Result<Vec<Event>, ErrorMessage> {
    let request: FirehoseRequest = serde_json::from_reader(body.reader()).map_err(|error| {
        let error = RequestError::RequestParse(error.to_string());
        emit!(AwsKinesisFirehoseRequestError {
            request_id,
            error: &error
        });
        ErrorMessage::new(StatusCode::BAD_REQUEST, error.to_string())
    })?;

    let records: Vec<Vec<u8>> = request
        .records
        .iter()
        .enumerate()
        .map(|(i, record)| {
            decode_record(record).map_err(|error| {
                let error = RequestError::RecordDecode(i, error.to_string());
                emit!(AwsKinesisFirehoseRequestError {
                    request_id,
                    error: &error
                });
                ErrorMessage::new(StatusCode::BAD_REQUEST, error.to_string())
            })
        })
        .collect::<Result<Vec<Vec<u8>>, ErrorMessage>>()?;

    let records: Vec<Event> = records
        .iter()
        .enumerate()
        .map(|(i, record)| {
            parse_record(record, encoding).map_err(|error| {
                let error = RequestError::RecordParse(i, error.to_string());
                emit!(AwsKinesisFirehoseRequestError {
                    request_id,
                    error: &error
                });
                ErrorMessage::new(StatusCode::BAD_REQUEST, error.to_string())
            })
        })
        .collect::<Result<Vec<Vec<Event>>, ErrorMessage>>()?
        .into_iter()
        .flatten()
        .map(|mut event| {
            let log = event.as_mut_log();
            if let Some(id) = request_id {
                log.insert("amz_request_id", id.to_owned());
            }
            if let Some(arn) = source_arn {
                log.insert("amz_source_arn", arn.to_owned());
            }
            event
        })
        .collect();

    Ok(records)
}

fn parse_record(
    record: &[u8],
    encoding: &EncodingConfig<Encoding>,
) -> Result<Vec<Event>, serde_json::error::Error> {
    match encoding.codec {
        Encoding::AwsCloudWatchLogsSubscription => {
            let record: AwsCloudWatchLogsSubscriptionMessage =
                serde_json::from_reader(record.reader())?;

            Ok(match record.message_type {
                AwsCloudWatchLogsSubscriptionMessageType::ControlMessage => vec![],
                AwsCloudWatchLogsSubscriptionMessageType::DataMessage => record
                    .log_events
                    .into_iter()
                    .map(|log_event| {
                        let mut event = Event::from(log_event.message.as_str());
                        let log = event.as_mut_log();
                        log.insert(log_schema().timestamp_key().clone(), log_event.timestamp);
                        event
                    })
                    .collect(),
            })
        }

        _ => unimplemented!("TODO"),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum AwsCloudWatchLogsSubscriptionMessageType {
    ControlMessage,
    DataMessage,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AwsCloudWatchLogsSubscriptionMessage {
    owner: String,
    message_type: AwsCloudWatchLogsSubscriptionMessageType,
    log_group: String,
    log_stream: String,
    subscription_filters: Vec<String>,
    log_events: Vec<AwsCloudWatchLogEvent>,
}

#[derive(Debug, Deserialize)]
struct AwsCloudWatchLogEvent {
    id: String,
    #[serde(with = "ts_milliseconds")]
    timestamp: DateTime<Utc>,
    message: String,
}

/// return the parsed header, if it exists
fn get_header<'a>(header_map: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, ErrorMessage> {
    header_map
        .get(name)
        .map(|value| {
            value
                .to_str()
                .map(Some)
                .map_err(|e| header_error_message(name, &e.to_string()))
        })
        .unwrap_or(Ok(None))
}

/// convert header parse errors
fn header_error_message(name: &str, msg: &str) -> ErrorMessage {
    ErrorMessage::new(
        StatusCode::BAD_REQUEST,
        format!("Invalid request header {:?}: {:?}", name, msg),
    )
}

/// decode record from its base64 gzip format
fn decode_record(record: &EncodedFirehoseRecord) -> std::io::Result<Vec<u8>> {
    dbg!(&record.data);
    use flate2::read::GzDecoder;

    let mut cursor = std::io::Cursor::new(record.data.as_bytes());
    let base64decoder = base64::read::DecoderReader::new(&mut cursor, base64::STANDARD);

    let mut gz = GzDecoder::new(base64decoder);
    let mut buffer = Vec::new();
    gz.read_to_end(&mut buffer)?;

    Ok(buffer)
}

/// Represents an AWS Kinesis Firehose request
///
/// Represents protocol v1.0 (the only protocol as of writing)
///
/// https://docs.aws.amazon.com/firehose/latest/dev/httpdeliveryrequestresponse.html
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FirehoseRequest {
    request_id: String,

    #[serde(with = "ts_milliseconds")]
    timestamp: DateTime<Utc>,

    records: Vec<EncodedFirehoseRecord>,
}

#[derive(Debug, Deserialize)]
struct EncodedFirehoseRecord {
    data: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shutdown::ShutdownSignal;
    use crate::{
        config::{GlobalOptions, SourceConfig},
        event::{Event, LogEvent},
        test_util::{collect_ready, next_addr, wait_for_tcp},
        Pipeline,
    };
    use chrono::{DateTime, Utc};
    use futures::compat::Future01CompatExt;
    use futures01::sync::mpsc;
    use pretty_assertions::assert_eq;
    use std::io::Read;
    use std::net::SocketAddr;

    macro_rules! log_event {
        ($($key:expr => $value:expr),*  $(,)?) => {
            {
                let mut event = Event::Log(LogEvent::default());
                let log = event.as_mut_log();
                $(
                    log.insert($key, $value);
                )*
				event
            }
        };
    }

    async fn source(
        access_key: Option<String>,
        encoding: EncodingConfig<Encoding>,
    ) -> (mpsc::Receiver<Event>, SocketAddr) {
        let (sender, recv) = Pipeline::new_test();
        let address = next_addr();
        tokio::spawn(async move {
            AwsKinesisFirehoseConfig {
                address,
                tls: None,
                access_key,
                encoding,
            }
            .build_async(
                "default",
                &GlobalOptions::default(),
                ShutdownSignal::noop(),
                sender,
            )
            .await
            .unwrap()
            .compat()
            .await
            .unwrap()
        });
        wait_for_tcp(address).await;
        (recv, address)
    }

    /// Sends the body to the address with the appropriate Firehose headers
    ///
    /// https://docs.aws.amazon.com/firehose/latest/dev/httpdeliveryrequestresponse.html
    async fn send(
        address: SocketAddr,
        body: &str,
        key: Option<&str>,
        request_id: &str,
        source_arn: &str,
    ) -> reqwest::Result<reqwest::Response> {
        let mut builder = reqwest::Client::new()
            .post(&format!("http://{}", address))
            .header("host", address.to_string())
            .header(
                "x-amzn-trace-id",
                "Root=1-5f5fbf1c-877c68cace58bea222ddbeec",
            )
            .header("content-length", body.len())
            .header("x-amz-firehose-protocol-version", "1.0")
            .header("x-amz-firehose-request-id", request_id.to_string())
            .header("x-amz-firehose-source-arn", source_arn.to_string())
            .header("user-agent", "Amazon Kinesis Data Firehose Agent/1.0")
            .header("content-type", "application/json")
            .body(body.to_owned());

        if let Some(key) = key {
            builder = builder.header("x-amz-firehose-access-key", key);
        }

        builder.send().await
    }

    /// Encodes record data to mach AWS's representation: base64 encoded, gzip'd data
    fn encode_record(record: &str) -> std::io::Result<String> {
        use flate2::read::GzEncoder;
        use flate2::Compression;

        let mut buffer = Vec::new();

        let mut gz = GzEncoder::new(record.as_bytes(), Compression::fast());
        gz.read_to_end(&mut buffer)?;

        Ok(base64::encode(&buffer))
    }

    #[tokio::test]
    async fn firehose_handles_cloudwatch_logs() {
        let record = r#"
{
  "messageType": "DATA_MESSAGE",
  "owner": "071959437513",
  "logGroup": "/jesse/test",
  "logStream": "test",
  "subscriptionFilters": [
	"Destination"
  ],
  "logEvents": [
	{
	  "id": "35683658089614582423604394983260738922885519999578275840",
	  "timestamp": 1600110569039,
	  "message": "{\"bytes\":26780,\"datetime\":\"14/Sep/2020:11:45:41 -0400\",\"host\":\"157.130.216.193\",\"method\":\"PUT\",\"protocol\":\"HTTP/1.0\",\"referer\":\"https://www.principalcross-platform.io/markets/ubiquitous\",\"request\":\"/expedite/convergence\",\"source_type\":\"stdin\",\"status\":301,\"user-identifier\":\"-\"}"
	},
	{
	  "id": "35683658089659183914001456229543810359430816722590236673",
	  "timestamp": 1600110569041,
	  "message": "{\"bytes\":17707,\"datetime\":\"14/Sep/2020:11:45:41 -0400\",\"host\":\"109.81.244.252\",\"method\":\"GET\",\"protocol\":\"HTTP/2.0\",\"referer\":\"http://www.investormission-critical.io/24/7/vortals\",\"request\":\"/scale/functionalities/optimize\",\"source_type\":\"stdin\",\"status\":502,\"user-identifier\":\"feeney1708\"}"
	}
  ]
}
"#;

        let body = r#"
{
  "requestId": "e17265d6-97af-4938-982e-90d5614c4242",
  "timestamp": 1600110364268,
  "records": [
    {
      "data": "%record%"
    }
  ]
}
"#
        .replace("%record%", &encode_record(record).unwrap());

        let (rx, addr) = source(
            None,
            EncodingConfig {
                codec: Encoding::AwsCloudWatchLogsSubscription,
            },
        )
        .await;

        let source_arn = "arn:aws:firehose:us-east-1:111111111111:deliverystream/test";
        let request_id = "e17265d6-97af-4938-982e-90d5614c4242";

        let res = send(addr, &body, None, request_id, source_arn)
            .await
            .unwrap();
        assert_eq!(200, res.status().as_u16());

        let events = collect_ready(rx).await.unwrap();
        assert_eq!(
            events,
            vec![
                log_event! {
                    "message" => r#"{"bytes":26780,"datetime":"14/Sep/2020:11:45:41 -0400","host":"157.130.216.193","method":"PUT","protocol":"HTTP/1.0","referer":"https://www.principalcross-platform.io/markets/ubiquitous","request":"/expedite/convergence","source_type":"stdin","status":301,"user-identifier":"-"}"#,
                    "timestamp" => "2020-09-14T19:09:29.039Z".parse::<DateTime<Utc>>().unwrap(),
                    "amz_request_id" => request_id,
                    "amz_source_arn" => source_arn,
                },
                log_event! {
                    "message" => r#"{"bytes":17707,"datetime":"14/Sep/2020:11:45:41 -0400","host":"109.81.244.252","method":"GET","protocol":"HTTP/2.0","referer":"http://www.investormission-critical.io/24/7/vortals","request":"/scale/functionalities/optimize","source_type":"stdin","status":502,"user-identifier":"feeney1708"}"#,
                    "timestamp" => "2020-09-14T19:09:29.041Z".parse::<DateTime<Utc>>().unwrap(),
                    "amz_request_id" => request_id,
                    "amz_source_arn" => source_arn,
                },
            ]
        );
    }

    #[tokio::test]
    async fn firehose_handles_cloudwatch_logs_ignores_control_message() {
        let record = r#"
{
  "messageType": "CONTROL_MESSAGE",
  "owner": "CloudwatchLogs",
  "logGroup": "",
  "logStream": "",
  "subscriptionFilters": [],
  "logEvents": [
    {
      "id": "",
      "timestamp": 1600110003794,
      "message": "CWL CONTROL MESSAGE: Checking health of destination Firehose."
    }
  ]
}
"#;

        let body = r#"
{
  "requestId": "e17265d6-97af-4938-982e-90d5614c4242",
  "timestamp": 1600110364268,
  "records": [
    {
      "data": "%record%"
    }
  ]
}
"#
        .replace("%record%", &encode_record(record).unwrap());

        let (rx, addr) = source(
            None,
            EncodingConfig {
                codec: Encoding::AwsCloudWatchLogsSubscription,
            },
        )
        .await;

        let res = send(addr, &body, None, "", "").await.unwrap();
        assert_eq!(200, res.status().as_u16());

        let events = collect_ready(rx).await.unwrap();
        assert_eq!(events, vec![]);
    }

    #[tokio::test]
    async fn firehose_rejects_bad_access_key() {
        let (_rx, addr) = source(
            Some("an access key".to_string()),
            EncodingConfig {
                codec: Encoding::AwsCloudWatchLogsSubscription,
            },
        )
        .await;

        let res = send(addr, "", Some("bad access key"), "", "")
            .await
            .unwrap();
        assert_eq!(401, res.status().as_u16());
    }
}
