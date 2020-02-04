use crate::{
    event::{self, flatten::flatten, Event},
    sources::util::{ErrorMessage, HttpSource},
    topology::config::{DataType, GlobalOptions, SourceConfig},
};
use bytes::Buf;
use chrono::Utc;
use futures::sync::mpsc;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::{
    io::{BufRead, BufReader, Read},
    net::SocketAddr,
};
use warp::http::{HeaderMap, HeaderValue, StatusCode};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SimpleHttpConfig {
    address: SocketAddr,
    #[serde(default)]
    encoding: Encoding,
    #[serde(default)]
    headers: Vec<String>,
}

#[derive(Clone)]
struct SimpleHttpSource {
    encoding: Encoding,
    headers: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone, Derivative, Copy)]
#[serde(rename_all = "snake_case")]
#[derivative(Default)]
pub enum Encoding {
    #[derivative(Default)]
    Text,
    Ndjson,
    Json,
}

impl HttpSource for SimpleHttpSource {
    fn build_event(
        &self,
        body: impl Buf,
        header_map: HeaderMap,
    ) -> Result<Vec<Event>, ErrorMessage> {
        decode_body(body, self.encoding)
            .map(|events| add_headers(events, &self.headers, header_map))
    }
}

#[typetag::serde(name = "http")]
impl SourceConfig for SimpleHttpConfig {
    fn build(
        &self,
        _: &str,
        _: &GlobalOptions,
        out: mpsc::Sender<Event>,
    ) -> crate::Result<super::Source> {
        let source = SimpleHttpSource {
            encoding: self.encoding,
            headers: self.headers.clone(),
        };
        source.run(self.address, "".to_string(), out)
    }

    fn output_type(&self) -> DataType {
        DataType::Log
    }

    fn source_type(&self) -> &'static str {
        "http"
    }
}

fn add_headers(
    mut events: Vec<Event>,
    headers_config: &[String],
    headers: HeaderMap,
) -> Vec<Event> {
    for header_name in headers_config {
        let value = headers
            .get(header_name)
            .map(HeaderValue::as_bytes)
            .unwrap_or_default();
        for event in events.iter_mut() {
            event.as_mut_log().insert(header_name as &str, value);
        }
    }

    events
}

fn body_to_lines(body: impl Buf) -> impl Iterator<Item = String> {
    BufReader::new(body.reader())
        .lines()
        .filter_map(|res| {
            res.map_err(|error| error!(message = "Error reading request body", ?error))
                .ok()
        })
        .filter(|s| !s.is_empty())
}

fn decode_body(body: impl Buf, enc: Encoding) -> Result<Vec<Event>, ErrorMessage> {
    match enc {
        Encoding::Text => Ok(body_to_lines(body).map(Event::from).collect()),
        Encoding::Ndjson => Ok(body_to_lines(body)
            .map(|j| {
                let parsed_json = serde_json::from_str(&j)
                    .map_err(|e| json_error(format!("Error parsing Ndjson: {:?}", e)))?;
                json_parse_object(parsed_json)
            })
            .collect::<Result<_, _>>()?),
        Encoding::Json => {
            let mut buffer = String::new();
            body.reader()
                .read_to_string(&mut buffer)
                .map_err(|e| json_error(format!("Error reading body: {:?}", e)))?;
            let parsed_json = serde_json::from_str(&buffer)
                .map_err(|e| json_error(format!("Error parsing Json: {:?}", e)))?;
            json_parse_array_of_object(parsed_json)
        }
    }
}

fn json_parse_object(value: JsonValue) -> Result<Event, ErrorMessage> {
    let mut event = Event::new_empty_log();
    let log = event.as_mut_log();
    log.insert(event::TIMESTAMP.clone(), Utc::now()); // Add timestamp
    match value {
        JsonValue::Object(map) => {
            flatten(log, map);
            Ok(event)
        }
        _ => Err(json_error(format!(
            "Expected Object, got {}",
            json_value_to_type_string(&value)
        ))),
    }
}

fn json_parse_array_of_object(value: JsonValue) -> Result<Vec<Event>, ErrorMessage> {
    match value {
        JsonValue::Array(v) => v
            .into_iter()
            .map(json_parse_object)
            .collect::<Result<_, _>>(),
        JsonValue::Object(map) => {
            //treat like an array of one object
            Ok(vec![json_parse_object(JsonValue::Object(map))?])
        }
        _ => Err(json_error(format!(
            "Expected Array or Object, got {}.",
            json_value_to_type_string(&value)
        ))),
    }
}

fn json_error(s: String) -> ErrorMessage {
    ErrorMessage::new(StatusCode::BAD_REQUEST, format!("Bad JSON: {}", s))
}
fn json_value_to_type_string(value: &JsonValue) -> &'static str {
    match value {
        JsonValue::Object(_) => "Object",
        JsonValue::Array(_) => "Array",
        JsonValue::String(_) => "String",
        JsonValue::Number(_) => "Number",
        JsonValue::Bool(_) => "Bool",
        JsonValue::Null => "Null",
    }
}

#[cfg(test)]
mod tests {
    use super::{Encoding, SimpleHttpConfig};
    use warp::http::HeaderMap;

    use crate::{
        event::{self, Event},
        runtime::Runtime,
        test_util::{self, collect_n},
        topology::config::{GlobalOptions, SourceConfig},
    };
    use futures::sync::mpsc;
    use http::Method;
    use pretty_assertions::assert_eq;
    use std::net::SocketAddr;
    use string_cache::DefaultAtom as Atom;

    fn source(
        rt: &mut Runtime,
        encoding: Encoding,
        headers: Vec<String>,
    ) -> (mpsc::Receiver<Event>, SocketAddr) {
        test_util::trace_init();
        let (sender, recv) = mpsc::channel(100);
        let address = test_util::next_addr();
        rt.spawn(
            SimpleHttpConfig {
                address,
                encoding,
                headers,
            }
            .build("default", &GlobalOptions::default(), sender)
            .unwrap(),
        );
        (recv, address)
    }

    fn send(address: SocketAddr, body: &str) -> u16 {
        reqwest::Client::new()
            .request(Method::POST, &format!("http://{}/", address))
            .body(body.to_owned())
            .send()
            .unwrap()
            .status()
            .as_u16()
    }

    fn send_with_headers(address: SocketAddr, body: &str, headers: HeaderMap) -> u16 {
        reqwest::Client::new()
            .request(Method::POST, &format!("http://{}/", address))
            .headers(headers)
            .body(body.to_owned())
            .send()
            .unwrap()
            .status()
            .as_u16()
    }

    #[test]
    fn http_multiline_text() {
        let body = "test body\n\ntest body 2";

        let mut rt = test_util::runtime();
        let (rx, addr) = source(&mut rt, Encoding::default(), vec![]);

        assert_eq!(200, send(addr, body));

        let mut events = rt.block_on(collect_n(rx, 2)).unwrap();
        {
            let event = events.remove(0);
            let log = event.as_log();
            assert_eq!(log[&event::MESSAGE], "test body".into());
            assert!(log.get(&event::TIMESTAMP).is_some());
        }
        {
            let event = events.remove(0);
            let log = event.as_log();
            assert_eq!(log[&event::MESSAGE], "test body 2".into());
            assert!(log.get(&event::TIMESTAMP).is_some());
        }
    }

    #[test]
    fn http_json_parsing() {
        let mut rt = test_util::runtime();
        let (rx, addr) = source(&mut rt, Encoding::Json, vec![]);

        assert_eq!(400, send(addr, "{")); //malformed
        assert_eq!(400, send(addr, r#"{"key"}"#)); //key without value

        assert_eq!(200, send(addr, "{}")); //can be one object or array of objects
        assert_eq!(200, send(addr, "[{},{},{}]"));

        let mut events = rt.block_on(collect_n(rx, 2)).unwrap();
        assert!(events.remove(1).as_log().get(&event::TIMESTAMP).is_some());
        assert!(events.remove(0).as_log().get(&event::TIMESTAMP).is_some());
    }

    #[test]
    fn http_json_values() {
        let mut rt = test_util::runtime();
        let (rx, addr) = source(&mut rt, Encoding::Json, vec![]);

        assert_eq!(200, send(addr, r#"[{"key":"value"}]"#));
        assert_eq!(200, send(addr, r#"{"key2":"value2"}"#));

        let mut events = rt.block_on(collect_n(rx, 2)).unwrap();
        {
            let event = events.remove(0);
            let log = event.as_log();
            assert_eq!(log[&Atom::from("key")], "value".into());
            assert!(log.get(&event::TIMESTAMP).is_some());
        }
        {
            let event = events.remove(0);
            let log = event.as_log();
            assert_eq!(log[&Atom::from("key2")], "value2".into());
            assert!(log.get(&event::TIMESTAMP).is_some());
        }
    }

    #[test]
    fn http_ndjson() {
        let mut rt = test_util::runtime();
        let (rx, addr) = source(&mut rt, Encoding::Ndjson, vec![]);

        assert_eq!(400, send(addr, r#"[{"key":"value"}]"#)); //one object per line

        assert_eq!(
            200,
            send(addr, "{\"key1\":\"value1\"}\n\n{\"key2\":\"value2\"}")
        );

        let mut events = rt.block_on(collect_n(rx, 2)).unwrap();
        {
            let event = events.remove(0);
            let log = event.as_log();
            assert_eq!(log[&Atom::from("key1")], "value1".into());
            assert!(log.get(&event::TIMESTAMP).is_some());
        }
        {
            let event = events.remove(0);
            let log = event.as_log();
            assert_eq!(log[&Atom::from("key2")], "value2".into());
            assert!(log.get(&event::TIMESTAMP).is_some());
        }
    }

    #[test]
    fn http_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("User-Agent", "test_client".parse().unwrap());
        headers.insert("Upgrade-Insecure-Requests", "false".parse().unwrap());

        let mut rt = test_util::runtime();
        let (rx, addr) = source(
            &mut rt,
            Encoding::Ndjson,
            vec![
                "User-Agent".to_string(),
                "Upgrade-Insecure-Requests".to_string(),
                "AbsentHeader".to_string(),
            ],
        );

        assert_eq!(
            200,
            send_with_headers(addr, "{\"key1\":\"value1\"}", headers)
        );

        let mut events = rt.block_on(collect_n(rx, 1)).unwrap();
        {
            let event = events.remove(0);
            let log = event.as_log();
            assert_eq!(log[&Atom::from("key1")], "value1".into());
            assert_eq!(log[&Atom::from("User-Agent")], "test_client".into());
            assert_eq!(
                log[&Atom::from("Upgrade-Insecure-Requests")],
                "false".into()
            );
            assert_eq!(log[&Atom::from("AbsentHeader")], "".into());
            assert!(log.get(&event::TIMESTAMP).is_some());
        }
    }
}
