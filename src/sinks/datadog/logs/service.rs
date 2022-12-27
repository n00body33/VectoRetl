use std::{
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::future::BoxFuture;
use headers::HeaderName;
use http::{
    header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE},
    HeaderValue, Request, Uri,
};
use hyper::Body;
use indexmap::IndexMap;
use tower::Service;
use tracing::Instrument;
use vector_common::request_metadata::{MetaDescriptive, RequestMetadata};
use vector_core::{
    event::{EventFinalizers, EventStatus, Finalizable},
    internal_event::CountByteSize,
    stream::DriverResponse,
};

use crate::{
    http::HttpClient,
    sinks::datadog::DatadogApiError,
    sinks::util::{retries::RetryLogic, Compression},
};

#[derive(Debug, Default, Clone)]
pub struct LogApiRetry;

impl RetryLogic for LogApiRetry {
    type Error = DatadogApiError;
    type Response = LogApiResponse;

    fn is_retriable_error(&self, error: &Self::Error) -> bool {
        error.is_retriable()
    }
}

#[derive(Debug, Clone)]
pub struct LogApiRequest {
    pub api_key: Arc<str>,
    pub compression: Compression,
    pub body: Bytes,
    pub finalizers: EventFinalizers,
    pub uncompressed_size: usize,
    pub metadata: RequestMetadata,
}

impl Finalizable for LogApiRequest {
    fn take_finalizers(&mut self) -> EventFinalizers {
        std::mem::take(&mut self.finalizers)
    }
}

impl MetaDescriptive for LogApiRequest {
    fn get_metadata(&self) -> RequestMetadata {
        self.metadata
    }
}

#[derive(Debug)]
pub struct LogApiResponse {
    event_status: EventStatus,
    count: usize,
    events_byte_size: usize,
    raw_byte_size: usize,
}

impl DriverResponse for LogApiResponse {
    fn event_status(&self) -> EventStatus {
        self.event_status
    }

    fn events_sent(&self) -> CountByteSize {
        CountByteSize(self.count, self.events_byte_size)
    }

    fn bytes_sent(&self) -> Option<usize> {
        Some(self.raw_byte_size)
    }
}

/// Wrapper for the Datadog API.
///
/// Provides a `tower::Service` for the Datadog Logs API, allowing it to be
/// composed within a Tower "stack", such that we can easily and transparently
/// provide retries, concurrency limits, rate limits, and more.
#[derive(Debug, Clone)]
pub struct LogApiService {
    client: HttpClient,
    uri: Uri,
    user_provided_headers: IndexMap<HeaderName, HeaderValue>,
}

impl LogApiService {
    pub fn new(
        client: HttpClient,
        uri: Uri,
        headers: IndexMap<String, String>,
    ) -> crate::Result<Self> {
        let headers = Self::validate_headers(&headers)?;

        Ok(Self {
            client,
            uri,
            user_provided_headers: headers,
        })
    }

    fn validate_headers(
        headers: &IndexMap<String, String>,
    ) -> crate::Result<IndexMap<HeaderName, HeaderValue>> {
        let mut parsed_headers = IndexMap::new();
        for (name, value) in headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|error| format!("{}: {}", error, name))?;

            if name == CONTENT_TYPE
                || name == CONTENT_LENGTH
                || name == HeaderName::from_lowercase(b"dd-api-key").unwrap()
            {
                return Err(format!("{} header can not be configured", name).into());
            }

            let value = HeaderValue::from_bytes(value.as_bytes())
                .map_err(|error| format!("{}: {}", error, value))?;

            parsed_headers.insert(name, value);
        }

        Ok(parsed_headers)
    }
}

impl Service<LogApiRequest> for LogApiService {
    type Response = LogApiResponse;
    type Error = DatadogApiError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    // Emission of Error internal event is handled upstream by the caller
    fn poll_ready(&mut self, _cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    // Emission of Error internal event is handled upstream by the caller
    fn call(&mut self, request: LogApiRequest) -> Self::Future {
        let mut client = self.client.clone();
        let mut http_request = Request::post(&self.uri)
            .header("DD-EVP-ORIGIN", "vector")
            .header("DD-EVP-ORIGIN-VERSION", crate::get_version());
        if let Some(headers) = http_request.headers_mut() {
            for (name, value) in &self.user_provided_headers {
                // Replace rather than append to any existing header values
                headers.insert(name, value.clone());
            }
        }

        let http_request = if let Some(ce) = request.compression.content_encoding() {
            http_request.header(CONTENT_ENCODING, ce)
        } else {
            http_request
        };

        let count = request.get_metadata().event_count();
        let events_byte_size = request.get_metadata().events_byte_size();
        let raw_byte_size = request.uncompressed_size;

        let http_request = http_request
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, request.body.len())
            .header("DD-API-KEY", request.api_key.to_string())
            .body(Body::from(request.body))
            .expect("building HTTP request failed unexpectedly");

        Box::pin(async move {
            DatadogApiError::from_result(client.call(http_request).in_current_span().await).map(
                |_| LogApiResponse {
                    event_status: EventStatus::Delivered,
                    count,
                    events_byte_size,
                    raw_byte_size,
                },
            )
        })
    }
}
