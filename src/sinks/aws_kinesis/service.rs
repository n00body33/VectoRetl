use std::{
    marker::PhantomData,
    task::{Context, Poll},
};

use aws_smithy_client::SdkError;
use aws_types::region::Region;
use futures::future::BoxFuture;
use tower::Service;
use vector_common::request_metadata::MetaDescriptive;
use vector_core::{internal_event::CountByteSize, stream::DriverResponse};

use super::{
    record::{Record, SendRecord},
    sink::BatchKinesisRequest,
};
use crate::event::EventStatus;

pub struct KinesisService<C, T, E> {
    pub client: C,
    pub stream_name: String,
    pub region: Option<Region>,
    pub _phantom_t: PhantomData<T>,
    pub _phantom_e: PhantomData<E>,
}

impl<C, T, E> Clone for KinesisService<C, T, E>
where
    C: Clone,
{
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            stream_name: self.stream_name.clone(),
            region: self.region.clone(),
            _phantom_e: self._phantom_e,
            _phantom_t: self._phantom_t,
        }
    }
}

pub struct KinesisResponse {
    pub(crate) count: usize,
    pub(crate) failure_count: usize,
    pub(crate) events_byte_size: usize,
}

impl DriverResponse for KinesisResponse {
    fn event_status(&self) -> EventStatus {
        EventStatus::Delivered
    }

    fn events_sent(&self) -> CountByteSize {
        CountByteSize(self.count, self.events_byte_size)
    }
}

impl<R, C, T, E> Service<BatchKinesisRequest<R>> for KinesisService<C, T, E>
where
    R: Record<T = T> + Clone,
    C: SendRecord + Clone + Sync + Send + 'static,
    Vec<<C as SendRecord>::T>: FromIterator<T>,
    <C as SendRecord>::T: Send,
{
    type Response = KinesisResponse;
    type Error = SdkError<<C as SendRecord>::E>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    // Emission of an internal event in case of errors is handled upstream by the caller.
    fn poll_ready(&mut self, _cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    // Emission of internal events for errors and dropped events is handled upstream by the caller.
    fn call(&mut self, requests: BatchKinesisRequest<R>) -> Self::Future {
        let events_byte_size = requests.get_metadata().events_byte_size();

        let records = requests
            .events
            .into_iter()
            .map(|req| req.record.get())
            .collect();

        let client = self.client.clone();
        let stream_name = self.stream_name.clone();

        Box::pin(async move {
            client.send(records, stream_name).await.map(|mut r| {
                // augment the response
                r.events_byte_size = events_byte_size;
                r
            })
        })
    }
}
