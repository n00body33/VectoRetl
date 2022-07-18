use crate::{
    config::{
        AcknowledgementsConfig, DataType, GenerateConfig, Output, Resource, SourceConfig,
        SourceContext,
    },
    internal_events::{EventsReceived, StreamClosedError},
    opentelemetry::LogService::{
        logs_service_server::{LogsService, LogsServiceServer},
        ExportLogsServiceRequest, ExportLogsServiceResponse,
    },
    serde::bool_or_struct,
    sources::{util::grpc::run_grpc_server, Source},
    tls::{MaybeTlsSettings, TlsEnableableConfig},
    SourceSender,
};
use futures::TryFutureExt;
use std::net::SocketAddr;
use tonic::{Request, Response, Status};
use vector_config::configurable_component;
use vector_core::{
    config::LogNamespace,
    event::{BatchNotifier, BatchStatus, BatchStatusReceiver, Event},
    ByteSizeOf,
};

pub const LOGS: &str = "logs";

/// Configuration for the `opentelemetry` source.
#[configurable_component(source)]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct OpentelemetryConfig {
    /// The address to listen for connections on.
    ///
    /// It _must_ include a port.
    address: SocketAddr,

    #[configurable(derived)]
    #[serde(default)]
    tls: Option<TlsEnableableConfig>,

    #[configurable(derived)]
    #[serde(default, deserialize_with = "bool_or_struct")]
    acknowledgements: AcknowledgementsConfig,
}

impl GenerateConfig for OpentelemetryConfig {
    fn generate_config() -> toml::Value {
        toml::Value::try_from(Self {
            address: "0.0.0.0:4317".parse().unwrap(),
            tls: Default::default(),
            acknowledgements: Default::default(),
        })
        .unwrap()
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "opentelemetry")]
impl SourceConfig for OpentelemetryConfig {
    async fn build(&self, cx: SourceContext) -> crate::Result<Source> {
        let tls_settings = MaybeTlsSettings::from_config(&self.tls, true)?;
        let acknowledgements = cx.do_acknowledgements(&self.acknowledgements);
        let service = LogsServiceServer::new(Service {
            pipeline: cx.out,
            acknowledgements,
        })
        .accept_gzip();
        let source =
            run_grpc_server(self.address, tls_settings, service, cx.shutdown).map_err(|error| {
                error!(message = "Source future failed.", %error);
            });

        Ok(Box::pin(source))
    }

    fn outputs(&self, _global_log_namespace: LogNamespace) -> Vec<Output> {
        vec![Output::default(DataType::Log).with_port(LOGS)]
    }

    fn source_type(&self) -> &'static str {
        "opentelemetry"
    }

    fn resources(&self) -> Vec<Resource> {
        vec![Resource::tcp(self.address)]
    }

    fn can_acknowledge(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone)]
pub struct Service {
    pipeline: SourceSender,
    acknowledgements: bool,
}

#[tonic::async_trait]
impl LogsService for Service {
    async fn export(
        &self,
        request: Request<ExportLogsServiceRequest>,
    ) -> Result<Response<ExportLogsServiceResponse>, Status> {
        let mut events: Vec<Event> = request
            .into_inner()
            .resource_logs
            .into_iter()
            .flat_map(|v| v.into_iter())
            .collect();

        let count = events.len();
        let byte_size = events.size_of();

        emit!(EventsReceived { count, byte_size });

        let receiver = BatchNotifier::maybe_apply_to(self.acknowledgements, &mut events);

        self.pipeline
            .clone()
            .send_batch_named(LOGS, events)
            .map_err(|error| {
                let message = error.to_string();
                emit!(StreamClosedError { error, count });
                Status::unavailable(message)
            })
            .and_then(|_| handle_batch_status(receiver))
            .await?;
        Ok(Response::new(ExportLogsServiceResponse {}))
    }
}

async fn handle_batch_status(receiver: Option<BatchStatusReceiver>) -> Result<(), Status> {
    let status = match receiver {
        Some(receiver) => receiver.await,
        None => BatchStatus::Delivered,
    };

    match status {
        BatchStatus::Errored => Err(Status::internal("Delivery error")),
        BatchStatus::Rejected => Err(Status::data_loss("Delivery failed")),
        BatchStatus::Delivered => Ok(()),
    }
}
