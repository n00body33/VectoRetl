use http::{Method, Request, Uri};
use hyper::{Body, Client};
use tokio::sync::mpsc;
use vector_core::event::Event;

use crate::components::compliance::sync::{Configured, ExternalResourceCoordinator, WaitHandle};

use super::ResourceDirection;

/// An HTTP resource.
pub struct HttpConfig {
    uri: Uri,
    method: Option<Method>,
}

impl HttpConfig {
    pub fn from_parts(uri: Uri, method: Option<Method>) -> Self {
        Self { uri, method }
    }

    pub fn spawn_as_input(
        self,
        direction: ResourceDirection,
        input_rx: mpsc::Receiver<Event>,
        resource_coordinator: &ExternalResourceCoordinator<Configured>,
        resource_shutdown_handle: WaitHandle,
    ) {
        match direction {
            // The source will pull data from us.
            ResourceDirection::Pull => spawn_input_http_server(
                self,
                input_rx,
                resource_coordinator,
                resource_shutdown_handle,
            ),
            // We'll push data to the source.
            ResourceDirection::Push => spawn_input_http_client(
                self,
                input_rx,
                resource_coordinator,
                resource_shutdown_handle,
            ),
        }
    }

    pub fn spawn_as_output(
        self,
        direction: ResourceDirection,
        output_tx: mpsc::Sender<Event>,
        resource_coordinator: &ExternalResourceCoordinator<Configured>,
        resource_shutdown_handle: WaitHandle,
    ) {
        match direction {
            // We'll pull data from the sink.
            ResourceDirection::Pull => spawn_output_http_client(
                self,
                output_tx,
                resource_coordinator,
                resource_shutdown_handle,
            ),
            // The sink will push data data to us.
            ResourceDirection::Push => spawn_output_http_server(
                self,
                output_tx,
                resource_coordinator,
                resource_shutdown_handle,
            ),
        }
    }
}

fn spawn_input_http_server(
    _config: HttpConfig,
    _input_rx: mpsc::Receiver<Event>,
    _resource_coordinator: &ExternalResourceCoordinator<Configured>,
    _resource_shutdown_handle: WaitHandle,
) {
    // Spin up an HTTP server that responds with all of the input data it has received since the
    // last request was responded to. Essentially, a client calling the server will never see data
    // more than once.
}

fn spawn_input_http_client(
    config: HttpConfig,
    mut input_rx: mpsc::Receiver<Event>,
    resource_coordinator: &ExternalResourceCoordinator<Configured>,
    _resource_shutdown_handle: WaitHandle,
) {
    // TODO: Should we actually obey the resource shutdown handle? Obviously we want to just keep
    // draining messages until we're done, but what about if the component errors prematurely and
    // now we're stuck waiting to be able to send requests to a server that isn't there and won't be
    // coming back? I guess we might just end up getting a "connection refused" error immediately,
    // but it's still worth thinking about more holistically, perhaps.

    // Spin up an HTTP client that will push the input data to the source on a
    // request-per-input-item basis. This runs serially and has no parallelism.
    let started = resource_coordinator.track_started();
    let completed = resource_coordinator.track_completed();

    tokio::spawn(async move {
        // Mark ourselves as started. We don't actually do anything until we get our first input
        // message, though.
        started.mark_as_done();
        debug!("HTTP client external input resource started.");

        let client = Client::builder().build_http::<Body>();
        let request_uri = config.uri;
        let request_method = config.method.unwrap_or(Method::POST);

        while let Some(_event) = input_rx.recv().await {
            debug!("Got event to send from runner.");

            let request = Request::builder()
                .uri(request_uri.clone())
                .method(request_method.clone())
                // TODO: We actually need to encode the event in a meaningful way for sending.
                .body(String::from("weeeoooo\n").into())
                .expect("should not fail to build request");

            match client.request(request).await {
                Ok(_response) => {
                    // TODO: Emit metric that tracks a successful response from the HTTP server.
                    debug!("Got response from server.");
                }
                Err(e) => {
                    // TODO: Emit metric that tracks a failed response from the HTTP server.
                    error!("Failed to send request: {}", e);
                }
            }
        }

        // Mark ourselves as completed now that we've sent all inputs to the source.
        completed.mark_as_done();

        debug!("HTTP client external input resource completed.");
    });
}

fn spawn_output_http_server(
    _config: HttpConfig,
    _output_tx: mpsc::Sender<Event>,
    _resource_coordinator: &ExternalResourceCoordinator<Configured>,
    _resource_shutdown_handle: WaitHandle,
) {
}

fn spawn_output_http_client(
    _config: HttpConfig,
    _output_tx: mpsc::Sender<Event>,
    _resource_coordinator: &ExternalResourceCoordinator<Configured>,
    _resource_shutdown_handle: WaitHandle,
) {
}
