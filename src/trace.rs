use std::sync::{Mutex, MutexGuard};

use metrics_tracing_context::MetricsLayer;
use once_cell::sync::OnceCell;
use tokio::sync::broadcast::{self, Receiver, Sender};
use tracing::{
    dispatcher::{set_global_default, Dispatch},
    span::Span,
    subscriber::Interest,
    Id, Metadata, Subscriber,
};
use tracing_core::span;
pub use tracing_futures::Instrument;
use tracing_limit::RateLimitedLayer;
use tracing_log::LogTracer;
use tracing_subscriber::layer::SubscriberExt;
pub use tracing_tower::{InstrumentableService, InstrumentedService};

use crate::event::LogEvent;

/// BUFFER contains all of the internal log events generated by Vector
/// before the topology has been initialized. It will be cleared (set to
/// `None`) by the topology initialization routines.
static BUFFER: OnceCell<Mutex<Option<Vec<LogEvent>>>> = OnceCell::new();

/// SENDER holds the sender/receiver handle that will receive a copy of
/// all the internal log events *after* the topology has been
/// initialized.
static SENDER: OnceCell<Sender<LogEvent>> = OnceCell::new();

fn metrics_layer_enabled() -> bool {
    !matches!(std::env::var("DISABLE_INTERNAL_METRICS_TRACING_INTEGRATION"), Ok(x) if x == "true")
}

pub fn init(color: bool, json: bool, levels: &str) {
    let _ = BUFFER.set(Mutex::new(Some(Vec::new())));

    // An escape hatch to disable injecting a mertics layer into tracing.
    // May be used for performance reasons.
    // This is a hidden and undocumented functionality.
    let metrics_layer_enabled = metrics_layer_enabled();

    #[cfg(feature = "tokio-console")]
    let subscriber = {
        let (tasks_layer, tasks_server) = console_subscriber::ConsoleLayer::new();
        tokio::spawn(tasks_server.serve());

        tracing_subscriber::registry::Registry::default()
            .with(tasks_layer)
            .with(tracing_subscriber::filter::EnvFilter::from(levels))
    };
    #[cfg(not(feature = "tokio-console"))]
    let subscriber = tracing_subscriber::registry::Registry::default()
        .with(tracing_subscriber::filter::EnvFilter::from(levels));

    // dev note: we attempted to refactor to reduce duplication but it was starting to seem like
    // the refactored code would be introducing more complexity than it was worth to remove this
    // bit of duplication as we started to create a generic struct to wrap the formatters that also
    // implemented `Layer`
    let dispatch = if json {
        #[cfg(not(test))]
        let formatter = tracing_subscriber::fmt::Layer::default()
            .json()
            .flatten_event(true);

        #[cfg(test)]
        let formatter = tracing_subscriber::fmt::Layer::default()
            .json()
            .flatten_event(true)
            .with_test_writer(); // ensures output is captured

        let subscriber = subscriber.with(RateLimitedLayer::new(formatter));

        if metrics_layer_enabled {
            let subscriber = subscriber.with(MetricsLayer::new());
            Dispatch::new(BroadcastSubscriber { subscriber })
        } else {
            Dispatch::new(BroadcastSubscriber { subscriber })
        }
    } else {
        #[cfg(not(test))]
        let formatter = tracing_subscriber::fmt::Layer::default()
            .with_ansi(color)
            .with_writer(std::io::stderr);

        #[cfg(test)]
        let formatter = tracing_subscriber::fmt::Layer::default()
            .with_ansi(color)
            .with_test_writer(); // ensures output is captured

        let subscriber = subscriber.with(RateLimitedLayer::new(formatter));

        if metrics_layer_enabled {
            let subscriber = subscriber.with(MetricsLayer::new());
            Dispatch::new(BroadcastSubscriber { subscriber })
        } else {
            Dispatch::new(BroadcastSubscriber { subscriber })
        }
    };

    let _ = LogTracer::init();
    let _ = set_global_default(dispatch);
}

#[cfg(test)]
pub fn reset_early_buffer() {
    *early_buffer() = Some(Vec::new());
}

fn early_buffer() -> MutexGuard<'static, Option<Vec<LogEvent>>> {
    BUFFER
        .get()
        .expect("Internal logs buffer not initialized")
        .lock()
        .expect("Couldn't acquire lock on internal logs buffer")
}

pub(crate) fn stop_buffering() {
    *early_buffer() = None;
}

pub(crate) fn current_span() -> Span {
    Span::current()
}

pub struct TraceSubscription {
    pub(crate) buffer: Vec<LogEvent>,
    pub receiver: Receiver<LogEvent>,
}

pub(crate) fn subscribe() -> TraceSubscription {
    let buffer = match early_buffer().as_mut() {
        Some(buffer) => buffer.drain(..).collect(),
        None => Vec::new(),
    };
    let receiver = SENDER.get_or_init(|| broadcast::channel(99).0).subscribe();
    TraceSubscription { buffer, receiver }
}

struct BroadcastSubscriber<S> {
    subscriber: S,
}

impl<S: Subscriber + 'static> Subscriber for BroadcastSubscriber<S> {
    #[inline]
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.subscriber.enabled(metadata)
    }

    #[inline]
    fn new_span(&self, span: &tracing::span::Attributes<'_>) -> Id {
        self.subscriber.new_span(span)
    }

    #[inline]
    fn record(&self, span: &Id, record: &tracing::span::Record<'_>) {
        self.subscriber.record(span, record)
    }

    #[inline]
    fn record_follows_from(&self, span: &Id, follows: &Id) {
        self.subscriber.record_follows_from(span, follows)
    }

    #[inline]
    fn event(&self, event: &tracing::Event<'_>) {
        if let Some(buffer) = early_buffer().as_mut() {
            buffer.push(event.into());
        }
        if let Some(sender) = SENDER.get() {
            let _ = sender.send(event.into()); // Ignore errors
        }
        self.subscriber.event(event)
    }

    #[inline]
    fn enter(&self, span: &Id) {
        self.subscriber.enter(span)
    }

    #[inline]
    fn exit(&self, span: &Id) {
        self.subscriber.exit(span)
    }

    #[inline]
    fn current_span(&self) -> span::Current {
        self.subscriber.current_span()
    }

    #[inline]
    fn clone_span(&self, id: &Id) -> Id {
        self.subscriber.clone_span(id)
    }

    #[inline]
    fn try_close(&self, id: Id) -> bool {
        self.subscriber.try_close(id)
    }

    #[inline]
    fn register_callsite(&self, meta: &'static Metadata<'static>) -> Interest {
        self.subscriber.register_callsite(meta)
    }

    #[inline]
    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        self.subscriber.max_level_hint()
    }

    #[inline]
    unsafe fn downcast_raw(&self, id: std::any::TypeId) -> Option<*const ()> {
        self.subscriber.downcast_raw(id)
    }
}
