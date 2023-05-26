mod bytes_received;
mod bytes_sent;
pub mod component_events_dropped;
mod events_received;
mod events_sent;
mod prelude;
pub mod service;

use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

pub use metrics::SharedString;

pub use bytes_received::BytesReceived;
pub use bytes_sent::BytesSent;
pub use component_events_dropped::{ComponentEventsDropped, INTENTIONAL, UNINTENTIONAL};
pub use events_received::EventsReceived;
pub use events_sent::{EventsSent, TaggedEventsSent, DEFAULT_OUTPUT};
pub use prelude::{error_stage, error_type};
pub use service::{CallError, PollReadyError};

pub trait InternalEvent: Sized {
    fn emit(self);

    // Optional for backwards compat until all events implement this
    fn name(&self) -> Option<&'static str> {
        None
    }
}

#[allow(clippy::module_name_repetitions)]
pub trait RegisterInternalEvent: Sized {
    type Handle: InternalEventHandle;

    fn register(self) -> Self::Handle;

    fn name(&self) -> Option<&'static str> {
        None
    }
}

#[allow(clippy::module_name_repetitions)]
pub trait InternalEventHandle: Sized {
    type Data: Sized;
    fn emit(&self, data: Self::Data);
}

// Sets the name of an event if it doesn't have one
pub struct DefaultName<E> {
    pub name: &'static str,
    pub event: E,
}

impl<E: InternalEvent> InternalEvent for DefaultName<E> {
    fn emit(self) {
        self.event.emit();
    }

    fn name(&self) -> Option<&'static str> {
        Some(self.event.name().unwrap_or(self.name))
    }
}

impl<E: RegisterInternalEvent> RegisterInternalEvent for DefaultName<E> {
    type Handle = E::Handle;

    fn register(self) -> Self::Handle {
        self.event.register()
    }

    fn name(&self) -> Option<&'static str> {
        Some(self.event.name().unwrap_or(self.name))
    }
}

#[cfg(any(test, feature = "test"))]
pub fn emit(event: impl InternalEvent) {
    if let Some(name) = event.name() {
        super::event_test_util::record_internal_event(name);
    }
    event.emit();
}

#[cfg(not(any(test, feature = "test")))]
pub fn emit(event: impl InternalEvent) {
    event.emit();
}

#[cfg(any(test, feature = "test"))]
pub fn register<E: RegisterInternalEvent>(event: E) -> E::Handle {
    if let Some(name) = event.name() {
        super::event_test_util::record_internal_event(name);
    }
    event.register()
}

#[cfg(not(any(test, feature = "test")))]
pub fn register<E: RegisterInternalEvent>(event: E) -> E::Handle {
    event.register()
}

pub type Registered<T> = <T as RegisterInternalEvent>::Handle;

// Wrapper types used to hold data emitted by registered events

#[derive(Clone, Copy)]
pub struct ByteSize(pub usize);

#[derive(Clone, Copy)]
pub struct Count(pub usize);

/// Holds the tuple `(count_of_events, size_of_events_in_bytes)`.
#[derive(Clone, Copy)]
pub struct CountByteSize(pub usize, pub usize);

// Wrapper types used to hold parameters for registering events

pub struct Output(pub Option<SharedString>);

pub struct Protocol(pub SharedString);

impl Protocol {
    pub const HTTP: Protocol = Protocol(SharedString::const_str("http"));
    pub const HTTPS: Protocol = Protocol(SharedString::const_str("https"));
    pub const NONE: Protocol = Protocol(SharedString::const_str("none"));
    pub const TCP: Protocol = Protocol(SharedString::const_str("tcp"));
    pub const UDP: Protocol = Protocol(SharedString::const_str("udp"));
    pub const UNIX: Protocol = Protocol(SharedString::const_str("unix"));
}

impl From<&'static str> for Protocol {
    fn from(s: &'static str) -> Self {
        Self(SharedString::const_str(s))
    }
}

/// Macro to take care of some of the repetitive boilerplate in implementing a registered event. See
/// the other events in this module for examples of how to use this.
///
/// ## Usage
///
/// ```ignore
/// registered_event!(
///     Event {
///         event_field: &'static str,
///     } => {
///         handle_field: Counter = register_counter!("name", "tag" => self.event_field),
///     }
///     fn emit(&self, data: DataType) {
///         self.handle_field.increment(data.0);
///     }
/// );
///
/// let handle = register!(Event { event_field: "message" });
///
/// handle.emit(DataType(123));
/// ```
///
/// In this example, the first set of fields describes the data required to register the event. This
/// is what would be used by the `register!` macro. For example, `register!(Event { event_field:
/// "something" })`. The second set of fields describes the data required to store the registered
/// handle, namely the `Counter`s and `Gauge`s that record the handle from `metrics` as well as any
/// associated data for emitting traces or debug messages, followed by an initialization assignment
/// value. The `emit` function is the code required to update the metrics and generate any log
/// messages.
#[macro_export]
macro_rules! registered_event {
    // A registered event struct with no fields (zero-sized type).
    ($event:ident => $($tail:tt)*) => {
        #[derive(Debug)]
        pub struct $event;

        $crate::registered_event!(=> $event $($tail)*);
    };

    // A normal registered event struct.
    ($event:ident { $( $field:ident: $type:ty, )* } => $($tail:tt)*) => {
        #[derive(Debug)]
        pub struct $event {
            $( pub $field: $type, )*
        }

        $crate::registered_event!(=> $event $($tail)*);
    };

    // Sub-matcher to implement the common bits in the above two cases.
    (
        => $event:ident {
            $( $field:ident: $type:ty = $value:expr, )*
        }

        fn emit(&$slf:ident, $data_name:ident: $data:ident)
            $emit_body:block
    ) => {
        paste::paste!{
            #[derive(Clone)]
            pub struct [<$event Handle>] {
                $( $field: $type, )*
            }

            impl $crate::internal_event::RegisterInternalEvent for $event {
                type Handle = [<$event Handle>];

                fn name(&self) -> Option<&'static str> {
                    Some(stringify!($event))
                }

                fn register($slf) -> Self::Handle {
                    Self::Handle {
                        $( $field: $value, )*
                    }
                }
            }

            impl $crate::internal_event::InternalEventHandle for [<$event Handle>] {
                type Data = $data;

                fn emit(&$slf, $data_name: $data)
                    $emit_body
            }
        }
    };
}

#[derive(Clone)]
pub struct Cached<Tags, Event, Register> {
    cache: Arc<RwLock<BTreeMap<Tags, Event>>>,
    register: Register,
}

impl<Tags, Event, Register, Data> Cached<Tags, Event, Register>
where
    Data: Sized,
    Register: Fn(&Tags) -> Event,
    Event: InternalEventHandle<Data = Data>,
    Tags: Ord + Clone,
{
    pub fn new(register: Register) -> Self {
        Self {
            cache: Arc::new(RwLock::new(BTreeMap::new())),
            register,
        }
    }

    pub fn emit(&self, tags: &Tags, value: Data) {
        let read = self.cache.read().unwrap();
        if let Some(event) = read.get(tags) {
            event.emit(value);
        } else {
            let event = (self.register)(tags);
            event.emit(value);

            // Ensure the read lock is dropped so we can write.
            drop(read);
            self.cache.write().unwrap().insert(tags.clone(), event);
        }
    }
}
