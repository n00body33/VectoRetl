use std::collections::HashMap;
use std::ops::Add;

use crate::internal_event::{CountByteSize, OptionalTag};
use crate::json_size::JsonSize;

/// (Source, Service)
pub type EventCountTags = (OptionalTag, OptionalTag);

/// Must be implemented by events to get the tags that will be attached to
/// the `component_sent_event_*` emitted metrics.
pub trait GetEventCountTags {
    fn get_tags(&self) -> EventCountTags;
}

/// Keeps track of the estimated json size of a given batch of events by
/// source and service.
#[derive(Clone, Debug)]
pub enum RequestCountByteSize {
    /// When we need to keep track of the events by certain tags we use this
    /// variant.
    Tagged {
        sizes: HashMap<EventCountTags, CountByteSize>,
    },
    /// If we don't need to track the events by certain tags we can use
    /// this variant to avoid allocating a `HashMap`,
    Untagged { size: CountByteSize },
}

impl Default for RequestCountByteSize {
    fn default() -> Self {
        Self::Untagged {
            size: CountByteSize(0, JsonSize::zero()),
        }
    }
}

impl RequestCountByteSize {
    /// Creates a new Tagged variant for when we need to track events by
    /// certain tags.
    #[must_use]
    pub fn new_tagged() -> Self {
        Self::Tagged {
            sizes: HashMap::new(),
        }
    }

    /// Creates a new Tagged variant for when we do not need to track events by
    /// tags.
    #[must_use]
    pub fn new_untagged() -> Self {
        Self::Untagged {
            size: CountByteSize(0, JsonSize::zero()),
        }
    }

    /// Returns a `HashMap` of tags => event counts for when we are tracking by tags.
    /// Returns `None` if we are not tracking by tags.
    #[must_use]
    pub fn sizes(&self) -> Option<&HashMap<EventCountTags, CountByteSize>> {
        match self {
            RequestCountByteSize::Tagged { sizes } => Some(sizes),
            RequestCountByteSize::Untagged { .. } => None,
        }
    }

    /// Returns a single count for when we are not tracking by tags.
    #[must_use]
    pub fn size(&self) -> Option<CountByteSize> {
        match self {
            RequestCountByteSize::Tagged { .. } => None,
            RequestCountByteSize::Untagged { size } => Some(*size),
        }
    }

    /// Adds the given estimated json size of the event to current count.
    pub fn add_event<E>(&mut self, event: &E, json_size: JsonSize)
    where
        E: GetEventCountTags,
    {
        match self {
            RequestCountByteSize::Tagged { sizes } => {
                let size = CountByteSize(1, json_size);
                let tags = event.get_tags();

                match sizes.get_mut(&tags) {
                    Some(current) => {
                        *current += size;
                    }
                    None => {
                        sizes.insert(tags, size);
                    }
                }
            }
            RequestCountByteSize::Untagged { size } => {
                *size += CountByteSize(1, json_size);
            }
        }
    }
}

impl From<CountByteSize> for RequestCountByteSize {
    fn from(value: CountByteSize) -> Self {
        Self::Untagged { size: value }
    }
}

impl<'a> Add<&'a RequestCountByteSize> for RequestCountByteSize {
    type Output = RequestCountByteSize;

    fn add(self, other: &'a Self::Output) -> Self::Output {
        match (self, other) {
            (
                RequestCountByteSize::Tagged { sizes: mut us },
                RequestCountByteSize::Tagged { sizes: them },
            ) => {
                for (key, value) in them {
                    match us.get_mut(key) {
                        Some(size) => *size += *value,
                        None => {
                            us.insert(key.clone(), *value);
                        }
                    }
                }

                Self::Tagged { sizes: us }
            }

            (
                RequestCountByteSize::Untagged { size: us },
                RequestCountByteSize::Untagged { size: them },
            ) => RequestCountByteSize::Untagged { size: us + *them },

            // The following two scenarios shouldn't really occur in practice, but are provided for completeness.
            (
                RequestCountByteSize::Tagged { mut sizes },
                RequestCountByteSize::Untagged { size },
            ) => {
                match sizes.get_mut(&(OptionalTag::Specified(None), OptionalTag::Specified(None))) {
                    Some(empty_size) => *empty_size += *size,
                    None => {
                        sizes.insert(
                            (OptionalTag::Specified(None), OptionalTag::Specified(None)),
                            *size,
                        );
                    }
                }

                Self::Tagged { sizes }
            }
            (RequestCountByteSize::Untagged { size }, RequestCountByteSize::Tagged { sizes }) => {
                let mut sizes = sizes.clone();
                match sizes.get_mut(&(OptionalTag::Specified(None), OptionalTag::Specified(None))) {
                    Some(empty_size) => *empty_size += size,
                    None => {
                        sizes.insert(
                            (OptionalTag::Specified(None), OptionalTag::Specified(None)),
                            size,
                        );
                    }
                }

                Self::Tagged { sizes }
            }
        }
    }
}

/// Metadata for batch requests.
#[derive(Clone, Debug, Default)]
pub struct RequestMetadata {
    /// Number of events represented by this batch request.
    event_count: usize,
    /// Size, in bytes, of the in-memory representation of all events in this batch request.
    events_byte_size: usize,
    /// Size, in bytes, of the estimated JSON-encoded representation of all events in this batch request.
    events_estimated_json_encoded_byte_size: RequestCountByteSize,
    /// Uncompressed size, in bytes, of the encoded events in this batch request.
    request_encoded_size: usize,
    /// On-the-wire size, in bytes, of the batch request itself after compression, etc.
    ///
    /// This is akin to the bytes sent/received over the network, regardless of whether or not compression was used.
    request_wire_size: usize,
}

impl RequestMetadata {
    #[must_use]
    pub fn new(
        event_count: usize,
        events_byte_size: usize,
        request_encoded_size: usize,
        request_wire_size: usize,
        events_estimated_json_encoded_byte_size: RequestCountByteSize,
    ) -> Self {
        Self {
            event_count,
            events_byte_size,
            events_estimated_json_encoded_byte_size,
            request_encoded_size,
            request_wire_size,
        }
    }

    #[must_use]
    pub const fn event_count(&self) -> usize {
        self.event_count
    }

    #[must_use]
    pub const fn events_byte_size(&self) -> usize {
        self.events_byte_size
    }

    #[must_use]
    pub fn events_estimated_json_encoded_byte_size(&self) -> &RequestCountByteSize {
        &self.events_estimated_json_encoded_byte_size
    }

    /// Consumes the object and returns the byte size of the request grouped by
    /// the tags (source and service).
    #[must_use]
    pub fn into_events_estimated_json_encoded_byte_size(self) -> RequestCountByteSize {
        self.events_estimated_json_encoded_byte_size
    }

    #[must_use]
    pub const fn request_encoded_size(&self) -> usize {
        self.request_encoded_size
    }

    #[must_use]
    pub const fn request_wire_size(&self) -> usize {
        self.request_wire_size
    }

    /// Constructs a `RequestMetadata` by summation of the "batch" of `RequestMetadata` provided.
    #[must_use]
    pub fn from_batch<T: IntoIterator<Item = RequestMetadata>>(metadata_iter: T) -> Self {
        let mut metadata_sum = RequestMetadata::new(0, 0, 0, 0, RequestCountByteSize::default());

        for metadata in metadata_iter {
            metadata_sum = metadata_sum + &metadata;
        }
        metadata_sum
    }
}

impl<'a> Add<&'a RequestMetadata> for RequestMetadata {
    type Output = RequestMetadata;

    /// Adds the other `RequestMetadata` to this one.
    fn add(self, other: &'a Self::Output) -> Self::Output {
        Self::Output {
            event_count: self.event_count + other.event_count,
            events_byte_size: self.events_byte_size + other.events_byte_size,
            events_estimated_json_encoded_byte_size: self.events_estimated_json_encoded_byte_size
                + &other.events_estimated_json_encoded_byte_size,
            request_encoded_size: self.request_encoded_size + other.request_encoded_size,
            request_wire_size: self.request_wire_size + other.request_wire_size,
        }
    }
}

/// Objects implementing this trait have metadata that describes the request.
pub trait MetaDescriptive {
    /// Returns the `RequestMetadata` associated with this object.
    fn get_metadata(&self) -> &RequestMetadata;

    /// Returns the owned `RequestMetadata`.
    /// This function should only be called once.
    fn take_metadata(&mut self) -> RequestMetadata;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyEvent {
        source: OptionalTag,
        service: OptionalTag,
    }

    impl GetEventCountTags for DummyEvent {
        fn get_tags(&self) -> EventCountTags {
            (self.source.clone(), self.service.clone())
        }
    }

    #[test]
    fn add_request_count_bytesize_event_untagged() {
        let mut bytesize = RequestCountByteSize::new_untagged();
        let event = DummyEvent {
            source: Some("carrot".to_string()).into(),
            service: Some("cabbage".to_string()).into(),
        };

        bytesize.add_event(&event, JsonSize::new(42));

        let event = DummyEvent {
            source: Some("pea".to_string()).into(),
            service: Some("potato".to_string()).into(),
        };

        bytesize.add_event(&event, JsonSize::new(36));

        assert_eq!(Some(CountByteSize(2, JsonSize::new(78))), bytesize.size());
        assert_eq!(None, bytesize.sizes());
    }

    #[test]
    fn add_request_count_bytesize_event_tagged() {
        let mut bytesize = RequestCountByteSize::new_tagged();
        let event = DummyEvent {
            source: OptionalTag::Ignored,
            service: Some("cabbage".to_string()).into(),
        };

        bytesize.add_event(&event, JsonSize::new(42));

        let event = DummyEvent {
            source: OptionalTag::Ignored,
            service: Some("cabbage".to_string()).into(),
        };

        bytesize.add_event(&event, JsonSize::new(36));

        let event = DummyEvent {
            source: OptionalTag::Ignored,
            service: Some("tomato".to_string()).into(),
        };

        bytesize.add_event(&event, JsonSize::new(23));

        assert_eq!(None, bytesize.size());
        let mut sizes = bytesize
            .sizes()
            .unwrap()
            .clone()
            .into_iter()
            .collect::<Vec<_>>();
        sizes.sort();

        assert_eq!(
            vec![
                (
                    (OptionalTag::Ignored, Some("cabbage".to_string()).into()),
                    CountByteSize(2, JsonSize::new(78))
                ),
                (
                    (OptionalTag::Ignored, Some("tomato".to_string()).into()),
                    CountByteSize(1, JsonSize::new(23))
                ),
            ],
            sizes
        );
    }
}
