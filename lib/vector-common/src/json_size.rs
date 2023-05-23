use std::{
    fmt,
    iter::Sum,
    ops::{Add, AddAssign, Sub},
};

/// A newtype for the Json size of an event.
/// Used to emit the `component_received_event_bytes_total` and
/// `component_sent_event_bytes_total` metrics.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct JsonSize(usize);

impl fmt::Display for JsonSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Sub for JsonSize {
    type Output = JsonSize;

    fn sub(self, rhs: Self) -> Self::Output {
        JsonSize(self.0 - rhs.0)
    }
}

impl Add for JsonSize {
    type Output = JsonSize;

    fn add(self, rhs: Self) -> Self::Output {
        JsonSize(self.0 + rhs.0)
    }
}

impl AddAssign for JsonSize {
    fn add_assign(&mut self, rhs: Self) {
        *self = JsonSize::new(self.0 + rhs.0);
    }
}

impl Sum for JsonSize {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(JsonSize(0), |a, b| a + b)
    }
}

impl From<usize> for JsonSize {
    fn from(value: usize) -> Self {
        Self(value)
    }
}

impl JsonSize {
    /// Create a new instance with the specified size.
    #[must_use]
    pub const fn new(size: usize) -> Self {
        Self(size)
    }

    /// Create a new instance with size 0.
    #[must_use]
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Returns the contained size.
    #[must_use]
    pub fn size(&self) -> usize {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[allow(clippy::module_name_repetitions)]
pub struct NonZeroJsonSize(JsonSize);

impl NonZeroJsonSize {
    #[must_use]
    pub fn new(size: JsonSize) -> Option<Self> {
        if size.0 == 0 {
            None
        } else {
            Some(NonZeroJsonSize(size))
        }
    }
}

impl From<NonZeroJsonSize> for JsonSize {
    fn from(value: NonZeroJsonSize) -> Self {
        value.0
    }
}
