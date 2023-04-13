use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

static THREAD_ID_COUNTER: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static THREAD_ID: usize = THREAD_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
}

const DEFAULT_SHARD_FACTOR: usize = 32;

#[derive(Debug)]
pub struct ShardedAtomicU64 {
    slots: [AtomicU64; DEFAULT_SHARD_FACTOR],
}

impl ShardedAtomicU64 {
    pub const fn new() -> Self {
        debug_assert!(
            DEFAULT_SHARD_FACTOR == DEFAULT_SHARD_FACTOR.next_power_of_two(),
            "shard factor must be a power of two"
        );

        // We allow this usage, against Clippy's recommendation to the contrary, because while
        // _normally_ this would indeed be an instance of bad usage, we _need_ to construct the
        // `AtomicU64` in a const fashion so that it can be used for the static array initializer,
        // and we can't achieve this in any other way: using a static, or specifying
        // `AtomicU64::new(0)` in the initializer, etc.
        #[allow(clippy::declare_interior_mutable_const)]
        const DEFAULT_ATOMIC: AtomicU64 = AtomicU64::new(0);
        let slots = [DEFAULT_ATOMIC; DEFAULT_SHARD_FACTOR];

        Self { slots }
    }

    #[inline]
    pub fn increment_local(&self, amount: u64) {
        let id = THREAD_ID.try_with(|id| *id).unwrap_or_default();
        let idx = id & (DEFAULT_SHARD_FACTOR - 1);

        // SAFETY: `idx` is always smaller than `DEFAULT_SHARD_FACTOR`, and `self.slots` has
        // `DEFAULT_SHARD_FACTOR` elements, so we can never go out-of-bounds by indexing via `idx`.
        unsafe {
            self.slots
                .get_unchecked(idx)
                .fetch_add(amount, Ordering::Relaxed);
        }
    }

    pub const fn get_all(&self) -> &[AtomicU64] {
        &self.slots
    }
}

impl Default for ShardedAtomicU64 {
    fn default() -> Self {
        Self::new()
    }
}
