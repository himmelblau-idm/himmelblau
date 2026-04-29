// Re-export everything from foldhash 0.2.0
pub use foldhash::*;

// Override fast::RandomState to restore Copy trait for 0.1.5 compatibility
pub mod fast {
    // Import foldhash::fast::RandomState privately to exclude it from glob re-export
    #[allow(unused_imports)]
    use foldhash::fast::RandomState as _;

    // Re-export everything from foldhash::fast except RandomState
    pub use foldhash::fast::*;

    use core::hash::BuildHasher;
    use foldhash::SharedSeed;

    /// A BuildHasher that provides Copy semantics to match foldhash 0.1.5's API.
    ///
    /// Delegates to foldhash 0.2.0 for all hashing logic, only adds Copy.
    #[derive(Copy, Clone, Debug)]
    pub struct RandomState {
        per_hasher_seed: u64,
    }

    // Simple atomic counter for generating unique per-hasher seeds
    use core::sync::atomic::{AtomicU64, Ordering};
    static SEED_COUNTER: AtomicU64 = AtomicU64::new(1);

    impl Default for RandomState {
        fn default() -> Self {
            Self {
                // Each instance gets a unique seed from a simple counter
                // This ensures good distribution while staying minimal
                per_hasher_seed: SEED_COUNTER.fetch_add(1, Ordering::Relaxed),
            }
        }
    }

    impl BuildHasher for RandomState {
        type Hasher = FoldHasher<'static>;

        fn build_hasher(&self) -> Self::Hasher {
            // Delegate entirely to foldhash 0.2.0's implementation
            FoldHasher::with_seed(self.per_hasher_seed, SharedSeed::global_random())
        }
    }
}
