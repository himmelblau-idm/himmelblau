// Import hashbrown's DefaultHashBuilder privately to exclude it from glob re-export
#[allow(unused_imports)]
use hashbrown::DefaultHashBuilder as _;

// Re-export everything from hashbrown 0.17 (except DefaultHashBuilder)
pub use hashbrown::*;

// Provide our own DefaultHashBuilder matching hashbrown 0.15.5's exact definition
#[cfg(feature = "default-hasher")]
pub type DefaultHashBuilder = foldhash::fast::RandomState;

#[cfg(not(feature = "default-hasher"))]
pub enum DefaultHashBuilder {}
