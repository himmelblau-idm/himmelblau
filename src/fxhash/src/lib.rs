//! Minimal, maintained replacement for `fxhash 0.2.x`.
//!
//! This crate preserves the **public API** expected by downstream crates like
//! `selectors`/`scraper` by re-exporting `rustc_hash`'s Fx hasher and providing
//! the same type aliases (`FxHasher`, `FxBuildHasher`, `FxHashMap`, `FxHashSet`).

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasherDefault;

pub use rustc_hash::FxHasher;

/// A `BuildHasher` for `FxHasher`, matching the original crate’s alias.
pub type FxBuildHasher = BuildHasherDefault<FxHasher>;

/// A `HashMap` using `FxHasher`.
pub type FxHashMap<K, V> = HashMap<K, V, FxBuildHasher>;

/// A `HashSet` using `FxHasher`.
pub type FxHashSet<T> = HashSet<T, FxBuildHasher>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_and_set_compile_and_work() {
        let mut m: FxHashMap<&'static str, i32> = FxHashMap::default();
        m.insert("a", 1);
        m.insert("b", 2);
        assert_eq!(m.get("a"), Some(&1));
        assert!(m.contains_key("b"));

        let mut s: FxHashSet<&'static str> = FxHashSet::default();
        s.insert("x");
        s.insert("y");
        assert!(s.contains("x"));

        // Ensure the build hasher type is usable.
        let _state: FxBuildHasher = Default::default();
        let _h = FxHasher::default();
    }
}
