//! Compatibility for the heapless 0.7 APIs used by this project's dependencies.
//!
//! Storage and collection operations come from heapless 0.9. This shim deliberately
//! does not implement the full heapless 0.7 API.

#![no_std]

use core::ops::{Deref, DerefMut};

pub use heapless::*;

/// A vector with the legacy unit errors required by heapless-bytes and iso7816.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Vec<T, const N: usize>(heapless::Vec<T, N>);

impl<T, const N: usize> Vec<T, N> {
    pub const fn new() -> Self {
        Self(heapless::Vec::new())
    }

    pub fn from_slice(slice: &[T]) -> Result<Self, ()>
    where
        T: Clone,
    {
        heapless::Vec::from_slice(slice).map(Self).map_err(|_| ())
    }

    pub fn extend_from_slice(&mut self, slice: &[T]) -> Result<(), ()>
    where
        T: Clone,
    {
        self.0.extend_from_slice(slice).map_err(|_| ())
    }

    pub fn resize_default(&mut self, new_len: usize) -> Result<(), ()>
    where
        T: Clone + Default,
    {
        self.0.resize_default(new_len).map_err(|_| ())
    }
}

impl<T, const N: usize> Default for Vec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone, const N: usize> TryFrom<&[T]> for Vec<T, N> {
    type Error = ();

    fn try_from(slice: &[T]) -> Result<Self, Self::Error> {
        Self::from_slice(slice)
    }
}

impl<T, const N: usize> Deref for Vec<T, N> {
    type Target = heapless::Vec<T, N>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, const N: usize> DerefMut for Vec<T, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T, const N: usize> AsRef<[T]> for Vec<T, N> {
    fn as_ref(&self) -> &[T] {
        self.0.as_slice()
    }
}

impl<T, const N: usize> AsMut<[T]> for Vec<T, N> {
    fn as_mut(&mut self) -> &mut [T] {
        self.0.as_mut_slice()
    }
}

impl<T, const N: usize> IntoIterator for Vec<T, N> {
    type Item = T;
    type IntoIter = <heapless::Vec<T, N> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a Vec<T, N> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a mut Vec<T, N> {
    type Item = &'a mut T;
    type IntoIter = core::slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

/// A string supporting the legacy `String::from(&str)` constructor.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct String<const N: usize>(heapless::String<N>);

impl<const N: usize> String<N> {
    pub const fn new() -> Self {
        Self(heapless::String::new())
    }

    /// Construct a string, panicking if it exceeds capacity as in heapless 0.7.
    // Keep this inherent so TryFrom remains fallible instead of using the blanket
    // implementation that a From<&str> implementation would introduce.
    pub fn from(value: &str) -> Self {
        Self::try_from(value).expect("string exceeds heapless capacity")
    }
}

impl<const N: usize> TryFrom<&str> for String<N> {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        heapless::String::try_from(value).map(Self).map_err(|_| ())
    }
}

impl<const N: usize> Deref for String<N> {
    type Target = heapless::String<N>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for String<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> PartialEq<str> for String<N> {
    fn eq(&self, other: &str) -> bool {
        self.0.as_str() == other
    }
}

impl<const N: usize> PartialEq<&str> for String<N> {
    fn eq(&self, other: &&str) -> bool {
        self.0.as_str() == *other
    }
}

#[cfg(test)]
mod tests {
    use super::{String, Vec};

    #[test]
    fn vector_capacity_errors_preserve_contents() {
        let mut vec = Vec::<u8, 3>::from_slice(&[1, 2]).unwrap();
        assert_eq!(vec.extend_from_slice(&[3, 4]), Err(()));
        assert_eq!(vec.as_slice(), &[1, 2]);
        assert_eq!(vec.extend_from_slice(&[3]), Ok(()));
        assert_eq!(vec.resize_default(4), Err(()));
        assert_eq!(vec.as_slice(), &[1, 2, 3]);
        vec.resize_default(1).unwrap();
        vec.resize_default(3).unwrap();
        assert_eq!(vec.as_slice(), &[1, 0, 0]);
        assert_eq!(Vec::<u8, 1>::try_from([1, 2].as_slice()), Err(()));
    }

    #[test]
    fn vector_iteration_and_slice_access() {
        let mut vec = Vec::<u8, 3>::new();
        vec.push(1).unwrap();
        vec.push(2).unwrap();
        vec.as_mut()[0] = 3;
        for item in &mut vec {
            *item += 1;
        }
        assert_eq!(vec.as_ref(), &[4, 3]);
        assert_eq!((&vec).into_iter().copied().sum::<u8>(), 7);
        assert_eq!(vec.into_iter().sum::<u8>(), 7);
    }

    #[test]
    fn string_construction_respects_byte_capacity() {
        assert_eq!(String::<2>::try_from("é").unwrap(), "é");
        assert_eq!(String::<1>::try_from("é"), Err(()));
        assert_eq!(String::<3>::from("abc"), "abc");
        let mut string = String::<3>::new();
        string.push_str("abc").unwrap();
        assert_eq!(string, "abc");
    }

    #[test]
    #[should_panic(expected = "string exceeds heapless capacity")]
    fn legacy_string_constructor_panics_on_overflow() {
        String::<1>::from("ab");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_deserialization_respects_capacity() {
        use serde::{de::value, Deserialize};

        type Error = value::Error;
        let vec = Vec::<u8, 2>::deserialize(value::SeqDeserializer::<_, Error>::new(
            [1u8, 2].into_iter(),
        ))
        .unwrap();
        assert_eq!(vec.as_slice(), &[1, 2]);
        assert!(
            Vec::<u8, 1>::deserialize(value::SeqDeserializer::<_, Error>::new(
                [1u8, 2].into_iter(),
            ))
            .is_err()
        );
        assert_eq!(
            String::<2>::deserialize(value::StrDeserializer::<Error>::new("é")).unwrap(),
            "é"
        );
        assert!(String::<1>::deserialize(value::StrDeserializer::<Error>::new("é")).is_err());
    }
}
