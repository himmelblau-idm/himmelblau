//! Compatibility with the crypto-bigint 0.5 API used by elliptic-curve.
use core::{fmt::Debug, ops::*};
pub use crypto_bigint::{WideWord, Word};
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Limb(pub Word);
impl Limb {
    pub const ZERO: Self = Self(0);
    pub const BITS: usize = Word::BITS as usize;
    pub const BYTES: usize = core::mem::size_of::<Word>();
}

#[macro_export]
macro_rules! nlimbs {
    ($bits:expr) => {
        $bits / $crate::Limb::BITS as usize
    };
}
#[cfg(feature = "rand_core")]
use rand_core::CryptoRngCore;
pub use subtle;
use subtle::{
    Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess,
    CtOption,
};
pub trait Integer:
    'static
    + AsRef<[Limb]>
    + BitAnd<Output = Self>
    + BitOr<Output = Self>
    + BitXor<Output = Self>
    + for<'a> CheckedAdd<&'a Self, Output = Self>
    + for<'a> CheckedSub<&'a Self, Output = Self>
    + for<'a> CheckedMul<&'a Self, Output = Self>
    + Copy
    + ConditionallySelectable
    + ConstantTimeEq
    + ConstantTimeGreater
    + ConstantTimeLess
    + Debug
    + Default
    + Div<NonZero<Self>, Output = Self>
    + Eq
    + From<u64>
    + Not
    + Ord
    + Rem<NonZero<Self>, Output = Self>
    + Send
    + Sized
    + Shl<usize, Output = Self>
    + Shr<usize, Output = Self>
    + Sync
    + Zero
{
    const ONE: Self;

    const MAX: Self;

    const BITS: usize;

    const BYTES: usize;

    const LIMBS: usize;

    fn is_odd(&self) -> Choice;

    fn is_even(&self) -> Choice {
        !self.is_odd()
    }
}

pub trait Zero: ConstantTimeEq + Sized {
    const ZERO: Self;

    fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }
}

#[cfg(feature = "rand_core")]
pub trait Random: Sized {
    fn random(rng: &mut impl CryptoRngCore) -> Self;
}

#[cfg(feature = "rand_core")]
pub trait RandomMod: Sized + Zero {
    fn random_mod(rng: &mut impl CryptoRngCore, modulus: &NonZero<Self>) -> Self;
}

pub trait AddMod<Rhs = Self> {
    type Output;

    fn add_mod(&self, rhs: &Rhs, p: &Self) -> Self::Output;
}

pub trait SubMod<Rhs = Self> {
    type Output;

    fn sub_mod(&self, rhs: &Rhs, p: &Self) -> Self::Output;
}

pub trait NegMod {
    type Output;

    #[must_use]
    fn neg_mod(&self, p: &Self) -> Self::Output;
}

pub trait CheckedAdd<Rhs = Self>: Sized {
    type Output;

    fn checked_add(&self, rhs: Rhs) -> CtOption<Self>;
}

pub trait CheckedMul<Rhs = Self>: Sized {
    type Output;

    fn checked_mul(&self, rhs: Rhs) -> CtOption<Self>;
}

pub trait CheckedSub<Rhs = Self>: Sized {
    type Output;

    fn checked_sub(&self, rhs: Rhs) -> CtOption<Self>;
}

pub trait Encoding: Sized {
    type Repr: AsRef<[u8]> + AsMut<[u8]> + Copy + Clone + Sized;

    fn from_be_bytes(bytes: Self::Repr) -> Self;

    fn from_le_bytes(bytes: Self::Repr) -> Self;

    fn to_be_bytes(&self) -> Self::Repr;

    fn to_le_bytes(&self) -> Self::Repr;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Uint<const N: usize>(crypto_bigint::Uint<N>);
impl<const N: usize> Uint<N> {
    pub const ZERO: Self = Self(crypto_bigint::Uint::ZERO);
    pub const ONE: Self = Self(crypto_bigint::Uint::ONE);
    pub const MAX: Self = Self(crypto_bigint::Uint::MAX);
    pub const BITS: usize = N * Limb::BITS as usize;
    pub const BYTES: usize = N * Limb::BYTES;
    pub const LIMBS: usize = N;
    pub const fn from_be_hex(s: &str) -> Self {
        Self(crypto_bigint::Uint::from_be_hex(s))
    }
    pub const fn from_u64(n: u64) -> Self {
        Self(crypto_bigint::Uint::from_u64(n))
    }
    pub const fn from_words(w: [Word; N]) -> Self {
        Self(crypto_bigint::Uint::from_words(w))
    }
    pub const fn as_words(&self) -> &[Word; N] {
        self.0.as_words()
    }
    pub const fn to_words(self) -> [Word; N] {
        self.0.to_words()
    }
    pub const fn sbb(&self, rhs: &Self, b: Limb) -> (Self, Limb) {
        let (v, b) = self.0.borrowing_sub(&rhs.0, crypto_bigint::Limb(b.0));
        (Self(v), Limb(b.0))
    }
    pub const fn adc(&self, rhs: &Self, b: Limb) -> (Self, Limb) {
        let (v, b) = self.0.carrying_add(&rhs.0, crypto_bigint::Limb(b.0));
        (Self(v), Limb(b.0))
    }
    pub const fn mul_wide(&self, rhs: &Self) -> (Self, Self) {
        let (lo, hi) = self.0.widening_mul(&rhs.0);
        (Self(lo), Self(hi))
    }
    pub const fn shr_vartime(&self, n: usize) -> Self {
        if n >= Self::BITS {
            Self::ZERO
        } else {
            Self(self.0.shr_vartime(n as u32))
        }
    }
    pub const fn add_mod(&self, rhs: &Self, p: &Self) -> Self {
        Self(self.0.add_mod(
            &rhs.0,
            &crypto_bigint::NonZero::<crypto_bigint::Uint<N>>::new_unwrap(p.0),
        ))
    }
    pub const fn sub_mod(&self, rhs: &Self, p: &Self) -> Self {
        Self(self.0.sub_mod(
            &rhs.0,
            &crypto_bigint::NonZero::<crypto_bigint::Uint<N>>::new_unwrap(p.0),
        ))
    }
    pub const fn neg_mod(&self, p: &Self) -> Self {
        Self(
            self.0
                .neg_mod(&crypto_bigint::NonZero::<crypto_bigint::Uint<N>>::new_unwrap(p.0)),
        )
    }
}
impl<const N: usize> From<u64> for Uint<N> {
    fn from(n: u64) -> Self {
        Self::from_u64(n)
    }
}
impl<const N: usize> AsRef<[Limb]> for Uint<N> {
    fn as_ref(&self) -> &[Limb] {
        unsafe {
            // SAFETY: Limb is a transparent wrapper over Word, with identical validity and alignment.
            core::slice::from_raw_parts(self.0.as_words().as_ptr().cast::<Limb>(), N)
        }
    }
}
impl<const N: usize> Zero for Uint<N> {
    const ZERO: Self = Self::ZERO;
}
impl<const N: usize> Integer for Uint<N> {
    const ONE: Self = Self::ONE;
    const MAX: Self = Self::MAX;
    const BITS: usize = Self::BITS;
    const BYTES: usize = Self::BYTES;
    const LIMBS: usize = N;
    fn is_odd(&self) -> Choice {
        Choice::from((self.as_words()[0] & 1) as u8)
    }
}
impl<const N: usize> ConditionallySelectable for Uint<N> {
    fn conditional_select(a: &Self, b: &Self, c: Choice) -> Self {
        let mut w = [0; N];
        for (i, v) in w.iter_mut().enumerate() {
            *v = Word::conditional_select(&a.as_words()[i], &b.as_words()[i], c);
        }
        Self::from_words(w)
    }
}
impl<const N: usize> ConstantTimeEq for Uint<N> {
    fn ct_eq(&self, b: &Self) -> Choice {
        self.as_words().ct_eq(b.as_words())
    }
}
impl<const N: usize> ConstantTimeLess for Uint<N> {
    fn ct_lt(&self, b: &Self) -> Choice {
        let (_, borrow) = self.sbb(b, Limb::ZERO);
        Choice::from((borrow.0 >> (Limb::BITS - 1)) as u8)
    }
}
impl<const N: usize> ConstantTimeGreater for Uint<N> {
    fn ct_gt(&self, b: &Self) -> Choice {
        b.ct_lt(self)
    }
}
impl<const N: usize> Not for Uint<N> {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0)
    }
}
impl<const N: usize> Shr<usize> for Uint<N> {
    type Output = Self;
    fn shr(self, n: usize) -> Self {
        self.shr_vartime(n)
    }
}
impl<const N: usize> Shl<usize> for Uint<N> {
    type Output = Self;
    fn shl(self, n: usize) -> Self {
        if n >= Self::BITS {
            Self::ZERO
        } else {
            Self(self.0.shl(n as u32))
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct NonZero<T>(T);
impl<T: Zero> NonZero<T> {
    pub fn new(n: T) -> CtOption<Self> {
        let c = !n.is_zero();
        CtOption::new(Self(n), c)
    }
}
impl<T> Deref for NonZero<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}
impl<T: Copy> AsRef<T> for NonZero<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}
#[cfg(feature = "zeroize")]
impl<const N: usize> zeroize::DefaultIsZeroes for Uint<N> {}
impl<const N: usize> BitAnd for Uint<N> {
    type Output = Self;
    fn bitand(self, b: Self) -> Self {
        Self(self.0.bitand(b.0))
    }
}
impl<const N: usize> BitOr for Uint<N> {
    type Output = Self;
    fn bitor(self, b: Self) -> Self {
        Self(self.0.bitor(b.0))
    }
}
impl<const N: usize> BitXor for Uint<N> {
    type Output = Self;
    fn bitxor(self, b: Self) -> Self {
        Self(self.0.bitxor(b.0))
    }
}
impl<const N: usize> Div<NonZero<Self>> for Uint<N> {
    type Output = Self;
    fn div(self, b: NonZero<Self>) -> Self {
        Self(
            self.0
                .div(crypto_bigint::NonZero::<crypto_bigint::Uint<N>>::new_unwrap(b.0 .0)),
        )
    }
}
impl<const N: usize> Rem<NonZero<Self>> for Uint<N> {
    type Output = Self;
    fn rem(self, b: NonZero<Self>) -> Self {
        Self(
            self.0
                .rem(crypto_bigint::NonZero::<crypto_bigint::Uint<N>>::new_unwrap(b.0 .0)),
        )
    }
}
impl<const N: usize> AddMod for Uint<N> {
    type Output = Self;
    fn add_mod(&self, b: &Self, p: &Self) -> Self {
        self.add_mod(b, p)
    }
}
impl<const N: usize> SubMod for Uint<N> {
    type Output = Self;
    fn sub_mod(&self, b: &Self, p: &Self) -> Self {
        self.sub_mod(b, p)
    }
}
impl<const N: usize> NegMod for Uint<N> {
    type Output = Self;
    fn neg_mod(&self, p: &Self) -> Self {
        self.neg_mod(p)
    }
}
impl<const N: usize> CheckedAdd<&Self> for Uint<N> {
    type Output = Self;
    fn checked_add(&self, b: &Self) -> CtOption<Self> {
        let (v, c) = self.adc(b, Limb::ZERO);
        CtOption::new(v, c.0.ct_eq(&0))
    }
}
impl<const N: usize> CheckedSub<&Self> for Uint<N> {
    type Output = Self;
    fn checked_sub(&self, b: &Self) -> CtOption<Self> {
        let (v, c) = self.sbb(b, Limb::ZERO);
        CtOption::new(v, c.0.ct_eq(&0))
    }
}
impl<const N: usize> CheckedMul<&Self> for Uint<N> {
    type Output = Self;
    fn checked_mul(&self, b: &Self) -> CtOption<Self> {
        let (v, c) = self.mul_wide(b);
        CtOption::new(v, c.is_zero())
    }
}

#[cfg(feature = "rand_core")]
impl<const N: usize> Random for Uint<N> {
    fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut words = [0; N];
        for w in &mut words {
            let mut bytes = [0; core::mem::size_of::<Word>()];
            rng.fill_bytes(&mut bytes);
            *w = Word::from_le_bytes(bytes);
        }
        Self::from_words(words)
    }
}
#[cfg(feature = "rand_core")]
impl<const N: usize> RandomMod for Uint<N> {
    fn random_mod(rng: &mut impl CryptoRngCore, p: &NonZero<Self>) -> Self {
        let bits = p.0 .0.bits_vartime() as usize;
        loop {
            let mut v = Self::random(rng).to_words();
            for (i, w) in v.iter_mut().enumerate() {
                let start = i * Limb::BITS as usize;
                if start >= bits {
                    *w = 0;
                } else if bits - start < Limb::BITS as usize {
                    *w &= Word::MAX >> (Limb::BITS as usize - (bits - start));
                }
            }
            let v = Self::from_words(v);
            if v < p.0 {
                return v;
            }
        }
    }
}
#[cfg(feature = "generic-array")]
pub use generic_array::{self, typenum::consts};
#[cfg(feature = "generic-array")]
pub type ByteArray<T> = generic_array::GenericArray<u8, <T as ArrayEncoding>::ByteSize>;
#[cfg(feature = "generic-array")]
pub trait ArrayEncoding: Encoding {
    type ByteSize: generic_array::ArrayLength<u8>
        + Add
        + Eq
        + Ord
        + generic_array::typenum::Unsigned;
    fn from_be_byte_array(bytes: ByteArray<Self>) -> Self;
    fn from_le_byte_array(bytes: ByteArray<Self>) -> Self;
    fn to_be_byte_array(&self) -> ByteArray<Self>;
    fn to_le_byte_array(&self) -> ByteArray<Self>;
}
pub mod prelude {
    #[cfg(feature = "generic-array")]
    pub use crate::ArrayEncoding;
    pub use crate::{
        AddMod, CheckedAdd, CheckedMul, CheckedSub, Encoding, Integer, NegMod, SubMod, Zero,
    };
    #[cfg(feature = "rand_core")]
    pub use crate::{Random, RandomMod};
}
pub type U256 = Uint<{ nlimbs!(256) }>;
impl Encoding for U256 {
    type Repr = [u8; 32];
    fn from_be_bytes(b: Self::Repr) -> Self {
        Self(crypto_bigint::Uint::from_be_slice(&b))
    }
    fn from_le_bytes(b: Self::Repr) -> Self {
        Self(crypto_bigint::Uint::from_le_slice(&b))
    }
    fn to_be_bytes(&self) -> Self::Repr {
        let mut b = [0; 32];
        for (i, w) in self.as_words().iter().rev().enumerate() {
            b[i * Limb::BYTES..(i + 1) * Limb::BYTES].copy_from_slice(&w.to_be_bytes());
        }
        b
    }
    fn to_le_bytes(&self) -> Self::Repr {
        let mut b = [0; 32];
        for (i, w) in self.as_words().iter().enumerate() {
            b[i * Limb::BYTES..(i + 1) * Limb::BYTES].copy_from_slice(&w.to_le_bytes());
        }
        b
    }
}
#[cfg(feature = "generic-array")]
impl ArrayEncoding for U256 {
    type ByteSize = consts::U32;
    fn from_be_byte_array(b: ByteArray<Self>) -> Self {
        Self(crypto_bigint::Uint::from_be_slice(&b))
    }
    fn from_le_byte_array(b: ByteArray<Self>) -> Self {
        Self(crypto_bigint::Uint::from_le_slice(&b))
    }
    fn to_be_byte_array(&self) -> ByteArray<Self> {
        generic_array::GenericArray::clone_from_slice(&self.to_be_bytes())
    }
    fn to_le_byte_array(&self) -> ByteArray<Self> {
        generic_array::GenericArray::clone_from_slice(&self.to_le_bytes())
    }
}
pub type U384 = Uint<{ nlimbs!(384) }>;
impl Encoding for U384 {
    type Repr = [u8; 48];
    fn from_be_bytes(b: Self::Repr) -> Self {
        Self(crypto_bigint::Uint::from_be_slice(&b))
    }
    fn from_le_bytes(b: Self::Repr) -> Self {
        Self(crypto_bigint::Uint::from_le_slice(&b))
    }
    fn to_be_bytes(&self) -> Self::Repr {
        let mut b = [0; 48];
        for (i, w) in self.as_words().iter().rev().enumerate() {
            b[i * Limb::BYTES..(i + 1) * Limb::BYTES].copy_from_slice(&w.to_be_bytes());
        }
        b
    }
    fn to_le_bytes(&self) -> Self::Repr {
        let mut b = [0; 48];
        for (i, w) in self.as_words().iter().enumerate() {
            b[i * Limb::BYTES..(i + 1) * Limb::BYTES].copy_from_slice(&w.to_le_bytes());
        }
        b
    }
}
#[cfg(feature = "generic-array")]
impl ArrayEncoding for U384 {
    type ByteSize = consts::U48;
    fn from_be_byte_array(b: ByteArray<Self>) -> Self {
        Self(crypto_bigint::Uint::from_be_slice(&b))
    }
    fn from_le_byte_array(b: ByteArray<Self>) -> Self {
        Self(crypto_bigint::Uint::from_le_slice(&b))
    }
    fn to_be_byte_array(&self) -> ByteArray<Self> {
        generic_array::GenericArray::clone_from_slice(&self.to_be_bytes())
    }
    fn to_le_byte_array(&self) -> ByteArray<Self> {
        generic_array::GenericArray::clone_from_slice(&self.to_le_bytes())
    }
}
pub type U576 = Uint<{ nlimbs!(576) }>;
impl Encoding for U576 {
    type Repr = [u8; 72];
    fn from_be_bytes(b: Self::Repr) -> Self {
        Self(crypto_bigint::Uint::from_be_slice(&b))
    }
    fn from_le_bytes(b: Self::Repr) -> Self {
        Self(crypto_bigint::Uint::from_le_slice(&b))
    }
    fn to_be_bytes(&self) -> Self::Repr {
        let mut b = [0; 72];
        for (i, w) in self.as_words().iter().rev().enumerate() {
            b[i * Limb::BYTES..(i + 1) * Limb::BYTES].copy_from_slice(&w.to_be_bytes());
        }
        b
    }
    fn to_le_bytes(&self) -> Self::Repr {
        let mut b = [0; 72];
        for (i, w) in self.as_words().iter().enumerate() {
            b[i * Limb::BYTES..(i + 1) * Limb::BYTES].copy_from_slice(&w.to_le_bytes());
        }
        b
    }
}
#[cfg(feature = "generic-array")]
impl ArrayEncoding for U576 {
    type ByteSize = consts::U72;
    fn from_be_byte_array(b: ByteArray<Self>) -> Self {
        Self(crypto_bigint::Uint::from_be_slice(&b))
    }
    fn from_le_byte_array(b: ByteArray<Self>) -> Self {
        Self(crypto_bigint::Uint::from_le_slice(&b))
    }
    fn to_be_byte_array(&self) -> ByteArray<Self> {
        generic_array::GenericArray::clone_from_slice(&self.to_be_bytes())
    }
    fn to_le_byte_array(&self) -> ByteArray<Self> {
        generic_array::GenericArray::clone_from_slice(&self.to_le_bytes())
    }
}

impl<const N: usize> AsRef<[Word; N]> for Uint<N> {
    fn as_ref(&self) -> &[Word; N] {
        self.as_words()
    }
}
impl<const N: usize> From<[Word; N]> for Uint<N> {
    fn from(w: [Word; N]) -> Self {
        Self::from_words(w)
    }
}
impl<const N: usize> ShrAssign<usize> for Uint<N> {
    fn shr_assign(&mut self, n: usize) {
        *self = self.shr_vartime(n);
    }
}
impl<const N: usize> core::fmt::UpperHex for Uint<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::UpperHex::fmt(&self.0, f)
    }
}
impl<const N: usize> Uint<N> {
    pub const fn from_u8(n: u8) -> Self {
        Self::from_u64(n as u64)
    }
    pub const fn wrapping_add(&self, b: &Self) -> Self {
        Self(self.0.wrapping_add(&b.0))
    }
    pub const fn wrapping_sub(&self, b: &Self) -> Self {
        Self(self.0.wrapping_sub(&b.0))
    }
}
impl<const N: usize> From<u32> for Uint<N> {
    fn from(n: u32) -> Self {
        Self::from_u64(n as u64)
    }
}
impl<const N: usize> From<u128> for Uint<N> {
    fn from(n: u128) -> Self {
        Self(crypto_bigint::Uint::from_u128(n))
    }
}
