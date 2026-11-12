pub use rsa::*;

// Only the legacy API used by openidconnect is adapted here. RSA arithmetic,
// encoding, padding, and blinding remain implemented by upstream.
pub struct BigUint(rsa::BoxedUint);

impl BigUint {
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        Self(rsa::BoxedUint::from_be_slice_vartime(bytes))
    }

    pub fn to_bytes_be(&self) -> Vec<u8> {
        let bytes = self.0.to_be_bytes_trimmed_vartime().into_vec();
        if bytes.is_empty() {
            vec![0]
        } else {
            bytes
        }
    }
}

pub mod traits {
    pub use rsa::traits::*;

    pub trait PublicKeyParts {
        fn n(&self) -> &super::BigUint;
        fn e(&self) -> &super::BigUint;
    }
}

pub struct RsaPublicKey {
    inner: rsa::PublicKey,
    n: BigUint,
    e: BigUint,
}

impl RsaPublicKey {
    pub fn new(n: BigUint, e: BigUint) -> rsa::Result<Self> {
        rsa::PublicKey::new(n.0, e.0).map(Self::from)
    }

    pub fn verify<S: rsa::traits::SignatureScheme>(
        &self,
        padding: S,
        hashed: &[u8],
        signature: &[u8],
    ) -> rsa::Result<()> {
        self.inner.verify(padding, hashed, signature)
    }
}

impl From<rsa::PublicKey> for RsaPublicKey {
    fn from(inner: rsa::PublicKey) -> Self {
        use rsa::traits::PublicKeyParts;
        Self {
            n: BigUint(inner.n().as_ref().clone()),
            e: BigUint(inner.e().clone()),
            inner,
        }
    }
}

impl traits::PublicKeyParts for RsaPublicKey {
    fn n(&self) -> &BigUint {
        &self.n
    }

    fn e(&self) -> &BigUint {
        &self.e
    }
}

pub struct RsaPrivateKey(rsa::PrivateKey);

impl rsa::pkcs1::DecodeRsaPrivateKey for RsaPrivateKey {
    fn from_pkcs1_der(bytes: &[u8]) -> rsa::pkcs1::Result<Self> {
        rsa::PrivateKey::from_pkcs1_der(bytes).map(Self)
    }
}

impl RsaPrivateKey {
    pub fn sign_with_rng<R, S>(
        &self,
        rng: &mut R,
        padding: S,
        hashed: &[u8],
    ) -> rsa::Result<Vec<u8>>
    where
        R: rand_core_legacy::RngCore + rand_core_legacy::CryptoRng + ?Sized,
        S: rsa::traits::SignatureScheme,
    {
        self.0.sign_with_rng(&mut LegacyRng(rng), padding, hashed)
    }

    pub fn to_public_key(&self) -> RsaPublicKey {
        self.0.to_public_key().into()
    }
}

struct LegacyRng<'a, R: ?Sized>(&'a mut R);

impl<R: rand_core_legacy::RngCore + ?Sized> rsa::rand_core::TryRng for LegacyRng<'_, R> {
    type Error = rand_core_legacy::Error;

    fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
        Ok(self.0.next_u32())
    }

    fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
        Ok(self.0.next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), Self::Error> {
        self.0.try_fill_bytes(dst)
    }
}

impl<R: rand_core_legacy::RngCore + rand_core_legacy::CryptoRng + ?Sized>
    rsa::rand_core::TryCryptoRng for LegacyRng<'_, R>
{
}

pub trait LegacyDigest {
    type Upstream: rsa::sha2::Digest
        + rsa::sha2::digest::FixedOutputReset
        + rsa::pkcs8::AssociatedOid;
}

impl LegacyDigest for sha2_legacy::Sha256 {
    type Upstream = rsa::sha2::Sha256;
}

impl LegacyDigest for sha2_legacy::Sha384 {
    type Upstream = rsa::sha2::Sha384;
}

impl LegacyDigest for sha2_legacy::Sha512 {
    type Upstream = rsa::sha2::Sha512;
}

pub struct Pkcs1v15Sign;

impl Pkcs1v15Sign {
    pub fn new<D: LegacyDigest>() -> rsa::Pkcs1v15Sign {
        rsa::Pkcs1v15Sign::new::<D::Upstream>()
    }
}

pub struct Pss;

impl Pss {
    pub fn new<D: LegacyDigest>() -> rsa::Pss<D::Upstream> {
        rsa::Pss::<D::Upstream>::new()
    }

    pub fn new_with_salt<D: LegacyDigest>(len: usize) -> rsa::Pss<D::Upstream> {
        rsa::Pss::<D::Upstream>::new_with_salt(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::PublicKeyParts;
    use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
    use std::sync::OnceLock;

    fn native_key() -> &'static rsa::PrivateKey {
        static KEY: OnceLock<rsa::PrivateKey> = OnceLock::new();
        KEY.get_or_init(|| {
            rsa::PrivateKey::new(&mut LegacyRng(&mut rand_core_legacy::OsRng), 2048).unwrap()
        })
    }

    fn imported_key() -> RsaPrivateKey {
        let pem = native_key()
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .unwrap();
        RsaPrivateKey::from_pkcs1_pem(&pem).unwrap()
    }

    struct TestRng {
        bytes: usize,
        fail: bool,
    }

    impl rand_core_legacy::RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.bytes += 4;
            rand_core_legacy::OsRng.next_u32()
        }

        fn next_u64(&mut self) -> u64 {
            self.bytes += 8;
            rand_core_legacy::OsRng.next_u64()
        }

        fn fill_bytes(&mut self, dst: &mut [u8]) {
            self.try_fill_bytes(dst).unwrap();
        }

        fn try_fill_bytes(
            &mut self,
            dst: &mut [u8],
        ) -> std::result::Result<(), rand_core_legacy::Error> {
            if self.fail {
                return Err(rand_core_legacy::Error::new("test RNG failure"));
            }
            self.bytes += dst.len();
            rand_core_legacy::OsRng.try_fill_bytes(dst)
        }
    }

    impl rand_core_legacy::CryptoRng for TestRng {}

    #[test]
    fn public_components_preserve_values_without_leading_zeroes() {
        assert_eq!(BigUint::from_bytes_be(&[0, 0, 1]).to_bytes_be(), [1]);
        assert_eq!(BigUint::from_bytes_be(&[0]).to_bytes_be(), [0]);
        assert_eq!(BigUint::from_bytes_be(&[]).to_bytes_be(), [0]);

        let public = imported_key().to_public_key();
        let mut padded_n = vec![0];
        padded_n.extend(public.n().to_bytes_be());
        let reconstructed = RsaPublicKey::new(
            BigUint::from_bytes_be(&padded_n),
            BigUint::from_bytes_be(&public.e().to_bytes_be()),
        )
        .unwrap();
        assert_eq!(reconstructed.n().to_bytes_be(), public.n().to_bytes_be());
        assert_eq!(reconstructed.e().to_bytes_be(), public.e().to_bytes_be());
        assert!(
            RsaPublicKey::new(BigUint::from_bytes_be(&[0]), BigUint::from_bytes_be(&[3]),).is_err()
        );
    }

    fn check_scheme<S: rsa::traits::SignatureScheme>(
        scheme: impl Fn() -> S,
        native_scheme: impl Fn() -> S,
        key: &RsaPrivateKey,
        hash: &[u8],
    ) {
        let mut rng = TestRng {
            bytes: 0,
            fail: false,
        };
        let signature = key.sign_with_rng(&mut rng, scheme(), hash).unwrap();
        assert!(rng.bytes > 0);
        native_key()
            .to_public_key()
            .verify(native_scheme(), hash, &signature)
            .unwrap();

        let signature = native_key().sign(native_scheme(), hash).unwrap();
        let public = key.to_public_key();
        public.verify(scheme(), hash, &signature).unwrap();
        let mut wrong_hash = hash.to_vec();
        wrong_hash[0] ^= 1;
        assert!(public.verify(scheme(), &wrong_hash, &signature).is_err());
        let mut wrong_signature = signature;
        wrong_signature[0] ^= 1;
        assert!(public.verify(scheme(), hash, &wrong_signature).is_err());
    }

    fn check_digest<D: LegacyDigest + sha2_legacy::Digest>(key: &RsaPrivateKey) {
        let hash = <D as sha2_legacy::Digest>::digest(b"RSA adapter interoperability");
        check_scheme(
            Pkcs1v15Sign::new::<D>,
            rsa::Pkcs1v15Sign::new::<D::Upstream>,
            key,
            &hash,
        );
        check_scheme(Pss::new::<D>, rsa::Pss::<D::Upstream>::new, key, &hash);
        check_scheme(
            || Pss::new_with_salt::<D>(7),
            || rsa::Pss::<D::Upstream>::new_with_salt(7),
            key,
            &hash,
        );

        let signature = key
            .sign_with_rng(
                &mut rand_core_legacy::OsRng,
                Pss::new_with_salt::<D>(7),
                &hash,
            )
            .unwrap();
        assert!(key
            .to_public_key()
            .verify(Pss::new::<D>(), &hash, &signature)
            .is_err());
    }

    #[test]
    fn signatures_interoperate_with_upstream_for_each_used_digest() {
        let key = imported_key();
        check_digest::<sha2_legacy::Sha256>(&key);
        check_digest::<sha2_legacy::Sha384>(&key);
        check_digest::<sha2_legacy::Sha512>(&key);
    }

    #[test]
    fn signing_propagates_rng_failure() {
        let mut rng = TestRng {
            bytes: 0,
            fail: true,
        };
        let result =
            imported_key().sign_with_rng(&mut rng, Pss::new::<sha2_legacy::Sha256>(), &[0; 32]);
        assert_eq!(result, Err(rsa::Error::Rng));
    }
}
