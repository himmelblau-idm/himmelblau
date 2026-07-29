use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::{digest, rsa as aws_rsa, signature as aws_signature};
use pkcs1_crate::der::{self, asn1::BitString, asn1::Null, Decode, Encode};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::marker::PhantomData;
use zeroize::{ZeroizeOnDrop, Zeroizing};

pub use num_bigint::BigUint;

pub mod signature {
    pub use signature_crate::*;
}

pub mod pkcs1 {
    pub use pkcs1_crate::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
}

pub mod traits {
    use super::{errors, BigUint, RsaPrivateKey, RsaPublicKey};

    pub trait PublicKeyParts {
        fn n(&self) -> &BigUint;
        fn e(&self) -> &BigUint;

        fn size(&self) -> usize {
            (self.n().bits() as usize + 7) / 8
        }
    }

    pub trait SignatureScheme {
        fn sign<Rng>(
            self,
            rng: Option<&mut Rng>,
            private_key: &RsaPrivateKey,
            hashed: &[u8],
        ) -> errors::Result<Vec<u8>>;

        fn verify(
            self,
            public_key: &RsaPublicKey,
            hashed: &[u8],
            signature: &[u8],
        ) -> errors::Result<()>;
    }
}

pub mod errors {
    use std::fmt;

    pub type Result<T> = std::result::Result<T, Error>;

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Error;

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("RSA operation failed")
        }
    }

    impl std::error::Error for Error {}

    impl From<aws_lc_rs::error::Unspecified> for Error {
        fn from(_: aws_lc_rs::error::Unspecified) -> Self {
            Self
        }
    }

    impl From<aws_lc_rs::error::KeyRejected> for Error {
        fn from(_: aws_lc_rs::error::KeyRejected) -> Self {
            Self
        }
    }
}

#[derive(Clone)]
pub struct RsaPublicKey {
    pkcs1_der: Vec<u8>,
    n: BigUint,
    e: BigUint,
}

impl fmt::Debug for RsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPublicKey").finish_non_exhaustive()
    }
}

impl PartialEq for RsaPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.pkcs1_der == other.pkcs1_der
    }
}

impl Eq for RsaPublicKey {}

impl traits::PublicKeyParts for RsaPublicKey {
    fn n(&self) -> &BigUint {
        &self.n
    }

    fn e(&self) -> &BigUint {
        &self.e
    }
}

impl RsaPublicKey {
    pub fn new(n: BigUint, e: BigUint) -> errors::Result<Self> {
        let components = aws_rsa::PublicKeyComponents {
            n: n.to_bytes_be(),
            e: e.to_bytes_be(),
        };
        let _: aws_rsa::PublicEncryptingKey = components.try_into()?;
        let pkcs1_der = encode_pkcs1_public_key(&n, &e).map_err(|_| errors::Error)?;
        Ok(Self { pkcs1_der, n, e })
    }

    pub fn encrypt<R>(&self, _rng: &mut R, padding: Oaep, data: &[u8]) -> errors::Result<Vec<u8>> {
        let key = aws_rsa::OaepPublicEncryptingKey::new(self.encrypting_key()?)?;
        let mut out = vec![0; key.ciphertext_size()];
        let ciphertext = key.encrypt(padding.algorithm()?, data, &mut out, padding.label())?;
        Ok(ciphertext.to_vec())
    }

    pub fn verify<S: traits::SignatureScheme>(
        &self,
        padding: S,
        hashed: &[u8],
        signature: &[u8],
    ) -> errors::Result<()> {
        padding.verify(self, hashed, signature)
    }

    fn from_public_key(key: aws_rsa::PublicKey) -> errors::Result<Self> {
        let pkcs1_der = key.as_ref().to_vec();
        let parsed =
            pkcs1_crate::RsaPublicKey::try_from(pkcs1_der.as_slice()).map_err(|_| errors::Error)?;
        let n = BigUint::from_bytes_be(parsed.modulus.as_bytes());
        let e = BigUint::from_bytes_be(parsed.public_exponent.as_bytes());
        let components = aws_rsa::PublicKeyComponents {
            n: parsed.modulus.as_bytes().to_vec(),
            e: parsed.public_exponent.as_bytes().to_vec(),
        };
        let _: aws_rsa::PublicEncryptingKey = components.try_into()?;
        Ok(Self { pkcs1_der, n, e })
    }

    fn encrypting_key(&self) -> errors::Result<aws_rsa::PublicEncryptingKey> {
        let components = aws_rsa::PublicKeyComponents {
            n: self.n.to_bytes_be(),
            e: self.e.to_bytes_be(),
        };
        components.try_into().map_err(Into::into)
    }
}

impl TryFrom<spki::SubjectPublicKeyInfoRef<'_>> for RsaPublicKey {
    type Error = spki::Error;

    fn try_from(spki: spki::SubjectPublicKeyInfoRef<'_>) -> spki::Result<Self> {
        let der = spki.to_der()?;
        let key = aws_rsa::PublicKey::from_der(&der).map_err(|_| spki::Error::KeyMalformed)?;
        Self::from_public_key(key).map_err(|_| spki::Error::KeyMalformed)
    }
}

pub struct RsaPrivateKey {
    pkcs8_der: Zeroizing<Vec<u8>>,
    public_key: RsaPublicKey,
}

impl Clone for RsaPrivateKey {
    fn clone(&self) -> Self {
        Self {
            pkcs8_der: Zeroizing::new(self.pkcs8_der.as_slice().to_vec()),
            public_key: self.public_key.clone(),
        }
    }
}

impl ZeroizeOnDrop for RsaPrivateKey {}

impl fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPrivateKey").finish_non_exhaustive()
    }
}

impl traits::PublicKeyParts for RsaPrivateKey {
    fn n(&self) -> &BigUint {
        self.public_key.n()
    }

    fn e(&self) -> &BigUint {
        self.public_key.e()
    }
}

impl RsaPrivateKey {
    pub fn new<R>(_rng: &mut R, bits: usize) -> errors::Result<Self> {
        let size = match bits {
            0 => return Err(errors::Error),
            1..=2048 => aws_rsa::KeySize::Rsa2048,
            2049..=3072 => aws_rsa::KeySize::Rsa3072,
            3073..=4096 => aws_rsa::KeySize::Rsa4096,
            4097..=8192 => aws_rsa::KeySize::Rsa8192,
            _ => return Err(errors::Error),
        };
        Self::from_private_decrypting_key(aws_rsa::PrivateDecryptingKey::generate(size)?)
    }

    pub fn decrypt(&self, padding: Oaep, ciphertext: &[u8]) -> errors::Result<Vec<u8>> {
        let private_key = aws_rsa::PrivateDecryptingKey::from_pkcs8(self.pkcs8_der.as_slice())?;
        let key = aws_rsa::OaepPrivateDecryptingKey::new(private_key)?;
        let mut out = vec![0; key.min_output_size()];
        let plaintext = key.decrypt(padding.algorithm()?, ciphertext, &mut out, padding.label())?;
        Ok(plaintext.to_vec())
    }

    fn from_private_decrypting_key(key: aws_rsa::PrivateDecryptingKey) -> errors::Result<Self> {
        let pkcs8_der = AsDer::<Pkcs8V1Der<'static>>::as_der(&key)?
            .as_ref()
            .to_vec();
        let public_encrypting_key = key.public_key();
        let public_der = AsDer::<PublicKeyX509Der<'static>>::as_der(&public_encrypting_key)?
            .as_ref()
            .to_vec();
        let public_key = RsaPublicKey::from_public_key(aws_rsa::PublicKey::from_der(&public_der)?)?;
        Ok(Self {
            pkcs8_der: Zeroizing::new(pkcs8_der),
            public_key,
        })
    }

    fn key_pair(
        &self,
    ) -> std::result::Result<aws_signature::RsaKeyPair, aws_lc_rs::error::KeyRejected> {
        aws_signature::RsaKeyPair::from_pkcs8(self.pkcs8_der.as_slice())
    }

    pub fn sign_with_rng<R, S: traits::SignatureScheme>(
        &self,
        rng: &mut R,
        padding: S,
        hashed: &[u8],
    ) -> errors::Result<Vec<u8>> {
        padding.sign(Some(rng), self, hashed)
    }

    pub fn to_public_key(&self) -> RsaPublicKey {
        self.public_key.clone()
    }
}

impl From<&RsaPrivateKey> for RsaPublicKey {
    fn from(private_key: &RsaPrivateKey) -> Self {
        private_key.public_key.clone()
    }
}

impl From<RsaPrivateKey> for RsaPublicKey {
    fn from(private_key: RsaPrivateKey) -> Self {
        private_key.public_key
    }
}

impl pkcs1_crate::DecodeRsaPrivateKey for RsaPrivateKey {
    fn from_pkcs1_der(bytes: &[u8]) -> pkcs1_crate::Result<Self> {
        let key_pair =
            aws_signature::RsaKeyPair::from_der(bytes).map_err(|_| pkcs1_crate::Error::Crypto)?;
        let pkcs8_der = AsDer::<Pkcs8V1Der<'static>>::as_der(&key_pair)
            .map_err(|_| pkcs1_crate::Error::Crypto)?
            .as_ref()
            .to_vec();
        let key = aws_rsa::PrivateDecryptingKey::from_pkcs8(&pkcs8_der)
            .map_err(|_| pkcs1_crate::Error::Crypto)?;
        Self::from_private_decrypting_key(key).map_err(|_| pkcs1_crate::Error::Crypto)
    }
}

impl pkcs1_crate::EncodeRsaPrivateKey for RsaPrivateKey {
    fn to_pkcs1_der(&self) -> pkcs1_crate::Result<pkcs1_crate::der::SecretDocument> {
        let pkcs8_key = pkcs8::PrivateKeyInfo::from_der(self.pkcs8_der.as_slice())
            .map_err(|_| pkcs1_crate::Error::Crypto)?;
        let rsa_oid = pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
        if pkcs8_key.algorithm.oid != rsa_oid {
            return Err(pkcs1_crate::Error::Crypto);
        }
        let pkcs1_key = pkcs1_crate::RsaPrivateKey::from_der(pkcs8_key.private_key)
            .map_err(|_| pkcs1_crate::Error::Crypto)?;
        pkcs1_crate::der::SecretDocument::try_from(pkcs1_key)
    }
}

impl pkcs8::DecodePrivateKey for RsaPrivateKey {
    fn from_pkcs8_der(bytes: &[u8]) -> pkcs8::Result<Self> {
        let key = aws_rsa::PrivateDecryptingKey::from_pkcs8(bytes)
            .map_err(|_| pkcs8::Error::KeyMalformed)?;
        Self::from_private_decrypting_key(key).map_err(|_| pkcs8::Error::KeyMalformed)
    }
}

impl pkcs8::EncodePrivateKey for RsaPrivateKey {
    fn to_pkcs8_der(&self) -> pkcs8::Result<pkcs8::SecretDocument> {
        pkcs8::SecretDocument::try_from(self.pkcs8_der.as_slice().to_vec())
            .map_err(|_| pkcs8::Error::KeyMalformed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Oaep {
    digest: OaepDigestAlgorithm,
    mgf_digest: OaepDigestAlgorithm,
    label: Option<String>,
}

impl Oaep {
    pub fn new<D: SelectOaepDigestAlgorithm>() -> Self {
        Self {
            digest: D::OAEP_DIGEST_ALGORITHM,
            mgf_digest: D::OAEP_DIGEST_ALGORITHM,
            label: None,
        }
    }

    pub fn new_with_label<D: SelectOaepDigestAlgorithm, S: AsRef<str>>(label: S) -> Self {
        Self {
            digest: D::OAEP_DIGEST_ALGORITHM,
            mgf_digest: D::OAEP_DIGEST_ALGORITHM,
            label: Some(label.as_ref().to_string()),
        }
    }

    pub fn new_with_mgf_hash<D: SelectOaepDigestAlgorithm, MGD: SelectOaepDigestAlgorithm>() -> Self
    {
        Self {
            digest: D::OAEP_DIGEST_ALGORITHM,
            mgf_digest: MGD::OAEP_DIGEST_ALGORITHM,
            label: None,
        }
    }

    pub fn new_with_mgf_hash_and_label<
        D: SelectOaepDigestAlgorithm,
        MGD: SelectOaepDigestAlgorithm,
        S: AsRef<str>,
    >(
        label: S,
    ) -> Self {
        Self {
            digest: D::OAEP_DIGEST_ALGORITHM,
            mgf_digest: MGD::OAEP_DIGEST_ALGORITHM,
            label: Some(label.as_ref().to_string()),
        }
    }

    fn algorithm(&self) -> errors::Result<&'static aws_rsa::OaepAlgorithm> {
        match (self.digest, self.mgf_digest) {
            (OaepDigestAlgorithm::Sha1, OaepDigestAlgorithm::Sha1) => {
                Ok(&aws_rsa::OAEP_SHA1_MGF1SHA1)
            }
            (OaepDigestAlgorithm::Sha256, OaepDigestAlgorithm::Sha256) => {
                Ok(&aws_rsa::OAEP_SHA256_MGF1SHA256)
            }
            (OaepDigestAlgorithm::Sha384, OaepDigestAlgorithm::Sha384) => {
                Ok(&aws_rsa::OAEP_SHA384_MGF1SHA384)
            }
            (OaepDigestAlgorithm::Sha512, OaepDigestAlgorithm::Sha512) => {
                Ok(&aws_rsa::OAEP_SHA512_MGF1SHA512)
            }
            _ => Err(errors::Error),
        }
    }

    fn label(&self) -> Option<&[u8]> {
        self.label.as_deref().map(str::as_bytes)
    }
}

impl Default for Oaep {
    fn default() -> Self {
        Self::new::<sha2::Sha256>()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OaepDigestAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlgorithm {
    fn pkcs1_signing_algorithm(self) -> &'static aws_signature::RsaSignatureEncoding {
        match self {
            Self::Sha256 => &aws_signature::RSA_PKCS1_SHA256,
            Self::Sha384 => &aws_signature::RSA_PKCS1_SHA384,
            Self::Sha512 => &aws_signature::RSA_PKCS1_SHA512,
        }
    }

    fn pkcs1_verification_algorithm(self) -> &'static aws_signature::RsaParameters {
        match self {
            Self::Sha256 => &aws_signature::RSA_PKCS1_2048_8192_SHA256,
            Self::Sha384 => &aws_signature::RSA_PKCS1_2048_8192_SHA384,
            Self::Sha512 => &aws_signature::RSA_PKCS1_2048_8192_SHA512,
        }
    }

    fn pss_signing_algorithm(self) -> &'static aws_signature::RsaSignatureEncoding {
        match self {
            Self::Sha256 => &aws_signature::RSA_PSS_SHA256,
            Self::Sha384 => &aws_signature::RSA_PSS_SHA384,
            Self::Sha512 => &aws_signature::RSA_PSS_SHA512,
        }
    }

    fn pss_verification_algorithm(self) -> &'static aws_signature::RsaParameters {
        match self {
            Self::Sha256 => &aws_signature::RSA_PSS_2048_8192_SHA256,
            Self::Sha384 => &aws_signature::RSA_PSS_2048_8192_SHA384,
            Self::Sha512 => &aws_signature::RSA_PSS_2048_8192_SHA512,
        }
    }

    fn aws_digest(self, hashed: &[u8]) -> errors::Result<digest::Digest> {
        let algorithm = match self {
            Self::Sha256 => &digest::SHA256,
            Self::Sha384 => &digest::SHA384,
            Self::Sha512 => &digest::SHA512,
        };
        digest::Digest::import_less_safe(hashed, algorithm).map_err(Into::into)
    }
}

pub trait SelectDigestAlgorithm {
    const DIGEST_ALGORITHM: DigestAlgorithm;
}

pub trait SelectOaepDigestAlgorithm {
    const OAEP_DIGEST_ALGORITHM: OaepDigestAlgorithm;
}

pub trait SelectSignatureAlgorithmIdentifier {
    const SIGNATURE_ALGORITHM_IDENTIFIER: spki::AlgorithmIdentifier<Null>;
}

impl SelectOaepDigestAlgorithm for sha1::Sha1 {
    const OAEP_DIGEST_ALGORITHM: OaepDigestAlgorithm = OaepDigestAlgorithm::Sha1;
}

impl SelectDigestAlgorithm for sha2::Sha256 {
    const DIGEST_ALGORITHM: DigestAlgorithm = DigestAlgorithm::Sha256;
}

impl SelectOaepDigestAlgorithm for sha2::Sha256 {
    const OAEP_DIGEST_ALGORITHM: OaepDigestAlgorithm = OaepDigestAlgorithm::Sha256;
}

impl SelectSignatureAlgorithmIdentifier for sha2::Sha256 {
    const SIGNATURE_ALGORITHM_IDENTIFIER: spki::AlgorithmIdentifier<Null> =
        spki::AlgorithmIdentifier {
            oid: spki::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
            parameters: Some(Null),
        };
}

impl SelectDigestAlgorithm for sha2::Sha384 {
    const DIGEST_ALGORITHM: DigestAlgorithm = DigestAlgorithm::Sha384;
}

impl SelectOaepDigestAlgorithm for sha2::Sha384 {
    const OAEP_DIGEST_ALGORITHM: OaepDigestAlgorithm = OaepDigestAlgorithm::Sha384;
}

impl SelectSignatureAlgorithmIdentifier for sha2::Sha384 {
    const SIGNATURE_ALGORITHM_IDENTIFIER: spki::AlgorithmIdentifier<Null> =
        spki::AlgorithmIdentifier {
            oid: spki::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12"),
            parameters: Some(Null),
        };
}

impl SelectDigestAlgorithm for sha2::Sha512 {
    const DIGEST_ALGORITHM: DigestAlgorithm = DigestAlgorithm::Sha512;
}

impl SelectOaepDigestAlgorithm for sha2::Sha512 {
    const OAEP_DIGEST_ALGORITHM: OaepDigestAlgorithm = OaepDigestAlgorithm::Sha512;
}

impl SelectSignatureAlgorithmIdentifier for sha2::Sha512 {
    const SIGNATURE_ALGORITHM_IDENTIFIER: spki::AlgorithmIdentifier<Null> =
        spki::AlgorithmIdentifier {
            oid: spki::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13"),
            parameters: Some(Null),
        };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pkcs1v15Sign {
    digest: DigestAlgorithm,
}

impl Pkcs1v15Sign {
    pub fn new<D: SelectDigestAlgorithm>() -> Self {
        Self {
            digest: D::DIGEST_ALGORITHM,
        }
    }
}

impl traits::SignatureScheme for Pkcs1v15Sign {
    fn sign<Rng>(
        self,
        _rng: Option<&mut Rng>,
        private_key: &RsaPrivateKey,
        hashed: &[u8],
    ) -> errors::Result<Vec<u8>> {
        let digest = self.digest.aws_digest(hashed)?;
        let pair = private_key.key_pair().map_err(|_| errors::Error)?;
        let mut signature = vec![0; pair.public_modulus_len()];
        pair.sign_digest(
            self.digest.pkcs1_signing_algorithm(),
            &digest,
            &mut signature,
        )?;
        Ok(signature)
    }

    fn verify(
        self,
        public_key: &RsaPublicKey,
        hashed: &[u8],
        signature: &[u8],
    ) -> errors::Result<()> {
        let digest = self.digest.aws_digest(hashed)?;
        aws_signature::UnparsedPublicKey::new(
            self.digest.pkcs1_verification_algorithm(),
            &public_key.pkcs1_der,
        )
        .verify_digest(&digest, signature)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pss {
    digest: DigestAlgorithm,
}

impl Pss {
    pub fn new<D: SelectDigestAlgorithm>() -> Self {
        Self {
            digest: D::DIGEST_ALGORITHM,
        }
    }

    pub fn new_with_salt<D: SelectDigestAlgorithm>(_salt_len: usize) -> Self {
        Self::new::<D>()
    }
}

impl traits::SignatureScheme for Pss {
    fn sign<Rng>(
        self,
        _rng: Option<&mut Rng>,
        private_key: &RsaPrivateKey,
        hashed: &[u8],
    ) -> errors::Result<Vec<u8>> {
        let digest = self.digest.aws_digest(hashed)?;
        let pair = private_key.key_pair().map_err(|_| errors::Error)?;
        let mut signature = vec![0; pair.public_modulus_len()];
        pair.sign_digest(self.digest.pss_signing_algorithm(), &digest, &mut signature)?;
        Ok(signature)
    }

    fn verify(
        self,
        public_key: &RsaPublicKey,
        hashed: &[u8],
        signature: &[u8],
    ) -> errors::Result<()> {
        let digest = self.digest.aws_digest(hashed)?;
        aws_signature::UnparsedPublicKey::new(
            self.digest.pss_verification_algorithm(),
            &public_key.pkcs1_der,
        )
        .verify_digest(&digest, signature)?;
        Ok(())
    }
}

pub mod pkcs1v15 {
    use super::*;

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Signature(Vec<u8>);

    impl AsRef<[u8]> for Signature {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl TryFrom<&[u8]> for Signature {
        type Error = signature_crate::Error;

        fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
            Ok(Self(value.to_vec()))
        }
    }

    impl TryFrom<Signature> for Vec<u8> {
        type Error = signature_crate::Error;

        fn try_from(value: Signature) -> std::result::Result<Self, Self::Error> {
            Ok(value.0)
        }
    }

    impl From<Signature> for Box<[u8]> {
        fn from(value: Signature) -> Self {
            value.0.into_boxed_slice()
        }
    }

    impl signature_crate::SignatureEncoding for Signature {
        type Repr = Vec<u8>;
    }

    #[derive(Clone, Debug)]
    pub struct VerifyingKey<D> {
        key: RsaPublicKey,
        _digest: PhantomData<D>,
    }

    impl<D> VerifyingKey<D> {
        pub fn new(key: RsaPublicKey) -> Self {
            Self {
                key,
                _digest: PhantomData,
            }
        }
    }

    impl<D> From<RsaPublicKey> for VerifyingKey<D> {
        fn from(key: RsaPublicKey) -> Self {
            Self::new(key)
        }
    }

    impl<D> AsRef<RsaPublicKey> for VerifyingKey<D> {
        fn as_ref(&self) -> &RsaPublicKey {
            &self.key
        }
    }

    impl<D> signature_crate::Verifier<Signature> for VerifyingKey<D>
    where
        D: SelectDigestAlgorithm,
    {
        fn verify(
            &self,
            msg: &[u8],
            signature: &Signature,
        ) -> std::result::Result<(), signature_crate::Error> {
            aws_signature::UnparsedPublicKey::new(
                D::DIGEST_ALGORITHM.pkcs1_verification_algorithm(),
                &self.key.pkcs1_der,
            )
            .verify(msg, signature.as_ref())
            .map_err(|_| signature_crate::Error::new())
        }
    }

    impl<D> signature_crate::DigestVerifier<D, Signature> for VerifyingKey<D>
    where
        D: signature_crate::digest::Digest + SelectDigestAlgorithm,
    {
        fn verify_digest(
            &self,
            digest: D,
            signature: &Signature,
        ) -> std::result::Result<(), signature_crate::Error> {
            let out = digest.finalize();
            let digest = D::DIGEST_ALGORITHM
                .aws_digest(out.as_ref())
                .map_err(|_| signature_crate::Error::new())?;
            aws_signature::UnparsedPublicKey::new(
                D::DIGEST_ALGORITHM.pkcs1_verification_algorithm(),
                &self.key.pkcs1_der,
            )
            .verify_digest(&digest, signature.as_ref())
            .map_err(|_| signature_crate::Error::new())
        }
    }

    impl<D> signature_crate::hazmat::PrehashVerifier<Signature> for VerifyingKey<D>
    where
        D: SelectDigestAlgorithm,
    {
        fn verify_prehash(
            &self,
            prehash: &[u8],
            signature: &Signature,
        ) -> std::result::Result<(), signature_crate::Error> {
            let digest = D::DIGEST_ALGORITHM
                .aws_digest(prehash)
                .map_err(|_| signature_crate::Error::new())?;
            aws_signature::UnparsedPublicKey::new(
                D::DIGEST_ALGORITHM.pkcs1_verification_algorithm(),
                &self.key.pkcs1_der,
            )
            .verify_digest(&digest, signature.as_ref())
            .map_err(|_| signature_crate::Error::new())
        }
    }

    impl<D> spki::EncodePublicKey for VerifyingKey<D> {
        fn to_public_key_der(&self) -> spki::Result<spki::der::Document> {
            self.key.to_public_key_der()
        }
    }

    impl<D> spki::SignatureAlgorithmIdentifier for VerifyingKey<D>
    where
        D: SelectSignatureAlgorithmIdentifier,
    {
        type Params = Null;

        const SIGNATURE_ALGORITHM_IDENTIFIER: spki::AlgorithmIdentifier<Self::Params> =
            D::SIGNATURE_ALGORITHM_IDENTIFIER;
    }

    #[derive(Clone, Debug)]
    pub struct SigningKey<D> {
        key: RsaPrivateKey,
        verifying_key: VerifyingKey<D>,
    }

    impl<D> SigningKey<D> {
        pub fn new(key: RsaPrivateKey) -> Self {
            let verifying_key = VerifyingKey::new(RsaPublicKey::from(&key));
            Self { key, verifying_key }
        }
    }

    impl<D> From<RsaPrivateKey> for SigningKey<D> {
        fn from(key: RsaPrivateKey) -> Self {
            Self::new(key)
        }
    }

    impl<D> AsRef<RsaPrivateKey> for SigningKey<D> {
        fn as_ref(&self) -> &RsaPrivateKey {
            &self.key
        }
    }

    impl<D: Clone> signature_crate::Keypair for SigningKey<D> {
        type VerifyingKey = VerifyingKey<D>;

        fn verifying_key(&self) -> Self::VerifyingKey {
            self.verifying_key.clone()
        }
    }

    impl<D> signature_crate::Signer<Signature> for SigningKey<D>
    where
        D: SelectDigestAlgorithm,
    {
        fn try_sign(&self, msg: &[u8]) -> std::result::Result<Signature, signature_crate::Error> {
            sign_message::<D>(&self.key, msg)
        }
    }

    impl<D> signature_crate::RandomizedSigner<Signature> for SigningKey<D>
    where
        D: SelectDigestAlgorithm,
    {
        fn try_sign_with_rng(
            &self,
            _rng: &mut impl signature_crate::rand_core::CryptoRngCore,
            msg: &[u8],
        ) -> std::result::Result<Signature, signature_crate::Error> {
            sign_message::<D>(&self.key, msg)
        }
    }

    impl<D> signature_crate::DigestSigner<D, Signature> for SigningKey<D>
    where
        D: signature_crate::digest::Digest + SelectDigestAlgorithm,
    {
        fn try_sign_digest(
            &self,
            digest: D,
        ) -> std::result::Result<Signature, signature_crate::Error> {
            let out = digest.finalize();
            let digest = D::DIGEST_ALGORITHM
                .aws_digest(out.as_ref())
                .map_err(|_| signature_crate::Error::new())?;
            let pair = self
                .key
                .key_pair()
                .map_err(|_| signature_crate::Error::new())?;
            let mut signature = vec![0; pair.public_modulus_len()];
            pair.sign_digest(
                D::DIGEST_ALGORITHM.pkcs1_signing_algorithm(),
                &digest,
                &mut signature,
            )
            .map_err(|_| signature_crate::Error::new())?;
            Ok(Signature(signature))
        }
    }

    impl spki::SignatureBitStringEncoding for Signature {
        fn to_bitstring(&self) -> der::Result<BitString> {
            BitString::from_bytes(&self.0)
        }
    }

    fn sign_message<D: SelectDigestAlgorithm>(
        key: &RsaPrivateKey,
        msg: &[u8],
    ) -> std::result::Result<Signature, signature_crate::Error> {
        let pair = key.key_pair().map_err(|_| signature_crate::Error::new())?;
        let rng = SystemRandom::new();
        let mut signature = vec![0; pair.public_modulus_len()];
        pair.sign(
            D::DIGEST_ALGORITHM.pkcs1_signing_algorithm(),
            &rng,
            msg,
            &mut signature,
        )
        .map_err(|_| signature_crate::Error::new())?;
        Ok(Signature(signature))
    }
}

impl spki::EncodePublicKey for RsaPublicKey {
    fn to_public_key_der(&self) -> spki::Result<spki::der::Document> {
        let key = self
            .encrypting_key()
            .map_err(|_| spki::Error::KeyMalformed)?;
        let der = AsDer::<PublicKeyX509Der<'static>>::as_der(&key)
            .map_err(|_| spki::Error::KeyMalformed)?;
        spki::der::Document::try_from(der.as_ref()).map_err(spki::Error::from)
    }
}

fn encode_pkcs1_public_key(n: &BigUint, e: &BigUint) -> pkcs1_crate::Result<Vec<u8>> {
    let n = n.to_bytes_be();
    let e = e.to_bytes_be();
    let key = pkcs1_crate::RsaPublicKey {
        modulus: pkcs1_crate::UintRef::new(&n)?,
        public_exponent: pkcs1_crate::UintRef::new(&e)?,
    };
    Ok(key.to_der()?)
}

#[cfg(test)]
mod tests {
    use super::traits::PublicKeyParts;
    use super::*;
    use sha2::Digest as _;
    use signature_crate::hazmat::PrehashVerifier;
    use signature_crate::{DigestSigner, DigestVerifier, Keypair, Signer, Verifier};

    fn test_key() -> RsaPrivateKey {
        let mut rng = SystemRandom::new();
        RsaPrivateKey::new(&mut rng, 2048).unwrap()
    }

    fn hash<D: sha2::Digest>(msg: &[u8]) -> Vec<u8> {
        D::digest(msg).to_vec()
    }

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn private_key_advertises_zeroize_on_drop() {
        assert_zeroize_on_drop::<RsaPrivateKey>();
    }

    #[test]
    fn pkcs1v15_signs_and_verifies_with_each_supported_digest() {
        let key = test_key();
        let msg = b"digest-specific pkcs1v15 signing";

        let sha256_key = pkcs1v15::SigningKey::<sha2::Sha256>::new(key.clone());
        let sha256_sig = sha256_key.sign(msg);
        sha256_key.verifying_key().verify(msg, &sha256_sig).unwrap();

        let sha384_key = pkcs1v15::SigningKey::<sha2::Sha384>::new(key.clone());
        let sha384_sig = sha384_key.sign(msg);
        sha384_key.verifying_key().verify(msg, &sha384_sig).unwrap();

        let sha512_key = pkcs1v15::SigningKey::<sha2::Sha512>::new(key);
        let sha512_sig = sha512_key.sign(msg);
        sha512_key.verifying_key().verify(msg, &sha512_sig).unwrap();
    }

    #[test]
    fn pkcs1v15_rejects_cross_digest_verification() {
        let key = test_key();
        let msg = b"cross digest mismatch";
        let signing_key = pkcs1v15::SigningKey::<sha2::Sha384>::new(key.clone());
        let signature = signing_key.sign(msg);
        let verifying_key = pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key.to_public_key());

        assert!(verifying_key.verify(msg, &signature).is_err());
    }

    #[test]
    fn pkcs1v15_digest_and_prehash_verifiers_use_selected_digest() {
        let key = test_key();
        let msg = b"prehashed pkcs1v15 signing";
        let signing_key = pkcs1v15::SigningKey::<sha2::Sha384>::new(key);
        let verifying_key = signing_key.verifying_key();

        let mut signing_digest = sha2::Sha384::new();
        signing_digest.update(msg);
        let signature = signing_key.sign_digest(signing_digest);

        let mut verifying_digest = sha2::Sha384::new();
        verifying_digest.update(msg);
        verifying_key
            .verify_digest(verifying_digest, &signature)
            .unwrap();

        let prehash = sha2::Sha384::digest(msg);
        verifying_key
            .verify_prehash(prehash.as_ref(), &signature)
            .unwrap();
    }

    #[test]
    fn pkcs1v15_signature_algorithm_oids_match_digest() {
        let sha256 =
            <pkcs1v15::VerifyingKey<sha2::Sha256> as spki::SignatureAlgorithmIdentifier>::SIGNATURE_ALGORITHM_IDENTIFIER;
        let sha384 =
            <pkcs1v15::VerifyingKey<sha2::Sha384> as spki::SignatureAlgorithmIdentifier>::SIGNATURE_ALGORITHM_IDENTIFIER;
        let sha512 =
            <pkcs1v15::VerifyingKey<sha2::Sha512> as spki::SignatureAlgorithmIdentifier>::SIGNATURE_ALGORITHM_IDENTIFIER;

        assert_eq!(sha256.oid.to_string(), "1.2.840.113549.1.1.11");
        assert_eq!(sha384.oid.to_string(), "1.2.840.113549.1.1.12");
        assert_eq!(sha512.oid.to_string(), "1.2.840.113549.1.1.13");
    }

    #[test]
    fn top_level_pkcs1v15_signatures_round_trip_with_each_supported_digest() {
        let key = test_key();
        let public_key = key.to_public_key();
        let mut rng = SystemRandom::new();
        let msg = b"top-level pkcs1v15 signing";

        let hashed = hash::<sha2::Sha256>(msg);
        let signature = key
            .sign_with_rng(&mut rng, Pkcs1v15Sign::new::<sha2::Sha256>(), &hashed)
            .unwrap();
        public_key
            .verify(Pkcs1v15Sign::new::<sha2::Sha256>(), &hashed, &signature)
            .unwrap();

        let hashed = hash::<sha2::Sha384>(msg);
        let signature = key
            .sign_with_rng(&mut rng, Pkcs1v15Sign::new::<sha2::Sha384>(), &hashed)
            .unwrap();
        public_key
            .verify(Pkcs1v15Sign::new::<sha2::Sha384>(), &hashed, &signature)
            .unwrap();

        let hashed = hash::<sha2::Sha512>(msg);
        let signature = key
            .sign_with_rng(&mut rng, Pkcs1v15Sign::new::<sha2::Sha512>(), &hashed)
            .unwrap();
        public_key
            .verify(Pkcs1v15Sign::new::<sha2::Sha512>(), &hashed, &signature)
            .unwrap();
    }

    #[test]
    fn top_level_pss_signatures_round_trip_with_each_supported_digest() {
        let key = test_key();
        let public_key = key.to_public_key();
        let mut rng = SystemRandom::new();
        let msg = b"top-level pss signing";

        let hashed = hash::<sha2::Sha256>(msg);
        let signature = key
            .sign_with_rng(&mut rng, Pss::new::<sha2::Sha256>(), &hashed)
            .unwrap();
        public_key
            .verify(Pss::new::<sha2::Sha256>(), &hashed, &signature)
            .unwrap();

        let hashed = hash::<sha2::Sha384>(msg);
        let signature = key
            .sign_with_rng(&mut rng, Pss::new::<sha2::Sha384>(), &hashed)
            .unwrap();
        public_key
            .verify(Pss::new::<sha2::Sha384>(), &hashed, &signature)
            .unwrap();

        let hashed = hash::<sha2::Sha512>(msg);
        let signature = key
            .sign_with_rng(&mut rng, Pss::new::<sha2::Sha512>(), &hashed)
            .unwrap();
        public_key
            .verify(Pss::new::<sha2::Sha512>(), &hashed, &signature)
            .unwrap();
    }

    #[test]
    fn oaep_round_trips_with_supported_digests_and_label() {
        let key = test_key();
        let public_key = key.to_public_key();
        let mut rng = SystemRandom::new();
        let msg = b"oaep payload";

        let ciphertext = public_key
            .encrypt(&mut rng, Oaep::new::<sha1::Sha1>(), msg)
            .unwrap();
        assert_eq!(
            key.decrypt(Oaep::new::<sha1::Sha1>(), &ciphertext).unwrap(),
            msg
        );

        let ciphertext = public_key
            .encrypt(&mut rng, Oaep::new::<sha2::Sha256>(), msg)
            .unwrap();
        assert_eq!(
            key.decrypt(Oaep::new::<sha2::Sha256>(), &ciphertext)
                .unwrap(),
            msg
        );

        let ciphertext = public_key
            .encrypt(&mut rng, Oaep::new::<sha2::Sha384>(), msg)
            .unwrap();
        assert_eq!(
            key.decrypt(Oaep::new::<sha2::Sha384>(), &ciphertext)
                .unwrap(),
            msg
        );

        let ciphertext = public_key
            .encrypt(
                &mut rng,
                Oaep::new_with_label::<sha2::Sha512, _>("label"),
                msg,
            )
            .unwrap();
        assert_eq!(
            key.decrypt(
                Oaep::new_with_label::<sha2::Sha512, _>("label"),
                &ciphertext
            )
            .unwrap(),
            msg
        );
        assert!(key
            .decrypt(
                Oaep::new_with_label::<sha2::Sha512, _>("different-label"),
                &ciphertext
            )
            .is_err());
    }

    #[test]
    fn oaep_rejects_mixed_mgf_digest() {
        let key = test_key();
        let public_key = key.to_public_key();
        let mut rng = SystemRandom::new();

        assert!(public_key
            .encrypt(
                &mut rng,
                Oaep::new_with_mgf_hash::<sha2::Sha256, sha2::Sha384>(),
                b"payload",
            )
            .is_err());
    }

    #[test]
    fn pkcs1_private_key_export_round_trips_public_components() {
        let key = test_key();
        let pkcs1_der = pkcs1_crate::EncodeRsaPrivateKey::to_pkcs1_der(&key).unwrap();
        let imported = <RsaPrivateKey as pkcs1_crate::DecodeRsaPrivateKey>::from_pkcs1_der(
            pkcs1_der.as_bytes(),
        )
        .unwrap();

        assert_eq!(key.n(), imported.n());
        assert_eq!(key.e(), imported.e());
    }

    #[test]
    fn pkcs1_private_key_pem_round_trips_public_components() {
        let key = test_key();
        let pkcs1_pem =
            pkcs1_crate::EncodeRsaPrivateKey::to_pkcs1_pem(&key, pkcs1_crate::LineEnding::LF)
                .unwrap();
        let imported =
            <RsaPrivateKey as pkcs1_crate::DecodeRsaPrivateKey>::from_pkcs1_pem(&pkcs1_pem)
                .unwrap();

        assert_eq!(key.n(), imported.n());
        assert_eq!(key.e(), imported.e());
    }

    #[test]
    fn pkcs8_private_key_der_and_pem_round_trip_public_components() {
        let key = test_key();

        let pkcs8_der = pkcs8::EncodePrivateKey::to_pkcs8_der(&key).unwrap();
        let imported =
            <RsaPrivateKey as pkcs8::DecodePrivateKey>::from_pkcs8_der(pkcs8_der.as_bytes())
                .unwrap();
        assert_eq!(key.n(), imported.n());
        assert_eq!(key.e(), imported.e());

        let pkcs8_pem = pkcs8::EncodePrivateKey::to_pkcs8_pem(&key, pkcs8::LineEnding::LF).unwrap();
        let imported =
            <RsaPrivateKey as pkcs8::DecodePrivateKey>::from_pkcs8_pem(&pkcs8_pem).unwrap();
        assert_eq!(key.n(), imported.n());
        assert_eq!(key.e(), imported.e());
    }

    #[test]
    fn zero_bit_key_generation_is_rejected() {
        let mut rng = SystemRandom::new();
        assert!(RsaPrivateKey::new(&mut rng, 0).is_err());
    }
}
