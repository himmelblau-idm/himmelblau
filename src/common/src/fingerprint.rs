//! Authenticator-secret protected Hello PIN envelopes. Outer HSM sealing belongs
//! to the caller; an HSM alone must never supply the key used here.
use crate::secret_memory::SecretBuffer;
use openssl::{
    md::Md,
    pkey::Id,
    pkey_ctx::PkeyCtx,
    rand::rand_bytes,
    symm::{Cipher, Crypter, Mode},
};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintBinding {
    pub account_id: String,
    pub credential_id: Vec<u8>,
    pub installation_id: String,
    pub hello_generation: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FingerprintEnvelope {
    version: u8,
    binding: FingerprintBinding,
    salt: [u8; 32],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    tag: [u8; 16],
}

#[derive(Debug)]
pub enum FingerprintError {
    InvalidInput,
    Cryptography,
    SecureMemory(std::io::Error),
}
impl fmt::Display for FingerprintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid fingerprint envelope binding or secret",
            Self::Cryptography => "fingerprint envelope cryptography failed",
            Self::SecureMemory(_) => "secure memory allocation failed",
        })
    }
}
impl Error for FingerprintError {}
impl From<openssl::error::ErrorStack> for FingerprintError {
    fn from(_: openssl::error::ErrorStack) -> Self {
        Self::Cryptography
    }
}
impl From<std::io::Error> for FingerprintError {
    fn from(error: std::io::Error) -> Self {
        Self::SecureMemory(error)
    }
}

impl FingerprintEnvelope {
    fn aad(&self) -> Result<Vec<u8>, FingerprintError> {
        serde_cbor::to_vec(&(
            "himmelblau-hello-fingerprint",
            self.version,
            &self.binding,
            self.salt,
        ))
        .map_err(|_| FingerprintError::InvalidInput)
    }
    fn key(&self, hmac_secret: &[u8], aad: &[u8]) -> Result<SecretBuffer, FingerprintError> {
        if hmac_secret.len() != 32 {
            return Err(FingerprintError::InvalidInput);
        }
        let mut key = SecretBuffer::new(32)?;
        // OpenSSL owns and clears the HKDF intermediate key/context on free.
        let mut context = PkeyCtx::new_id(Id::HKDF)?;
        context.derive_init()?;
        context.set_hkdf_md(Md::sha256())?;
        context.set_hkdf_salt(&self.salt)?;
        context.set_hkdf_key(hmac_secret)?;
        context.add_hkdf_info(aad)?;
        context.derive(Some(key.as_mut_slice()))?;
        Ok(key)
    }
    pub fn encrypt(
        pin: &[u8],
        hmac_secret: &[u8],
        binding: &FingerprintBinding,
    ) -> Result<Self, FingerprintError> {
        if pin.is_empty()
            || pin.len() > 1024
            || binding.account_id.is_empty()
            || binding.credential_id.is_empty()
            || binding.installation_id.is_empty()
            || binding.hello_generation.is_empty()
        {
            return Err(FingerprintError::InvalidInput);
        }
        let mut envelope = Self {
            version: 1,
            binding: binding.clone(),
            salt: [0; 32],
            nonce: [0; 12],
            ciphertext: vec![0; pin.len() + 16],
            tag: [0; 16],
        };
        rand_bytes(&mut envelope.salt)?;
        rand_bytes(&mut envelope.nonce)?;
        let aad = envelope.aad()?;
        let key = envelope.key(hmac_secret, &aad)?;
        let mut cipher = Crypter::new(
            Cipher::aes_256_gcm(),
            Mode::Encrypt,
            key.as_slice(),
            Some(&envelope.nonce),
        )?;
        cipher.aad_update(&aad)?;
        let count = cipher.update(pin, &mut envelope.ciphertext)?;
        let tail = cipher.finalize(&mut envelope.ciphertext[count..])?;
        envelope.ciphertext.truncate(count + tail);
        cipher.get_tag(&mut envelope.tag)?;
        Ok(envelope)
    }
    pub fn decrypt(
        &self,
        hmac_secret: &[u8],
        expected_binding: &FingerprintBinding,
    ) -> Result<SecretBuffer, FingerprintError> {
        if self.version != 1
            || &self.binding != expected_binding
            || self.ciphertext.is_empty()
            || self.ciphertext.len() > 1024
        {
            return Err(FingerprintError::InvalidInput);
        }
        let aad = self.aad()?;
        let key = self.key(hmac_secret, &aad)?;
        let mut plaintext = SecretBuffer::new(self.ciphertext.len() + 16)?;
        let mut cipher = Crypter::new(
            Cipher::aes_256_gcm(),
            Mode::Decrypt,
            key.as_slice(),
            Some(&self.nonce),
        )?;
        cipher.aad_update(&aad)?;
        cipher.set_tag(&self.tag)?;
        let count = cipher.update(&self.ciphertext, plaintext.as_mut_slice())?;
        let tail = cipher.finalize(&mut plaintext.as_mut_slice()[count..])?;
        // Keep the output allocation exact; the temporary remains locked and is wiped.
        Ok(SecretBuffer::from_slice(
            &plaintext.as_slice()[..count + tail],
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn envelope_security_properties() -> Result<(), Box<dyn Error>> {
        let binding = FingerprintBinding {
            account_id: "user".into(),
            credential_id: vec![1, 2],
            installation_id: "machine".into(),
            hello_generation: "generation".into(),
        };
        let mut envelope = FingerprintEnvelope::encrypt(b"123456", &[42; 32], &binding)?;
        assert_eq!(envelope.decrypt(&[42; 32], &binding)?.as_slice(), b"123456");
        assert!(envelope.decrypt(&[43; 32], &binding).is_err());
        assert!(envelope.decrypt(&[42; 31], &binding).is_err());
        let other = FingerprintEnvelope::encrypt(b"123456", &[42; 32], &binding)?;
        assert_ne!(envelope.nonce, other.nonce);
        assert_ne!(envelope.ciphertext, other.ciphertext);
        let mut altered = binding.clone();
        altered.hello_generation = "new".into();
        assert!(envelope.decrypt(&[42; 32], &altered).is_err());
        envelope.binding = altered.clone();
        assert!(envelope.decrypt(&[42; 32], &altered).is_err());
        envelope.binding = binding.clone();
        envelope.ciphertext[0] ^= 1;
        assert!(envelope.decrypt(&[42; 32], &binding).is_err());
        let serialized = serde_json::to_string(&envelope)?;
        assert!(!serialized.contains("123456"));
        Ok(())
    }
}
