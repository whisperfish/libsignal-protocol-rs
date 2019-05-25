use crate::{
    crypto::{Crypto, Sha256Hmac, Sha512Digest, SignalCipherType},
    errors::InternalError,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

/// Cryptography routines using native Rust crates.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct DefaultCrypto;

#[cfg(feature = "crypto-native")]
impl Crypto for DefaultCrypto {
    fn fill_random(&self, buffer: &mut [u8]) -> Result<(), InternalError> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        rng.fill_bytes(buffer);
        Ok(())
    }

    fn hmac_sha256(
        &self,
        key: &[u8],
    ) -> Result<Box<dyn Sha256Hmac>, InternalError> {
        let mac =
            HmacSha256::new_varkey(key).map_err(|_| InternalError::Unknown)?;
        Ok(Box::new(mac))
    }

    fn sha512_digest(&self) -> Result<Box<dyn Sha512Digest>, InternalError> {
        Ok(Box::new(Sha512::new()))
    }

    fn encrypt(
        &self,
        _cipher: SignalCipherType,
        _key: &[u8],
        _iv: &[u8],
        _data: &[u8],
    ) -> Result<Vec<u8>, InternalError> {
        unimplemented!()
    }

    fn decrypt(
        &self,
        _cipher: SignalCipherType,
        _key: &[u8],
        _iv: &[u8],
        _data: &[u8],
    ) -> Result<Vec<u8>, InternalError> {
        unimplemented!()
    }
}

#[cfg(feature = "crypto-native")]
impl Default for DefaultCrypto {
    fn default() -> Self { Self }
}

#[cfg(feature = "crypto-native")]
impl Sha512Digest for Sha512 {
    fn update(&mut self, data: &[u8]) -> Result<(), InternalError> {
        self.input(data);
        Ok(())
    }

    fn finalize(&mut self) -> Result<Vec<u8>, InternalError> {
        let result = self.result_reset();
        Ok(result.to_vec())
    }
}

#[cfg(feature = "crypto-native")]
impl Sha256Hmac for HmacSha256 {
    fn update(&mut self, data: &[u8]) -> Result<(), InternalError> {
        self.input(data);
        Ok(())
    }

    fn finalize(&mut self) -> Result<Vec<u8>, InternalError> {
        let result = self.result_reset().code();
        Ok(result.to_vec())
    }
}
