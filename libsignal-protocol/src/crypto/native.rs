use crate::{
    crypto::{Crypto, SignalCipherType},
    errors::InternalError,
};

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

    fn hmac_sha256_init(&self, _key: &[u8]) -> Result<(), InternalError> {
        unimplemented!()
    }

    fn hmac_sha256_update(&self, _data: &[u8]) -> Result<(), InternalError> {
        unimplemented!()
    }

    fn hmac_sha256_final(&self) -> Result<Vec<u8>, InternalError> {
        unimplemented!()
    }

    fn sha512_digest_init(&self) -> Result<(), InternalError> {
        unimplemented!()
    }

    fn sha512_digest_update(&self, _data: &[u8]) -> Result<(), InternalError> {
        unimplemented!()
    }

    fn sha512_digest_final(&self) -> Result<Vec<u8>, InternalError> {
        unimplemented!()
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
