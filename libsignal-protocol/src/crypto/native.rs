use crate::{
    crypto::{Crypto, Sha256Hmac, Sha512Digest, SignalCipherType},
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

    fn hmac_sha256(
        &self,
        key: &[u8],
    ) -> Result<Box<dyn Sha256Hmac>, InternalError> {
        unimplemented!()
    }

    fn sha512_digest(&self) -> Result<Box<dyn Sha512Digest>, InternalError> {
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
