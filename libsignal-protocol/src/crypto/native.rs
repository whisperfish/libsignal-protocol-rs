use aes::{Aes128, Aes192, Aes256};
use aes_ctr::{
    Aes128Ctr,
    Aes192Ctr, Aes256Ctr, stream_cipher::{NewStreamCipher, SyncStreamCipher},
};
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

use crate::{
    crypto::{Crypto, Sha256Hmac, Sha512Digest, SignalCipherType},
    errors::InternalError,
};

// FWI, PKCS5 padding is a subset of PKCS7
type Aes128Cbc = Cbc<Aes128, Pkcs7>;
type Aes192Cbc = Cbc<Aes192, Pkcs7>;
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

#[derive(Copy, Clone, Ord, PartialOrd, PartialEq, Eq)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

/// Cryptography routines using native Rust crates.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct DefaultCrypto;

impl DefaultCrypto {
    fn crypter(
        &self,
        mode: Mode,
        cipher: SignalCipherType,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, InternalError> {
        let result = match (cipher, key.len()) {
            (SignalCipherType::AesCtrNoPadding, 16) => {
                let mut buf = data.to_vec();
                // a side note here is that Ctr mode takes a nonce as 2nd param,
                // not an IV but if we for example use a
                // randomly nonce generated every call, it would fail
                // i mean by fail here, fail in decryption the cipher text
                // created by the same key. so i think it's not
                // not meant to be nonce here, but just an IV.
                // and now it works same as the openssl
                let mut c = Aes128Ctr::new_var(key, iv)
                    .map_err(|_| InternalError::Unknown)?;
                c.apply_keystream(&mut buf);
                buf
            },
            (SignalCipherType::AesCtrNoPadding, 24) => {
                let mut buf = data.to_vec();
                let mut c = Aes192Ctr::new_var(key, iv)
                    .map_err(|_| InternalError::Unknown)?;
                c.apply_keystream(&mut buf);
                buf
            },
            (SignalCipherType::AesCtrNoPadding, 32) => {
                let mut buf = data.to_vec();
                let mut c = Aes256Ctr::new_var(key, iv)
                    .map_err(|_| InternalError::Unknown)?;
                c.apply_keystream(&mut buf);
                buf
            },
            (SignalCipherType::AesCbcPkcs5, 16) => {
                let c = Aes128Cbc::new_var(&key, &iv)
                    .map_err(|_| InternalError::Unknown)?;
                let buf = match mode {
                    Mode::Encrypt => c.encrypt_vec(data),
                    Mode::Decrypt => c
                        .decrypt_vec(data)
                        .map_err(|_| InternalError::Unknown)?,
                };
                buf
            },
            (SignalCipherType::AesCbcPkcs5, 24) => {
                let c = Aes192Cbc::new_var(&key, &iv)
                    .map_err(|_| InternalError::Unknown)?;
                let buf = match mode {
                    Mode::Encrypt => c.encrypt_vec(data),
                    Mode::Decrypt => c
                        .decrypt_vec(data)
                        .map_err(|_| InternalError::Unknown)?,
                };
                buf
            },
            (SignalCipherType::AesCbcPkcs5, 32) => {
                let c = Aes256Cbc::new_var(&key, &iv)
                    .map_err(|_| InternalError::Unknown)?;
                let buf = match mode {
                    Mode::Encrypt => c.encrypt_vec(data),
                    Mode::Decrypt => c
                        .decrypt_vec(data)
                        .map_err(|_| InternalError::Unknown)?,
                };
                buf
            },
            _ => unreachable!(),
        };
        Ok(result)
    }
}

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
        cipher: SignalCipherType,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, InternalError> {
        self.crypter(Mode::Encrypt, cipher, key, iv, data)
    }

    fn decrypt(
        &self,
        cipher: SignalCipherType,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, InternalError> {
        self.crypter(Mode::Decrypt, cipher, key, iv, data)
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
