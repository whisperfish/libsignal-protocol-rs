use openssl::{
    hash::{Hasher, MessageDigest},
    nid::Nid,
    symm::{Cipher, Crypter, Mode},
};

use crate::{
    crypto::{Crypto, Sha256Hmac, Sha512Digest, SignalCipherType},
    errors::InternalError,
};

/// Cryptography routines built on top of the system's `openssl` library.
#[derive(Debug, Copy, Clone)]
pub struct OpenSSLCrypto;

impl OpenSSLCrypto {
    fn crypter(
        &self,
        mode: Mode,
        cipher: SignalCipherType,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, InternalError> {
        let signal_cipher_type = match (cipher, key.len()) {
            (SignalCipherType::AesCtrNoPadding, 16) => Cipher::aes_128_ctr(),
            (SignalCipherType::AesCtrNoPadding, 24) => {
                let nid = Nid::AES_192_CTR;
                Cipher::from_nid(nid)
                    .expect("OpenSSL should have AES_192_CTR !!")
            },
            (SignalCipherType::AesCtrNoPadding, 32) => Cipher::aes_256_ctr(),
            (SignalCipherType::AesCbcPkcs5, 16) => Cipher::aes_128_cbc(),
            (SignalCipherType::AesCbcPkcs5, 24) => {
                let nid = Nid::AES_192_CBC;
                Cipher::from_nid(nid)
                    .expect("OpenSSL should have AES_192_CBC !!")
            },
            (SignalCipherType::AesCbcPkcs5, 32) => Cipher::aes_256_cbc(),
            _ => unreachable!(),
        };
        let block_size = signal_cipher_type.block_size();
        // turns out that we have to fill the buffer with some initial value
        // to pass it to the openssl library.
        // also it depends on the mode, in the AesCtr (aka stream cipher) mode
        // we had to provide the same exact size as the input.
        // in the AesCbs, the buffer should be `data.len() + blocks_ize`
        // but there is a small problem here, that the returned value **the result buffer**
        // has a `data.len()` 0's tail at the end of the buffer !
        // for example, if the `data = [1, 2, 3, 4]`
        // the native (aka DefaultCrypto) will result for example
        // [70, 108, 98, 83, 33, 54, 241, 25, 86, 110, 44, 34, 228, 183, 215, 251]
        // and the openssl (aka OpenSSLCrypto) will result
        // [70, 108, 98, 83, 33, 54, 241, 25, 86, 110, 44, 34, 228, 183, 215, 251, 0, 0, 0, 0]
        // note the [..., 0, 0, 0, 0] at the end, it always has the same len of the input `data`.
        // see `test_crypter` unit test in the [`./crypto/mod.rs`]
        //
        // FIXME (@shekohex): Find why openssl has that behavior
        let mut result = match cipher {
            SignalCipherType::AesCtrNoPadding => vec![0u8; data.len()],
            SignalCipherType::AesCbcPkcs5 => vec![0u8; data.len() + block_size],
        };
        let mut crypter = Crypter::new(signal_cipher_type, mode, key, Some(iv))
            .map_err(|_e| InternalError::Unknown)?;
        crypter
            .update(data, &mut result)
            .map_err(|_e| InternalError::Unknown)?;

        crypter
            .finalize(&mut result)
            .map_err(|_e| InternalError::Unknown)?;
        Ok(result)
    }
}

impl Crypto for OpenSSLCrypto {
    fn fill_random(&self, buffer: &mut [u8]) -> Result<(), InternalError> {
        openssl::rand::rand_bytes(buffer).map_err(|_e| InternalError::Unknown)
    }

    fn hmac_sha256(
        &self,
        _key: &[u8],
    ) -> Result<Box<dyn Sha256Hmac>, InternalError> {
        let nid = Nid::HMACWITHSHA256;
        let ty = MessageDigest::from_nid(nid)
            .ok_or_else(|| InternalError::Unknown)?;
        let hasher = Hasher::new(ty).map_err(|_e| InternalError::Unknown)?;

        Ok(Box::new(hasher))
    }

    fn sha512_digest(&self) -> Result<Box<dyn Sha512Digest>, InternalError> {
        let ty = MessageDigest::sha512();
        let hasher = Hasher::new(ty).map_err(|_e| InternalError::Unknown)?;

        Ok(Box::new(hasher))
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

impl Default for OpenSSLCrypto {
    fn default() -> OpenSSLCrypto { OpenSSLCrypto }
}

impl Sha256Hmac for Hasher {
    fn update(&mut self, data: &[u8]) -> Result<(), InternalError> {
        self.update(data).map_err(|_| InternalError::Unknown)
    }

    fn finalize(&mut self) -> Result<Vec<u8>, InternalError> {
        self.finish()
            .map(|bytes| bytes.as_ref().to_vec())
            .map_err(|_| InternalError::Unknown)
    }
}

impl Sha512Digest for Hasher {
    fn update(&mut self, data: &[u8]) -> Result<(), InternalError> {
        self.update(data).map_err(|_| InternalError::Unknown)
    }

    fn finalize(&mut self) -> Result<Vec<u8>, InternalError> {
        self.finish()
            .map(|bytes| bytes.as_ref().to_vec())
            .map_err(|_| InternalError::Unknown)
    }
}
