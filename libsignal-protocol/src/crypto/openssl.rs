use crate::crypto::{Crypto, SignalCipherType::*};
use openssl::{
    hash::{Hasher, MessageDigest},
    nid::Nid,
    symm::{Cipher, Crypter, Mode},
};

pub struct OpenSSLCrypto {
    hmac_ctx: Mutex<Option<Hasher>>,
    sha512_ctx: Mutex<Option<Hasher>>,
}

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
            (AesCtrNoPadding, 16) => Cipher::aes_128_ctr(),
            (AesCtrNoPadding, 24) => {
                let nid = Nid::AES_192_CTR;
                Cipher::from_nid(nid)
                    .expect("OpenSSL should have AES_192_CTR !!")
            },
            (AesCtrNoPadding, 32) => Cipher::aes_256_ctr(),
            (AesCbcPkcs5, 16) => Cipher::aes_128_cbc(),
            (AesCbcPkcs5, 24) => {
                let nid = Nid::AES_192_CBC;
                Cipher::from_nid(nid)
                    .expect("OpenSSL should have AES_192_CBC !!")
            },
            (AesCbcPkcs5, 32) => Cipher::aes_256_cbc(),
            _ => unreachable!(),
        };
        let block_size = signal_cipher_type.block_size();
        let mut result = Vec::with_capacity(data.len() + block_size);
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

    fn hmac_sha256_init(&self, _key: &[u8]) -> Result<(), InternalError> {
        let nid = Nid::HMACWITHSHA256;
        let ty = MessageDigest::from_nid(nid)
            .ok_or_else(|| InternalError::Unknown)?;
        let ctx = Hasher::new(ty).map_err(|_e| InternalError::Unknown)?;
        let mut guard =
            self.hmac_ctx.lock().map_err(|_e| InternalError::Unknown)?;
        *guard = Some(ctx);
        Ok(())
    }

    fn hmac_sha256_update(&self, data: &[u8]) -> Result<(), InternalError> {
        let mut guard =
            self.hmac_ctx.lock().map_err(|_e| InternalError::Unknown)?;
        if let Some(ref mut ctx) = *guard {
            ctx.update(data).map_err(|_e| InternalError::Unknown)?;
        }
        Ok(())
    }

    fn hmac_sha256_final(&self) -> Result<Vec<u8>, InternalError> {
        let mut guard =
            self.hmac_ctx.lock().map_err(|_e| InternalError::Unknown)?;
        if let Some(ref mut ctx) = *guard {
            ctx.finish()
                .map(|buf| buf.as_ref().to_owned())
                .map_err(|_e| InternalError::Unknown)
        } else {
            Err(InternalError::Unknown)
        }
    }

    fn sha512_digest_init(&self) -> Result<(), InternalError> {
        let ty = MessageDigest::sha512();
        let ctx = Hasher::new(ty).map_err(|_e| InternalError::Unknown)?;
        let mut guard = self
            .sha512_ctx
            .lock()
            .map_err(|_e| InternalError::Unknown)?;
        *guard = Some(ctx);
        Ok(())
    }

    fn sha512_digest_update(&self, data: &[u8]) -> Result<(), InternalError> {
        let mut guard = self
            .sha512_ctx
            .lock()
            .map_err(|_e| InternalError::Unknown)?;
        if let Some(ref mut ctx) = *guard {
            ctx.update(data).map_err(|_e| InternalError::Unknown)?;
        }
        Ok(())
    }

    fn sha512_digest_final(&self) -> Result<Vec<u8>, InternalError> {
        let mut guard = self
            .sha512_ctx
            .lock()
            .map_err(|_e| InternalError::Unknown)?;
        if let Some(ref mut ctx) = *guard {
            ctx.finish()
                .map(|buf| buf.as_ref().to_owned())
                .map_err(|_e| InternalError::Unknown)
        } else {
            Err(InternalError::Unknown)
        }
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
    fn default() -> Self {
        Self {
            hmac_ctx: Mutex::new(None),
            sha512_ctx: Mutex::new(None),
        }
    }
}
