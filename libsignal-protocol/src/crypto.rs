use crate::{
    buffer::Buffer,
    errors::{InternalError, InternalErrorCode},
};
use std::{
    os::raw::{c_int, c_void},
    pin::Pin,
    slice,
};
use sys::{signal_buffer, signal_crypto_provider};
pub enum SignalCipherType {
    AesCtrNoPadding,
    AesCbcPkcs5,
}

impl From<i32> for SignalCipherType {
    fn from(v: i32) -> Self {
        match v as u32 {
            sys::SG_CIPHER_AES_CTR_NOPADDING => {
                SignalCipherType::AesCtrNoPadding
            },
            sys::SG_CIPHER_AES_CBC_PKCS5 => SignalCipherType::AesCbcPkcs5,
            _ => unimplemented!("Unimplemented Signal Cipher Type"),
        }
    }
}
/// Cryptography routines used in the signal protocol.
pub trait Crypto {
    fn fill_random(&self, buffer: &mut [u8]) -> Result<(), InternalError>;
    fn hmac_sha256_init(&mut self, key: &[u8]) -> Result<(), InternalError>;
    fn hmac_sha256_update(&mut self, data: &[u8]) -> Result<(), InternalError>;
    fn hmac_sha256_final(&mut self) -> Result<Vec<u8>, InternalError>;
    fn hmac_sha256_cleanup(&mut self) {}

    fn sha512_digest_init(&mut self) -> Result<(), InternalError>;
    fn sha512_digest_update(
        &mut self,
        data: &[u8],
    ) -> Result<(), InternalError>;
    fn sha512_digest_final(&mut self) -> Result<Vec<u8>, InternalError>;
    fn sha512_digest_cleanup(&mut self) {}

    fn encrypt(
        &self,
        cipher: SignalCipherType,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, InternalError>;
    fn decrypt(
        &self,
        cipher: SignalCipherType,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, InternalError>;
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct DefaultCrypto;

#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct DefaultCrypto {
    hmac_ctx: Option<openssl::hash::Hasher>,
    sha512_ctx: Option<openssl::hash::Hasher>,
}

#[cfg(not(target_os = "linux"))]
impl Crypto for DefaultCrypto {
    fn fill_random(&self, buffer: &mut [u8]) -> Result<(), InternalError> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        rng.fill_bytes(buffer);
        Ok(())
    }

    fn hmac_sha256_init(&mut self, key: &[u8]) -> Result<(), InternalError> {
        unimplemented!()
    }

    fn hmac_sha256_update(&mut self, data: &[u8]) -> Result<(), InternalError> {
        unimplemented!()
    }

    fn hmac_sha256_final(&mut self) -> Result<Vec<u8>, InternalError> {
        unimplemented!()
    }

    fn sha512_digest_init(&mut self) -> Result<(), InternalError> {
        unimplemented!()
    }

    fn sha512_digest_update(
        &mut self,
        data: &[u8],
    ) -> Result<(), InternalError> {
        unimplemented!()
    }

    fn sha512_digest_final(&mut self) -> Result<Vec<u8>, InternalError> {
        unimplemented!()
    }

    fn encrypt(
        &self,
        cipher: SignalCipherType,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, InternalError> {
        unimplemented!()
    }

    fn decrypt(
        &self,
        cipher: SignalCipherType,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, InternalError> {
        unimplemented!()
    }
}

#[cfg(not(target_os = "linux"))]
impl Default for DefaultCrypto {
    fn default() -> Self { Self }
}

#[cfg(target_os = "linux")]
impl Default for DefaultCrypto {
    fn default() -> Self {
        Self {
            hmac_ctx: None,
            sha512_ctx: None,
        }
    }
}
#[cfg(target_os = "linux")]
impl DefaultCrypto {
    pub fn crypter(
        &self,
        mode: openssl::symm::Mode,
        cipher: SignalCipherType,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, InternalError> {
        use openssl::symm::{Cipher, Crypter};
        use SignalCipherType::*;
        let signal_cipher_type = match (cipher, key.len()) {
            (AesCtrNoPadding, 16) => Cipher::aes_128_ctr(),
            (AesCtrNoPadding, 24) => {
                let nid = openssl::nid::Nid::AES_192_CTR;
                Cipher::from_nid(nid)
                    .expect("OpenSSL should have AES_192_CTR !!")
            },
            (AesCtrNoPadding, 32) => Cipher::aes_256_ctr(),
            (AesCbcPkcs5, 16) => Cipher::aes_128_cbc(),
            (AesCbcPkcs5, 24) => {
                let nid = openssl::nid::Nid::AES_192_CBC;
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
#[cfg(target_os = "linux")]
impl Crypto for DefaultCrypto {
    fn fill_random(&self, buffer: &mut [u8]) -> Result<(), InternalError> {
        openssl::rand::rand_bytes(buffer).map_err(|_e| InternalError::Unknown)
    }

    fn hmac_sha256_init(&mut self, _key: &[u8]) -> Result<(), InternalError> {
        let nid = openssl::nid::Nid::HMACWITHSHA256;
        let ty = openssl::hash::MessageDigest::from_nid(nid)
            .ok_or_else(|| InternalError::Unknown)?;
        let ctx = openssl::hash::Hasher::new(ty)
            .map_err(|_e| InternalError::Unknown)?;
        self.hmac_ctx = Some(ctx);
        Ok(())
    }

    fn hmac_sha256_update(&mut self, data: &[u8]) -> Result<(), InternalError> {
        if let Some(ref mut ctx) = self.hmac_ctx {
            ctx.update(data).map_err(|_e| InternalError::Unknown)?;
        }
        Ok(())
    }

    fn hmac_sha256_final(&mut self) -> Result<Vec<u8>, InternalError> {
        if let Some(ref mut ctx) = self.hmac_ctx {
            ctx.finish()
                .map(|buf| buf.as_ref().to_owned())
                .map_err(|_e| InternalError::Unknown)
        } else {
            Err(InternalError::Unknown)
        }
    }

    fn sha512_digest_init(&mut self) -> Result<(), InternalError> {
        let ty = openssl::hash::MessageDigest::sha512();
        let ctx = openssl::hash::Hasher::new(ty)
            .map_err(|_e| InternalError::Unknown)?;
        self.sha512_ctx = Some(ctx);
        Ok(())
    }

    fn sha512_digest_update(
        &mut self,
        data: &[u8],
    ) -> Result<(), InternalError> {
        if let Some(ref mut ctx) = self.sha512_ctx {
            ctx.update(data).map_err(|_e| InternalError::Unknown)?;
        }
        Ok(())
    }

    fn sha512_digest_final(&mut self) -> Result<Vec<u8>, InternalError> {
        if let Some(ref mut ctx) = self.sha512_ctx {
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
        use openssl::symm::Mode;
        self.crypter(Mode::Encrypt, cipher, key, iv, data)
    }

    fn decrypt(
        &self,
        cipher: SignalCipherType,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, InternalError> {
        use openssl::symm::Mode;
        self.crypter(Mode::Decrypt, cipher, key, iv, data)
    }
}

/// A simple vtable ([`signal_crypto_provider`]) and set of trampolines to let C
/// use our [`Crypto`] trait object.
pub(crate) struct CryptoProvider {
    pub(crate) vtable: signal_crypto_provider,
    state: Pin<Box<State>>,
}

impl CryptoProvider {
    pub fn new<C: Crypto + 'static>(crypto: C) -> CryptoProvider {
        // we need a double-pointer because C doesn't do fat pointers
        let mut state: Pin<Box<State>> = Box::pin(State(Box::new(crypto)));

        let vtable = signal_crypto_provider {
            user_data: state.as_mut().get_mut() as *mut State as *mut c_void,
            random_func: Some(random_func),
            hmac_sha256_init_func: Some(hmac_sha256_init_func),
            hmac_sha256_update_func: Some(hmac_sha256_update_func),
            hmac_sha256_final_func: Some(hmac_sha256_final_func),
            hmac_sha256_cleanup_func: Some(hmac_sha256_cleanup_func),
            sha512_digest_init_func: Some(sha512_digest_init_func),
            sha512_digest_update_func: Some(sha512_digest_update_func),
            sha512_digest_final_func: Some(sha512_digest_final_func),
            sha512_digest_cleanup_func: Some(sha512_digest_cleanup_func),
            encrypt_func: Some(encrypt_func),
            decrypt_func: Some(decrypt_func),
        };

        CryptoProvider { vtable, state }
    }

    pub fn state(&self) -> &dyn Crypto { &*self.state.0 }
}

struct State(Box<dyn Crypto>);

unsafe extern "C" fn random_func(
    data: *mut u8,
    len: usize,
    user_data: *mut c_void,
) -> c_int {
    assert!(!data.is_null());
    assert!(!user_data.is_null());

    let user_data = &*(user_data as *const State);
    let buffer = slice::from_raw_parts_mut(data, len);
    user_data.0.fill_random(buffer).into_code()
}

unsafe extern "C" fn hmac_sha256_cleanup_func(
    _hmac_context: *mut c_void,
    user_data: *mut c_void,
) {
    assert!(!user_data.is_null());

    let user_data = &mut *(user_data as *mut State);
    user_data.0.hmac_sha256_cleanup();
}

unsafe extern "C" fn hmac_sha256_final_func(
    _hmac_context: *mut c_void,
    output: *mut *mut signal_buffer,
    user_data: *mut c_void,
) -> i32 {
    assert!(!user_data.is_null());

    let user_data = &mut *(user_data as *mut State);
    match user_data.0.hmac_sha256_final() {
        Ok(buf) => {
            let buffer = Buffer::from(buf);
            output.write(buffer.into_raw());
            sys::SG_SUCCESS as c_int
        },
        Err(e) => e.code(),
    }
}

unsafe extern "C" fn hmac_sha256_init_func(
    _hmac_context: *mut *mut c_void,
    key: *const u8,
    key_len: usize,
    user_data: *mut c_void,
) -> i32 {
    assert!(!key.is_null());
    assert!(!user_data.is_null());

    let user_data = &mut *(user_data as *mut State);
    let buffer = slice::from_raw_parts(key, key_len);
    user_data.0.hmac_sha256_init(buffer).into_code()
}

unsafe extern "C" fn hmac_sha256_update_func(
    _hmac_context: *mut c_void,
    data: *const u8,
    data_len: usize,
    user_data: *mut c_void,
) -> i32 {
    assert!(!data.is_null());
    assert!(!user_data.is_null());

    let user_data = &mut *(user_data as *mut State);
    let buffer = slice::from_raw_parts(data, data_len);
    user_data.0.hmac_sha256_update(buffer).into_code()
}

unsafe extern "C" fn sha512_digest_init_func(
    _digest_context: *mut *mut c_void,
    user_data: *mut c_void,
) -> c_int {
    assert!(!user_data.is_null());

    let user_data = &mut *(user_data as *mut State);
    user_data.0.sha512_digest_init().into_code()
}

unsafe extern "C" fn sha512_digest_update_func(
    _digest_context: *mut c_void,
    data: *const u8,
    data_len: usize,
    user_data: *mut c_void,
) -> c_int {
    assert!(!data.is_null());
    assert!(!user_data.is_null());

    let user_data = &mut *(user_data as *mut State);
    let buffer = slice::from_raw_parts(data, data_len);
    user_data.0.sha512_digest_update(buffer).into_code()
}

unsafe extern "C" fn sha512_digest_final_func(
    _digest_context: *mut c_void,
    output: *mut *mut signal_buffer,
    user_data: *mut c_void,
) -> c_int {
    assert!(!user_data.is_null());

    let user_data = &mut *(user_data as *mut State);
    match user_data.0.sha512_digest_final() {
        Ok(buf) => {
            let buffer = Buffer::from(buf);
            output.write(buffer.into_raw());
            sys::SG_SUCCESS as c_int
        },
        Err(e) => e.code(),
    }
}

unsafe extern "C" fn sha512_digest_cleanup_func(
    _digest_context: *mut c_void,
    user_data: *mut c_void,
) {
    assert!(!user_data.is_null());

    let user_data = &mut *(user_data as *mut State);
    user_data.0.sha512_digest_cleanup();
}

unsafe extern "C" fn encrypt_func(
    output: *mut *mut signal_buffer,
    cipher: c_int,
    key: *const u8,
    key_len: usize,
    iv: *const u8,
    iv_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    user_data: *mut c_void,
) -> c_int {
    assert!(!user_data.is_null());
    assert!(!key.is_null());
    assert!(!iv.is_null());
    assert!(!plaintext.is_null());

    let key = slice::from_raw_parts(key, key_len);
    let iv = slice::from_raw_parts(iv, iv_len);
    let data = slice::from_raw_parts(plaintext, plaintext_len);
    let signal_cipher_type = SignalCipherType::from(cipher);
    let user_data = &mut *(user_data as *mut State);
    match user_data.0.encrypt(signal_cipher_type, key, iv, data) {
        Ok(buf) => {
            let buffer = Buffer::from(buf);
            output.write(buffer.into_raw());
            sys::SG_SUCCESS as c_int
        },
        Err(e) => e.code(),
    }
}

unsafe extern "C" fn decrypt_func(
    output: *mut *mut signal_buffer,
    cipher: c_int,
    key: *const u8,
    key_len: usize,
    iv: *const u8,
    iv_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    user_data: *mut c_void,
) -> c_int {
    assert!(!user_data.is_null());
    assert!(!key.is_null());
    assert!(!iv.is_null());
    assert!(!ciphertext.is_null());

    let key = slice::from_raw_parts(key, key_len);
    let iv = slice::from_raw_parts(iv, iv_len);
    let data = slice::from_raw_parts(ciphertext, ciphertext_len);
    let signal_cipher_type = SignalCipherType::from(cipher);
    let user_data = &mut *(user_data as *mut State);
    match user_data.0.decrypt(signal_cipher_type, key, iv, data) {
        Ok(buf) => {
            let buffer = Buffer::from(buf);
            output.write(buffer.into_raw());
            sys::SG_SUCCESS as c_int
        },
        Err(e) => e.code(),
    }
}
