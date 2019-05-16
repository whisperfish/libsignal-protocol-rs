#[cfg(feature = "crypto-native")]
mod native;
#[cfg(feature = "crypto-native")]
pub use self::native::DefaultCrypto;

#[cfg(feature = "crypto-openssl")]
mod openssl;
#[cfg(feature = "crypto-openssl")]
pub use self::openssl::OpenSSLCrypto;

use std::{
    convert::TryFrom,
    os::raw::{c_int, c_void},
    pin::Pin,
    slice,
};

use sys::{signal_buffer, signal_crypto_provider};

use crate::{
    buffer::Buffer,
    errors::{InternalError, IntoInternalErrorCode},
};

#[derive(Debug, Clone)]
pub struct SignalCipherTypeError(i32);

#[derive(Copy, Clone)]
pub enum CipherMode {
    Encrypt,
    Decrypt,
}
pub enum SignalCipherType {
    AesCtrNoPadding,
    AesCbcPkcs5,
}

impl TryFrom<i32> for SignalCipherType {
    type Error = SignalCipherTypeError;

    #[inline]
    fn try_from(v: i32) -> Result<Self, Self::Error> {
        match v as u32 {
            sys::SG_CIPHER_AES_CTR_NOPADDING => {
                Ok(SignalCipherType::AesCtrNoPadding)
            },
            sys::SG_CIPHER_AES_CBC_PKCS5 => Ok(SignalCipherType::AesCbcPkcs5),
            _ => Err(SignalCipherTypeError(v)),
        }
    }
}

/// Cryptography routines used in the signal protocol.
pub trait Crypto {
    fn fill_random(&self, buffer: &mut [u8]) -> Result<(), InternalError>;
    fn hmac_sha256_init(&self, key: &[u8]) -> Result<(), InternalError>;
    fn hmac_sha256_update(&self, data: &[u8]) -> Result<(), InternalError>;
    fn hmac_sha256_final(&self) -> Result<Vec<u8>, InternalError>;
    fn hmac_sha256_cleanup(&self) {}

    fn sha512_digest_init(&self) -> Result<(), InternalError>;
    fn sha512_digest_update(&self, data: &[u8]) -> Result<(), InternalError>;
    fn sha512_digest_final(&self) -> Result<Vec<u8>, InternalError>;
    fn sha512_digest_cleanup(&self) {}

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

    let user_data = &*(user_data as *const State);
    user_data.0.hmac_sha256_cleanup();
}

unsafe extern "C" fn hmac_sha256_final_func(
    _hmac_context: *mut c_void,
    output: *mut *mut signal_buffer,
    user_data: *mut c_void,
) -> i32 {
    // just to make sure that the c ffi gave us a valid buffer to write to.
    assert!(!output.is_null());
    assert!(!user_data.is_null());

    let user_data = &*(user_data as *const State);
    match user_data.0.hmac_sha256_final() {
        Ok(buf) => {
            let buffer = Buffer::from(buf);
            *output = buffer.into_raw();
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

    let user_data = &*(user_data as *const State);
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

    let user_data = &*(user_data as *const State);
    let buffer = slice::from_raw_parts(data, data_len);
    user_data.0.hmac_sha256_update(buffer).into_code()
}

unsafe extern "C" fn sha512_digest_init_func(
    _digest_context: *mut *mut c_void,
    user_data: *mut c_void,
) -> c_int {
    assert!(!user_data.is_null());

    let user_data = &*(user_data as *const State);
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

    let user_data = &*(user_data as *const State);
    let buffer = slice::from_raw_parts(data, data_len);
    user_data.0.sha512_digest_update(buffer).into_code()
}

unsafe extern "C" fn sha512_digest_final_func(
    _digest_context: *mut c_void,
    output: *mut *mut signal_buffer,
    user_data: *mut c_void,
) -> c_int {
    // just to make sure that the c ffi gave us a valid buffer to write to.
    assert!(!output.is_null());
    assert!(!user_data.is_null());

    let user_data = &*(user_data as *const State);
    match user_data.0.sha512_digest_final() {
        Ok(buf) => {
            let buffer = Buffer::from(buf);
            *output = buffer.into_raw();
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

    let user_data = &*(user_data as *const State);
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
    internal_cipher(
        CipherMode::Encrypt,
        output,
        cipher,
        key,
        key_len,
        iv,
        iv_len,
        plaintext,
        plaintext_len,
        user_data,
    )
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
    internal_cipher(
        CipherMode::Decrypt,
        output,
        cipher,
        key,
        key_len,
        iv,
        iv_len,
        ciphertext,
        ciphertext_len,
        user_data,
    )
}

#[inline]
unsafe extern "C" fn internal_cipher(
    mode: CipherMode,
    output: *mut *mut signal_buffer,
    cipher: c_int,
    key: *const u8,
    key_len: usize,
    iv: *const u8,
    iv_len: usize,
    data: *const u8,
    data_len: usize,
    user_data: *mut c_void,
) -> c_int {
    use self::CipherMode::*;
    // just to make sure that the c ffi gave us a valid buffer to write to.
    assert!(!output.is_null());
    assert!(!user_data.is_null());
    assert!(!key.is_null());
    assert!(!iv.is_null());
    assert!(!data.is_null());

    let signal_cipher_type = match SignalCipherType::try_from(cipher) {
        Ok(ty) => ty,
        // return early from the function with invalid arg instead of unknown
        // error, cuz we know it xD
        Err(_) => return InternalError::InvalidArgument.code(),
    };
    let key = slice::from_raw_parts(key, key_len);
    let iv = slice::from_raw_parts(iv, iv_len);
    let data = slice::from_raw_parts(data, data_len);

    let user_data = &*(user_data as *const State);

    let result = match mode {
        Encrypt => user_data.0.encrypt(signal_cipher_type, key, iv, data),
        Decrypt => user_data.0.decrypt(signal_cipher_type, key, iv, data),
    };

    match result {
        Ok(buf) => {
            let buffer = Buffer::from(buf);
            *output = buffer.into_raw();
            sys::SG_SUCCESS as c_int
        },
        Err(e) => e.code(),
    }
}
