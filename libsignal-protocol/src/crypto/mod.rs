//! Underlying cryptographic routines.

#[cfg(feature = "crypto-native")]
mod native;
#[cfg(feature = "crypto-native")]
pub use self::native::DefaultCrypto;

#[cfg(feature = "crypto-openssl")]
mod openssl;
#[cfg(feature = "crypto-openssl")]
pub use self::openssl::OpenSSLCrypto;

use std::{
    cell::RefCell,
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

/// The error returned from a failed conversion to [`SignalCipherType`].
#[derive(Debug, Copy, Clone)]
pub struct SignalCipherTypeError(i32);

#[derive(Debug, Copy, Clone)]
enum CipherMode {
    Encrypt,
    Decrypt,
}

/// The type of AES cipher.
#[derive(Debug, Copy, Clone)]
#[allow(missing_docs)]
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

/// Something which can calculate a SHA-256 HMAC.
pub trait Sha256Hmac {
    /// Update the HMAC context with the provided data.
    fn update(&mut self, data: &[u8]) -> Result<(), InternalError>;
    /// Return the HMAC result.
    ///
    /// # Note
    ///
    /// This method should prepare the context for reuse.
    fn finalize(&mut self) -> Result<Vec<u8>, InternalError>;
}

/// Something which can generate a SHA-512 hash.
pub trait Sha512Digest {
    /// Update the digest context with the provided data.
    fn update(&mut self, data: &[u8]) -> Result<(), InternalError>;
    /// Return the digest result.
    ///
    /// # Note
    ///
    /// This method should prepare the context for reuse.
    fn finalize(&mut self) -> Result<Vec<u8>, InternalError>;
}

/// Cryptography routines used in the signal protocol.
pub trait Crypto {
    /// Fill the provided buffer with some random bytes.
    fn fill_random(&self, buffer: &mut [u8]) -> Result<(), InternalError>;

    /// Start to calculate a SHA-256 HMAC using the provided key.
    fn hmac_sha256(
        &self,
        key: &[u8],
    ) -> Result<Box<dyn Sha256Hmac>, InternalError>;

    /// Start to generate a SHA-512 digest.
    fn sha512_digest(&self) -> Result<Box<dyn Sha512Digest>, InternalError>;

    /// Encrypt the provided data using AES.
    fn encrypt(
        &self,
        cipher: SignalCipherType,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, InternalError>;

    /// Decrypt the provided data using AES.
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

struct HmacContext(RefCell<Box<dyn Sha256Hmac>>);

struct DigestContext(RefCell<Box<dyn Sha512Digest>>);

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
    hmac_context: *mut c_void,
    _user_data: *mut c_void,
) {
    assert!(!hmac_context.is_null());

    let hmac_context: Box<HmacContext> =
        Box::from_raw(hmac_context as *mut HmacContext);
    drop(hmac_context);
}

unsafe extern "C" fn hmac_sha256_final_func(
    hmac_context: *mut c_void,
    output: *mut *mut signal_buffer,
    _user_data: *mut c_void,
) -> i32 {
    // just to make sure that the c ffi gave us a valid buffer to write to.
    assert!(!output.is_null());
    assert!(!hmac_context.is_null());

    let hmac_context = &*(hmac_context as *const HmacContext);

    match hmac_context.0.borrow_mut().finalize() {
        Ok(hmac) => {
            let buffer = Buffer::from(hmac);
            *output = buffer.into_raw();
            sys::SG_SUCCESS as c_int
        },
        Err(e) => e.code(),
    }
}

unsafe extern "C" fn hmac_sha256_init_func(
    hmac_context: *mut *mut c_void,
    key: *const u8,
    key_len: usize,
    user_data: *mut c_void,
) -> i32 {
    assert!(!key.is_null());
    assert!(!user_data.is_null());

    let state = &*(user_data as *const State);
    let key = slice::from_raw_parts(key, key_len);

    let hasher = match state.0.hmac_sha256(key) {
        Ok(h) => h,
        Err(e) => return e.code(),
    };

    *hmac_context = Box::into_raw(Box::new(HmacContext(RefCell::new(hasher))))
        as *mut c_void;
    sys::SG_SUCCESS as c_int
}

unsafe extern "C" fn hmac_sha256_update_func(
    hmac_context: *mut c_void,
    data: *const u8,
    data_len: usize,
    _user_data: *mut c_void,
) -> i32 {
    assert!(!data.is_null());
    assert!(!hmac_context.is_null());

    let hmac_context = &*(hmac_context as *const HmacContext);

    let data = slice::from_raw_parts(data, data_len);
    hmac_context.0.borrow_mut().update(data).into_code()
}

unsafe extern "C" fn sha512_digest_init_func(
    digest_context: *mut *mut c_void,
    user_data: *mut c_void,
) -> c_int {
    assert!(!user_data.is_null());

    let user_data = &*(user_data as *const State);
    let hasher = match user_data.0.sha512_digest() {
        Ok(h) => h,
        Err(e) => return e.code(),
    };

    let dc = Box::new(DigestContext(RefCell::new(hasher)));
    *digest_context = Box::into_raw(Box::new(dc)) as *mut c_void;

    sys::SG_SUCCESS as c_int
}

unsafe extern "C" fn sha512_digest_update_func(
    digest_context: *mut c_void,
    data: *const u8,
    data_len: usize,
    _user_data: *mut c_void,
) -> c_int {
    assert!(!data.is_null());
    assert!(!digest_context.is_null());

    let hasher = &*(digest_context as *const DigestContext);
    let mut hasher = hasher.0.borrow_mut();

    let buffer = slice::from_raw_parts(data, data_len);
    hasher.update(buffer).into_code()
}

unsafe extern "C" fn sha512_digest_final_func(
    digest_context: *mut c_void,
    output: *mut *mut signal_buffer,
    _user_data: *mut c_void,
) -> c_int {
    // just to make sure that the c ffi gave us a valid buffer to write to.
    assert!(!output.is_null());
    assert!(!digest_context.is_null());

    let hasher = &*(digest_context as *const DigestContext);

    match hasher.0.borrow_mut().finalize() {
        Ok(buf) => {
            let buffer = Buffer::from(buf);
            *output = buffer.into_raw();
            sys::SG_SUCCESS as c_int
        },
        Err(e) => e.code(),
    }
}

unsafe extern "C" fn sha512_digest_cleanup_func(
    digest_context: *mut c_void,
    _user_data: *mut c_void,
) {
    assert!(!digest_context.is_null());

    let digest_context: Box<DigestContext> =
        Box::from_raw(digest_context as *mut DigestContext);
    drop(digest_context);
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
