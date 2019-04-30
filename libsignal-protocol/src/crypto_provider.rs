use libsignal_protocol_sys as sys;

use std::ffi::c_void;
use std::pin::Pin;
use sys::{signal_buffer, signal_crypto_provider};

pub trait Crypto {}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct DefaultCrypto;

impl Crypto for DefaultCrypto {}

/// A simple vtable ([`signal_crypto_provider`]) and set of trampolines to let C
/// use our [`Crypto`] trait object.
pub(crate) struct CryptoProvider {
    pub(crate) vtable: signal_crypto_provider,
    _inner: Pin<Box<State>>,
}

impl CryptoProvider {
    pub fn new<C: Crypto + 'static>(crypto: C) -> CryptoProvider {
        // we need a double-pointer because C doesn't do fat pointers
        let mut state: Pin<Box<State>> = Box::pin(State(Box::pin(crypto)));

        let vtable = signal_crypto_provider {
            user_data: state.as_mut().get_mut() as *mut State as *mut c_void,
            decrypt_func: None,
            encrypt_func: None,
            hmac_sha256_cleanup_func: Some(hmac_sha256_cleanup_func),
            hmac_sha256_final_func: Some(hmac_sha256_final_func),
            hmac_sha256_init_func: Some(hmac_sha256_init_func),
            hmac_sha256_update_func: Some(hmac_sha256_update_func),
            random_func: None,
            sha512_digest_cleanup_func: None,
            sha512_digest_final_func: None,
            sha512_digest_init_func: None,
            sha512_digest_update_func: None,
        };

        CryptoProvider {
            vtable,
            _inner: state,
        }
    }
}

struct State(Pin<Box<dyn Crypto>>);

unsafe extern "C" fn hmac_sha256_cleanup_func(hmac_context: *mut c_void, user_data: *mut c_void) {}

unsafe extern "C" fn hmac_sha256_final_func(
    hmac_context: *mut c_void,
    output: *mut *mut signal_buffer,
    user_data: *mut c_void,
) -> i32 {
    let state = &mut *(user_data as *mut State);
    0
}

unsafe extern "C" fn hmac_sha256_init_func(
    hmac_context: *mut *mut c_void,
    key: *const u8,
    key_len: usize,
    user_data: *mut c_void,
) -> i32 {
    let state = &mut *(user_data as *mut State);
    0
}

unsafe extern "C" fn hmac_sha256_update_func(
    hmac_context: *mut c_void,
    data: *const u8,
    data_len: usize,
    user_data: *mut c_void,
) -> i32 {
    0
}
