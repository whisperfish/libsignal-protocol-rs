use rand::RngCore;
use std::{
    os::raw::{c_int, c_void},
    pin::Pin,
    slice,
};
use sys::{signal_buffer, signal_crypto_provider};

/// Cryptography routines used in the signal protocol.
pub trait Crypto {
    fn fill_random(&self, buffer: &mut [u8]);
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct DefaultCrypto;

impl Crypto for DefaultCrypto {
    fn fill_random(&self, buffer: &mut [u8]) {
        let mut rng = rand::thread_rng();
        rng.fill_bytes(buffer);
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
            decrypt_func: None,
            encrypt_func: None,
            hmac_sha256_cleanup_func: Some(hmac_sha256_cleanup_func),
            hmac_sha256_final_func: Some(hmac_sha256_final_func),
            hmac_sha256_init_func: Some(hmac_sha256_init_func),
            hmac_sha256_update_func: Some(hmac_sha256_update_func),
            sha512_digest_cleanup_func: None,
            random_func: Some(random_func),
            sha512_digest_final_func: None,
            sha512_digest_init_func: None,
            sha512_digest_update_func: None,
        };

        CryptoProvider { vtable, state }
    }

    pub fn state(&self) -> &dyn Crypto { &*self.state.0 }
}

struct State(Box<dyn Crypto>);

unsafe extern "C" fn hmac_sha256_cleanup_func(
    _hmac_context: *mut c_void,
    _user_data: *mut c_void,
) {
    unimplemented!();
}

unsafe extern "C" fn hmac_sha256_final_func(
    _hmac_context: *mut c_void,
    _output: *mut *mut signal_buffer,
    _user_data: *mut c_void,
) -> i32 {
    unimplemented!()
}

unsafe extern "C" fn hmac_sha256_init_func(
    _hmac_context: *mut *mut c_void,
    _key: *const u8,
    _key_len: usize,
    _user_data: *mut c_void,
) -> i32 {
    unimplemented!()
}

unsafe extern "C" fn hmac_sha256_update_func(
    _hmac_context: *mut c_void,
    _data: *const u8,
    _data_len: usize,
    _user_data: *mut c_void,
) -> i32 {
    unimplemented!()
}

unsafe extern "C" fn random_func(
    data: *mut u8,
    len: usize,
    user_data: *mut c_void,
) -> c_int {
    assert!(!data.is_null());
    assert!(!user_data.is_null());

    let user_data = &*(user_data as *const State);
    let buffer = slice::from_raw_parts_mut(data, len);
    user_data.0.fill_random(buffer);
    0
}
