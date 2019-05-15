
use failure::Error;

use lock_api::RawMutex as _;
use parking_lot::RawMutex;
use std::{ffi::c_void, pin::Pin, ptr, rc::Rc, time::SystemTime};

#[cfg(feature = "crypto-native")]
use crate::crypto::DefaultCrypto;
use crate::{
    crypto::{Crypto, CryptoProvider},
    errors::{FromInternalErrorCode, InternalError},
    identity_key_store::{self as iks, IdentityKeyStore},
    keys::{IdentityKeyPair, PreKeyList, SessionSignedPreKey},
    pre_key_store::{self as pks, PreKeyStore},
    raw_ptr::Raw,
    session_store::{self as sess, SessionStore},
    signed_pre_key_store::{self as spks, SignedPreKeyStore},
    StoreContext,
};

/// Global state and callbacks used by the library.
pub struct Context(pub(crate) Rc<ContextInner>);

impl Context {
    pub fn new<C: Crypto + 'static>(crypto: C) -> Result<Context, Error> {
        ContextInner::new(crypto)
            .map(|c| Context(Rc::new(c)))
            .map_err(Error::from)
    }

    pub fn generate_identity_key_pair(&self) -> Result<IdentityKeyPair, Error> {
        unsafe {
            let mut key_pair = ptr::null_mut();
            sys::signal_protocol_key_helper_generate_identity_key_pair(
                &mut key_pair,
                self.raw(),
            )
            .into_result()?;
            Ok(IdentityKeyPair {
                raw: Raw::from_ptr(key_pair),
            })
        }
    }

    pub fn generate_registration_id(
        &self,
        extended_range: i32,
    ) -> Result<u32, Error> {
        let mut id = 0;
        unsafe {
            sys::signal_protocol_key_helper_generate_registration_id(
                &mut id,
                extended_range,
                self.raw(),
            )
            .into_result()?;
        }

        Ok(id)
    }

    pub fn generate_pre_keys(
        &self,
        start: u32,
        count: u32,
    ) -> Result<PreKeyList, Error> {
        unsafe {
            let mut pre_keys_head = ptr::null_mut();
            sys::signal_protocol_key_helper_generate_pre_keys(
                &mut pre_keys_head,
                start,
                count,
                self.raw(),
            )
            .into_result()?;

            Ok(PreKeyList::from_raw(pre_keys_head))
        }
    }

    pub fn generate_signed_pre_key(
        &self,
        identity_key_pair: &IdentityKeyPair,
        id: u32,
        timestamp: SystemTime,
    ) -> Result<SessionSignedPreKey, Error> {
        unsafe {
            let mut raw = ptr::null_mut();
            let unix_time = timestamp.duration_since(SystemTime::UNIX_EPOCH)?;

            sys::signal_protocol_key_helper_generate_signed_pre_key(
                &mut raw,
                identity_key_pair.raw.as_const_ptr(),
                id,
                unix_time.as_secs(),
                self.raw(),
            )
            .into_result()?;

            if raw.is_null() {
                Err(failure::err_msg("Unable to generate a signed pre key"))
            } else {
                Ok(SessionSignedPreKey {
                    raw: Raw::from_ptr(raw),
                })
            }
        }
    }

    pub fn new_store_context<P, K, S, I>(
        &self,
        pre_key_store: P,
        signed_pre_key_store: K,
        session_store: S,
        identity_key_store: I,
    ) -> Result<StoreContext, Error>
    where
        P: PreKeyStore + 'static,
        K: SignedPreKeyStore + 'static,
        S: SessionStore + 'static,
        I: IdentityKeyStore + 'static,
    {
        unsafe {
            let mut store_ctx = ptr::null_mut();
            sys::signal_protocol_store_context_create(
                &mut store_ctx,
                self.raw(),
            )
            .into_result()?;

            let pre_key_store = pks::new_vtable(pre_key_store);
            sys::signal_protocol_store_context_set_pre_key_store(
                store_ctx,
                &pre_key_store,
            )
            .into_result()?;

            let signed_pre_key_store = spks::new_vtable(signed_pre_key_store);
            sys::signal_protocol_store_context_set_signed_pre_key_store(
                store_ctx,
                &signed_pre_key_store,
            )
            .into_result()?;

            let session_store = sess::new_vtable(session_store);
            sys::signal_protocol_store_context_set_session_store(
                store_ctx,
                &session_store,
            )
            .into_result()?;

            let identity_key_store = iks::new_vtable(identity_key_store);
            sys::signal_protocol_store_context_set_identity_key_store(
                store_ctx,
                &identity_key_store,
            )
            .into_result()?;

            Ok(StoreContext::new(store_ctx, &self.0))
        }
    }

    pub fn crypto(&self) -> &dyn Crypto { self.0.crypto.state() }

    pub(crate) fn raw(&self) -> *mut sys::signal_context { self.0.raw() }
}

#[cfg(feature = "crypto-native")]
impl Default for Context {
    fn default() -> Context {
        match Context::new(DefaultCrypto::default()) {
            Ok(c) => c,
            Err(e) => {
                panic!("Unable to create a context using the defaults: {}", e)
            },
        }
    }
}

/// Our Rust wrapper around the [`sys::signal_context`].
///
/// # Safety
///
/// This **must** outlive any data created by the `libsignal-protocol-c`
/// library. You'll usually do this by adding a `Rc<ContextInner>` to any
/// wrapper types.
#[allow(dead_code)]
pub(crate) struct ContextInner {
    raw: *mut sys::signal_context,
    crypto: CryptoProvider,
    // A pointer to our [`State`] has been passed to `libsignal-protocol-c`, so
    // we need to make sure it is never moved.
    state: Pin<Box<State>>,
}

impl ContextInner {
    pub fn new<C: Crypto + 'static>(
        crypto: C,
    ) -> Result<ContextInner, InternalError> {
        unsafe {
            let mut global_context: *mut sys::signal_context = ptr::null_mut();
            let crypto = CryptoProvider::new(crypto);
            let mut state = Pin::new(Box::new(State {
                mux: RawMutex::INIT,
            }));

            let user_data =
                state.as_mut().get_mut() as *mut State as *mut c_void;
            sys::signal_context_create(&mut global_context, user_data)
                .into_result()?;
            sys::signal_context_set_crypto_provider(
                global_context,
                &crypto.vtable,
            )
            .into_result()?;
            sys::signal_context_set_locking_functions(
                global_context,
                Some(lock_function),
                Some(unlock_function),
            )
            .into_result()?;

            Ok(ContextInner {
                raw: global_context,
                crypto,
                state,
            })
        }
    }

    pub fn raw(&self) -> *mut sys::signal_context { self.raw }
}

impl Drop for ContextInner {
    fn drop(&mut self) {
        unsafe {
            sys::signal_context_destroy(self.raw());
        }
    }
}

unsafe extern "C" fn lock_function(user_data: *mut c_void) {
    let state = &*(user_data as *const State);
    state.mux.lock();
}

unsafe extern "C" fn unlock_function(user_data: *mut c_void) {
    let state = &*(user_data as *const State);
    state.mux.unlock();
}

/// The "user state" we pass to `libsignal-protocol-c` as part of the global
/// context.
///
/// # Safety
///
/// A pointer to this [`State`] will be shared throughout the
/// `libsignal-protocol-c` library, so any mutation **must** be done using the
/// appropriate synchronisation mechanisms (i.e. `RefCell` or atomics).
struct State {
    mux: RawMutex,
}

#[cfg(all(test, feature = "crypto-native"))]
mod tests {
    use super::*;
    use crate::crypto::SignalCipherType;

    struct MockCrypto<C> {
        inner: C,
        random_func:
            Option<Box<Fn(&mut [u8]) -> Result<(), InternalError> + 'static>>,
    }

    impl<C: Crypto> MockCrypto<C> {
        pub fn new(inner: C) -> MockCrypto<C> {
            MockCrypto {
                inner,
                random_func: None,
            }
        }

        pub fn random_func<F>(mut self, func: F) -> Self
        where
            F: Fn(&mut [u8]) -> Result<(), InternalError> + 'static,
        {
            self.random_func = Some(Box::new(func));
            self
        }
    }

    impl<C: Crypto> Crypto for MockCrypto<C> {
        fn fill_random(&self, buffer: &mut [u8]) -> Result<(), InternalError> {
            if let Some(ref random_func) = self.random_func {
                random_func(buffer)
            } else {
                self.inner.fill_random(buffer)
            }
        }

        fn hmac_sha256_init(&self, key: &[u8]) -> Result<(), InternalError> {
            self.inner.hmac_sha256_init(key)
        }

        fn hmac_sha256_update(&self, data: &[u8]) -> Result<(), InternalError> {
            self.inner.hmac_sha256_update(data)
        }

        fn hmac_sha256_final(&self) -> Result<Vec<u8>, InternalError> {
            self.inner.hmac_sha256_final()
        }

        fn hmac_sha256_cleanup(&self) { self.inner.hmac_sha256_cleanup() }

        fn sha512_digest_init(&self) -> Result<(), InternalError> {
            self.inner.sha512_digest_init()
        }

        fn sha512_digest_update(
            &self,
            data: &[u8],
        ) -> Result<(), InternalError> {
            self.inner.sha512_digest_update(data)
        }

        fn sha512_digest_final(&self) -> Result<Vec<u8>, InternalError> {
            self.inner.sha512_digest_final()
        }

        fn sha512_digest_cleanup(&self) { self.inner.sha512_digest_cleanup() }

        fn encrypt(
            &self,
            cipher: SignalCipherType,
            key: &[u8],
            iv: &[u8],
            data: &[u8],
        ) -> Result<Vec<u8>, InternalError> {
            self.inner.encrypt(cipher, key, iv, data)
        }

        fn decrypt(
            &self,
            cipher: SignalCipherType,
            key: &[u8],
            iv: &[u8],
            data: &[u8],
        ) -> Result<Vec<u8>, InternalError> {
            self.inner.decrypt(cipher, key, iv, data)
        }
    }

    fn fake_random_generator() -> impl Fn(&mut [u8]) -> Result<(), InternalError>
    {
        use std::cell::Cell;
        let test_next_random = Cell::new(0);

        move |data| {
            for i in 0..data.len() {
                data[i] = test_next_random.get();
                test_next_random.set(test_next_random.get().wrapping_add(1));
            }

            Ok(())
        }
    }

    #[test]
    fn library_initialization_example_from_readme() {
        let ctx = Context::new(DefaultCrypto::default()).unwrap();

        drop(ctx);
    }

    /// Copied from https://github.com/signalapp/libsignal-protocol-c/blob/7bd0e5fee0ebde15c45fffcd631b74d188fd5551/tests/test_key_helper.c#L90
    #[test]
    fn test_generate_pre_keys() {
        const PRE_KEY1: &[u8] = &[
            0x08, 0x01, 0x12, 0x21, 0x05, 0x8f, 0x40, 0xc5, 0xad, 0xb6, 0x8f,
            0x25, 0x62, 0x4a, 0xe5, 0xb2, 0x14, 0xea, 0x76, 0x7a, 0x6e, 0xc9,
            0x4d, 0x82, 0x9d, 0x3d, 0x7b, 0x5e, 0x1a, 0xd1, 0xba, 0x6f, 0x3e,
            0x21, 0x38, 0x28, 0x5f, 0x1a, 0x20, 0x00, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
            0x1b, 0x1c, 0x1d, 0x1e, 0x5f,
        ];
        const PRE_KEY2: &[u8] = &[
            0x08, 0x02, 0x12, 0x21, 0x05, 0x35, 0x80, 0x72, 0xd6, 0x36, 0x58,
            0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38, 0x38,
            0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2,
            0xcd, 0x16, 0x62, 0x54, 0x1a, 0x20, 0x20, 0x21, 0x22, 0x23, 0x24,
            0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a,
            0x3b, 0x3c, 0x3d, 0x3e, 0x7f,
        ];
        const PRE_KEY3: &[u8] = &[
            0x08, 0x03, 0x12, 0x21, 0x05, 0x79, 0xa6, 0x31, 0xee, 0xde, 0x1b,
            0xf9, 0xc9, 0x8f, 0x12, 0x03, 0x2c, 0xde, 0xad, 0xd0, 0xe7, 0xa0,
            0x79, 0x39, 0x8f, 0xc7, 0x86, 0xb8, 0x8c, 0xc8, 0x46, 0xec, 0x89,
            0xaf, 0x85, 0xa5, 0x1a, 0x1a, 0x20, 0x40, 0x41, 0x42, 0x43, 0x44,
            0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
            0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
        ];
        const PRE_KEY4: &[u8] = &[
            0x08, 0x04, 0x12, 0x21, 0x05, 0x67, 0x5d, 0xd5, 0x74, 0xed, 0x77,
            0x89, 0x31, 0x0b, 0x3d, 0x2e, 0x76, 0x81, 0xf3, 0x79, 0x0b, 0x46,
            0x6c, 0x77, 0x3b, 0x15, 0x21, 0xfe, 0xcf, 0x36, 0x57, 0x79, 0x58,
            0x37, 0x1e, 0xa5, 0x2f, 0x1a, 0x20, 0x60, 0x61, 0x62, 0x63, 0x64,
            0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
            0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a,
            0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
        ];

        let ctx = Context::new(
            MockCrypto::new(DefaultCrypto::default())
                .random_func(fake_random_generator()),
        )
        .unwrap();

        let pre_keys = ctx.generate_pre_keys(1, 4).unwrap();
        let mut iter = pre_keys.iter();

        let pre_key_1 = iter.next().unwrap();
        let pre_key_2 = iter.next().unwrap();
        let pre_key_3 = iter.next().unwrap();
        let pre_key_4 = iter.next().unwrap();
        assert!(iter.next().is_none());

        let pre_key_1_serialized = pre_key_1.serialize().unwrap();
        let pre_key_2_serialized = pre_key_2.serialize().unwrap();
        let pre_key_3_serialized = pre_key_3.serialize().unwrap();
        let pre_key_4_serialized = pre_key_4.serialize().unwrap();

        assert_eq!(PRE_KEY1, pre_key_1_serialized.as_slice());
        assert_eq!(PRE_KEY2, pre_key_2_serialized.as_slice());
        assert_eq!(PRE_KEY3, pre_key_3_serialized.as_slice());
        assert_eq!(PRE_KEY4, pre_key_4_serialized.as_slice());
    }
}
