use std::{ffi::c_void, pin::Pin, ptr, rc::Rc};

use lock_api::RawMutex as _;
use parking_lot::RawMutex;

use sys::signal_context;

#[cfg(feature = "crypto-native")]
use crate::crypto::DefaultCrypto;
use crate::{
    crypto::{Crypto, CryptoProvider},
    errors::{FromInternalErrorCode, InternalError},
    identity_key_store::{self as iks, IdentityKeyStore},
    keys::{IdentityKeyPair, PreKeyList},
    pre_key_store::{self as pks, PreKeyStore},
    session_store::{self as sess, SessionStore},
    signed_pre_key_store::{self as spks, SignedPreKeyStore},
    store_context::StoreContext,
    Wrapped,
};

pub struct Context(pub(crate) Rc<ContextInner>);

impl Context {
    pub fn new<C: Crypto + 'static>(
        crypto: C,
    ) -> Result<Context, InternalError> {
        ContextInner::new(crypto).map(|c| Context(Rc::new(c)))
    }

    pub fn generate_identity_key_pair(
        &self,
    ) -> Result<IdentityKeyPair, InternalError> {
        unsafe {
            let mut key_pair = ptr::null_mut();
            sys::signal_protocol_key_helper_generate_identity_key_pair(
                &mut key_pair,
                self.raw(),
            )
            .into_result()?;
            Ok(IdentityKeyPair::from_raw(key_pair, &self.0))
        }
    }

    pub fn generate_registration_id(
        &self,
        extended_range: i32,
    ) -> Result<u32, InternalError> {
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
    ) -> Result<PreKeyList, InternalError> {
        unsafe {
            let mut pre_keys_head = ptr::null_mut();
            sys::signal_protocol_key_helper_generate_pre_keys(
                &mut pre_keys_head,
                start,
                count,
                self.raw(),
            )
            .into_result()?;

            Ok(PreKeyList::from_raw(pre_keys_head, &self.0))
        }
    }

    pub fn new_store_context<P, K, S, I>(
        &self,
        pre_key_store: P,
        signed_pre_key_store: K,
        session_store: S,
        identity_key_store: I,
    ) -> Result<StoreContext, InternalError>
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
            let mut global_context: *mut signal_context = ptr::null_mut();
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

    #[test]
    fn library_initialization_example_from_readme() {
        let ctx = Context::new(DefaultCrypto::default()).unwrap();

        drop(ctx);
    }
}
