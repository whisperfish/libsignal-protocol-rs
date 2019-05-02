use libsignal_protocol_sys as sys;

use crate::crypto::{Crypto, CryptoProvider, DefaultCrypto};
use crate::errors::{InternalError, InternalErrorCode};
use crate::keys::{IdentityKeyPair, PreKeyList};
use crate::store_context::StoreContext;
use crate::Wrapped;
use std::ffi::c_void;
use std::pin::Pin;
use std::ptr;
use std::rc::Rc;
use sys::signal_context;

pub struct Context(Rc<ContextInner>);

impl Context {
    pub fn new<C: Crypto + 'static>(crypto: C) -> Result<Context, InternalError> {
        ContextInner::new(crypto).map(|c| Context(Rc::new(c)))
    }

    pub fn generate_identity_key_pair(&self) -> Result<IdentityKeyPair, InternalError> {
        unsafe {
            let mut key_pair = ptr::null_mut();
            sys::signal_protocol_key_helper_generate_identity_key_pair(&mut key_pair, self.inner())
                .to_result()?;

            Ok(IdentityKeyPair::from_raw(key_pair, &self.0))
        }
    }

    pub fn generate_registration_id(&self, extended_range: i32) -> Result<u32, InternalError> {
        let mut id = 0;
        unsafe {
            sys::signal_protocol_key_helper_generate_registration_id(
                &mut id,
                extended_range,
                self.inner(),
            )
            .to_result()?;
        }

        Ok(id)
    }

    pub fn generate_pre_keys(&self, start: u32, count: u32) -> Result<PreKeyList, InternalError> {
        unsafe {
            let mut pre_keys_head = ptr::null_mut();
            sys::signal_protocol_key_helper_generate_pre_keys(
                &mut pre_keys_head,
                start,
                count,
                self.inner(),
            )
            .to_result()?;

            Ok(PreKeyList::from_raw(pre_keys_head, &self.0))
        }
    }

    pub fn new_store_context(&self) -> Result<StoreContext, InternalError> {
        unsafe {
            let mut store_ctx = ptr::null_mut();
            sys::signal_protocol_store_context_create(&mut store_ctx, self.inner()).to_result()?;

            Ok(StoreContext::from_raw(store_ctx, &self.0))
        }
    }

    fn inner(&self) -> *mut sys::signal_context {
        self.0.raw()
    }
}

impl Default for Context {
    fn default() -> Context {
        match Context::new(DefaultCrypto) {
            Ok(c) => c,
            Err(e) => panic!("Unable to create a context using the defaults: {}", e),
        }
    }
}

/// Our Rust wrapper around the [`sys::signal_context`].
///
/// # Safety
///
/// This **must** outlive any data created by the `libsignal-protocol-c` library.
/// You'll usually do this by adding a `Rc<ContextInner>` to any wrapper types.
#[allow(dead_code)]
pub(crate) struct ContextInner {
    raw: *mut sys::signal_context,
    crypto: CryptoProvider,
    // A pointer to our [`State`] has been passed to `libsignal-protocol-c`, so
    // we need to make sure it is never moved.
    state: Pin<Box<State>>,
}

impl ContextInner {
    pub fn new<C: Crypto + 'static>(crypto: C) -> Result<ContextInner, InternalError> {
        unsafe {
            let mut global_context: *mut signal_context = ptr::null_mut();
            let crypto = CryptoProvider::new(crypto);
            let mut state = Pin::new(Box::new(State {}));

            let user_data = state.as_mut().get_mut() as *mut State as *mut c_void;
            sys::signal_context_create(&mut global_context, user_data).to_result()?;
            sys::signal_context_set_crypto_provider(global_context, &crypto.vtable).to_result()?;
            sys::signal_context_set_locking_functions(
                global_context,
                Some(lock_function),
                Some(unlock_function),
            )
            .to_result()?;

            Ok(ContextInner {
                raw: global_context,
                crypto,
                state,
            })
        }
    }

    pub fn raw(&self) -> *mut sys::signal_context {
        self.raw
    }
}

impl Drop for ContextInner {
    fn drop(&mut self) {
        unsafe {
            sys::signal_context_destroy(self.raw());
        }
    }
}

unsafe extern "C" fn lock_function(user_data: *mut c_void) {
    let state = &mut *(user_data as *mut State);
    unimplemented!("TODO: Implement locking");
}
unsafe extern "C" fn unlock_function(user_data: *mut c_void) {
    let state = &mut *(user_data as *mut State);
    unimplemented!("TODO: Implement unlocking");
}

/// The "user state" we pass to `libsignal-protocol-c` as part of the global
/// context.
///
/// # Safety
///
/// A pointer to this [`State`] will be shared throughout the
/// `libsignal-protocol-c` library, so any mutation **must** be done using the
/// appropriate synchronisation mechanisms (i.e. `RefCell` or atomics).
struct State {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_initialization_example_from_readme() {
        let ctx = Context::new(DefaultCrypto).unwrap();

        drop(ctx);
    }
}
