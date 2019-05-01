use libsignal_protocol_sys as sys;

use crate::crypto::{Crypto, CryptoProvider, DefaultCrypto};
use crate::errors::{InternalError, InternalErrorCode};
use crate::keys::{IdentityKeyPair, PreKeyList, SignedPreKey};
use crate::Wrapped;
use std::ffi::c_void;
use std::pin::Pin;
use std::ptr;
use sys::signal_context;

pub struct Context {
    pub(crate) inner: *mut sys::signal_context,
    crypto: CryptoProvider,
    state: Pin<Box<State>>,
}

impl Context {
    pub fn new<C: Crypto + 'static>(crypto: C) -> Result<Context, InternalError> {
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

            Ok(Context {
                inner: global_context,
                crypto,
                state,
            })
        }
    }

    pub fn generate_identity_key_pair(&mut self) -> Result<IdentityKeyPair, InternalError> {
        unsafe {
            let mut key_pair = ptr::null_mut();
            sys::signal_protocol_key_helper_generate_identity_key_pair(&mut key_pair, self.inner)
                .to_result()?;

            Ok(IdentityKeyPair::from_raw(key_pair))
        }
    }

    pub fn generate_registration_id(&mut self, extended_range: i32) -> Result<u32, InternalError> {
        let mut id = 0;
        unsafe {
            sys::signal_protocol_key_helper_generate_registration_id(
                &mut id,
                extended_range,
                self.inner,
            )
            .to_result()?;
        }

        Ok(id)
    }

    pub fn generate_pre_keys(
        &mut self,
        start: u32,
        count: u32,
    ) -> Result<PreKeyList, InternalError> {
        unsafe {
            let mut pre_keys_head = ptr::null_mut();
            sys::signal_protocol_key_helper_generate_pre_keys(
                &mut pre_keys_head,
                start,
                count,
                self.inner,
            )
            .to_result()?;

            Ok(PreKeyList::from_raw(pre_keys_head))
        }
    }

    pub fn generate_signed_pre_key(
        &mut self,
        identity: &IdentityKeyPair,
        signed_pre_key_id: u32,
        timestamp: u64,
    ) -> Result<SignedPreKey, InternalError> {
        unsafe {
            let mut signed_pre_key = ptr::null_mut();

            sys::signal_protocol_key_helper_generate_signed_pre_key(
                &mut signed_pre_key,
                identity.raw(),
                signed_pre_key_id,
                timestamp,
                self.inner,
            )
            .to_result()?;

            Ok(SignedPreKey::from_raw(signed_pre_key))
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            sys::signal_context_destroy(self.inner);
        }
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

unsafe extern "C" fn lock_function(user_data: *mut c_void) {
    let state = &mut *(user_data as *mut State);
    unimplemented!("TODO: Implement locking");
}
unsafe extern "C" fn unlock_function(user_data: *mut c_void) {
    let state = &mut *(user_data as *mut State);
    unimplemented!("TODO: Implement unlocking");
}

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
