use libsignal_protocol_sys as sys;

mod crypto_provider;
mod errors;

pub use crate::crypto_provider::{Crypto, DefaultCrypto};
pub use crate::errors::InternalError;

use crate::crypto_provider::CryptoProvider;
use crate::errors::InternalErrorCode;
use std::ffi::c_void;
use std::pin::Pin;
use std::ptr;
use sys::signal_context;

pub struct Context {
    inner: *mut sys::signal_context,
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
