use crate::{
    context::{Context, ContextInner},
    errors::FromInternalErrorCode,
    messages::CiphertextMessage,
    raw_ptr::Raw,
    store_context::{StoreContext, StoreContextInner},
    Address,
};

use failure::Error;
use std::{
    fmt::{self, Debug, Formatter},
    ptr,
    rc::Rc,
};

/// The cipher context used for encryption.
pub struct SessionCipher {
    raw: *mut sys::session_cipher,
    _ctx: Rc<ContextInner>,
    _store_ctx: Rc<StoreContextInner>,
    _addr: Address,
}

impl SessionCipher {
    /// Create a new cipher for sending messages to the addressed recipient.
    pub fn new(
        ctx: &Context,
        store_ctx: &StoreContext,
        address: &Address,
    ) -> Result<SessionCipher, Error> {
        unsafe {
            let mut raw = ptr::null_mut();
            sys::session_cipher_create(
                &mut raw,
                store_ctx.raw(),
                address.raw(),
                ctx.raw(),
            )
            .into_result()?;

            Ok(SessionCipher {
                raw,
                _store_ctx: Rc::clone(&store_ctx.0),
                _ctx: Rc::clone(&ctx.0),
                _addr: address.clone(),
            })
        }
    }

    /// Encrypt a message.
    pub fn encrypt(&self, message: &[u8]) -> Result<CiphertextMessage, Error> {
        unsafe {
            let mut raw = ptr::null_mut();
            sys::session_cipher_encrypt(
                self.raw,
                message.as_ptr(),
                message.len(),
                &mut raw,
            )
            .into_result()?;

            Ok(CiphertextMessage {
                raw: Raw::from_ptr(raw),
            })
        }
    }
}

impl Drop for SessionCipher {
    fn drop(&mut self) {
        unsafe {
            sys::session_cipher_free(self.raw);
        }
    }
}

impl Debug for SessionCipher {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SessionCipher").finish()
    }
}
