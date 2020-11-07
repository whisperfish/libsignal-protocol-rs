use crate::{
    context::ContextInner,
    errors::FromInternalErrorCode,
    keys::{IdentityKeyPair, PreKey, PublicKey, SessionSignedPreKey},
    raw_ptr::Raw,
    stores::IdentityKeyStore,
    Address, Context, Error, InternalError, SessionRecord,
};
use std::{
    fmt::{self, Debug, Formatter},
    ptr,
    rc::Rc,
    sync::{Arc, RwLock},
};

/// Something which contains state used by the signal protocol.
///
/// Under the hood this contains several "Stores" for various keys and session
/// state (e.g. which identities are trusted, and their pre-keys).
#[derive(Clone)]
pub struct StoreContext(
    pub(crate) Rc<StoreContextInner>,
    /// doing this temporarily until libsignal-protocol-c gets a signal_protocol_identity_get_identity(addr) function
    Arc<RwLock<dyn IdentityKeyStore>>,
);

impl Debug for StoreContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("StoreContext")
            .field(&self.0)
            .field(&format!(
                "IdentityKeyStore(strong: {}, weak: {})",
                Arc::strong_count(&self.1),
                Arc::weak_count(&self.1),
            ))
            .finish()
    }
}

impl StoreContext {
    pub(crate) fn new(
        raw: *mut sys::signal_protocol_store_context,
        ctx: &Rc<ContextInner>,
        identity_key_store: Arc<RwLock<dyn IdentityKeyStore>>,
    ) -> StoreContext {
        StoreContext(
            Rc::new(StoreContextInner {
                raw,
                ctx: Rc::clone(ctx),
            }),
            identity_key_store,
        )
    }

    /// Return the identity key pair of this store.
    pub fn identity_key_pair(&self) -> Result<IdentityKeyPair, Error> {
        unsafe {
            let mut key_pair = std::ptr::null_mut();
            sys::signal_protocol_identity_get_key_pair(
                self.raw(),
                &mut key_pair,
            )
            .into_result()?;
            Ok(IdentityKeyPair {
                raw: Raw::from_ptr(key_pair),
            })
        }
    }

    /// Return the saved public identity key for a remote client.
    pub fn get_identity(
        &self,
        address: Address,
    ) -> Result<Option<PublicKey>, Error> {
        // TODO: this whole function should be replaced by a call to `libsignal-protocol-c`
        // once the missing functionality has been added.
        let context = Context(self.0.ctx.clone());
        Ok(self
            .1
            .read()
            .expect("poisoned mutex")
            .get_identity(address)?
            .and_then(|b| PublicKey::decode_point(&context, b.as_slice()).ok()))
    }

    /// Store pre key
    pub fn store_pre_key(&self, pre_key: &PreKey) -> Result<(), Error> {
        unsafe {
            sys::signal_protocol_pre_key_store_key(
                self.raw(),
                pre_key.raw.as_ptr(),
            )
            .into_result()?;

            Ok(())
        }
    }

    /// Store signed pre key
    pub fn store_signed_pre_key(
        &self,
        signed_pre_key: &SessionSignedPreKey,
    ) -> Result<(), Error> {
        unsafe {
            sys::signal_protocol_signed_pre_key_store_key(
                self.raw(),
                signed_pre_key.raw.as_ptr(),
            )
            .into_result()?;

            Ok(())
        }
    }

    /// Get the registration ID.
    pub fn registration_id(&self) -> Result<u32, Error> {
        unsafe {
            let mut id = 0;
            sys::signal_protocol_identity_get_local_registration_id(
                self.raw(),
                &mut id,
            )
            .into_result()?;

            Ok(id)
        }
    }

    /// Does this store already contain a session with the provided recipient?
    pub fn contains_session(&self, addr: &Address) -> Result<bool, Error> {
        unsafe {
            match sys::signal_protocol_session_contains_session(
                self.raw(),
                addr.raw(),
            ) {
                0 => Ok(false),
                1 => Ok(true),
                code => Err(InternalError::from_error_code(code)
                    .unwrap_or(InternalError::Unknown)
                    .into()),
            }
        }
    }

    /// Load the session corresponding to the provided recipient.
    pub fn load_session(&self, addr: &Address) -> Result<SessionRecord, Error> {
        unsafe {
            let mut raw = ptr::null_mut();
            sys::signal_protocol_session_load_session(
                self.raw(),
                &mut raw,
                addr.raw(),
            )
            .into_result()?;

            Ok(SessionRecord {
                raw: Raw::from_ptr(raw),
                ctx: Rc::clone(&self.0.ctx),
            })
        }
    }

    /// Load the sub-device sessions corresponding to the provided recipient
    /// identifier.
    pub fn get_sub_device_sessions(
        &self,
        identifier: &str,
    ) -> Result<Vec<i32>, Error> {
        unsafe {
            let mut sessions = ptr::null_mut();
            sys::signal_protocol_session_get_sub_device_sessions(
                self.raw(),
                &mut sessions,
                identifier.as_ptr() as *const ::std::os::raw::c_char,
                identifier.len(),
            )
            .into_result()?;
            let mut ids = Vec::with_capacity(
                sys::signal_int_list_size(sessions) as usize,
            );
            for i in 0..sys::signal_int_list_size(sessions) {
                ids.push(sys::signal_int_list_at(sessions, i));
            }
            Ok(ids)
        }
    }

    /// Delete an existing session corresponding to the provided address.
    pub fn delete_session(&self, address: &Address) -> Result<(), Error> {
        unsafe {
            sys::signal_protocol_session_delete_session(
                self.raw(),
                address.raw(),
            )
            .into_result()?;
        }
        Ok(())
    }

    pub(crate) fn raw(&self) -> *mut sys::signal_protocol_store_context {
        self.0.raw
    }
}

pub(crate) struct StoreContextInner {
    raw: *mut sys::signal_protocol_store_context,
    // the global context must outlive `signal_protocol_store_context`
    #[allow(dead_code)]
    ctx: Rc<ContextInner>,
}

impl Drop for StoreContextInner {
    fn drop(&mut self) {
        unsafe {
            sys::signal_protocol_store_context_destroy(self.raw);
        }
    }
}

impl Debug for StoreContextInner {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("StoreContextInner").finish()
    }
}
