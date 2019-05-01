use libsignal_protocol_sys as sys;

use crate::context::ContextInner;
use crate::errors::InternalErrorCode;
use crate::Wrapped;
use failure::Error;
use std::ptr;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};
use sys::AsSignalTypeBase;

pub struct IdentityKeyPair {
    raw: *mut sys::ratchet_identity_key_pair,
    ctx: Rc<ContextInner>,
}

impl IdentityKeyPair {
    pub fn sign(
        &self,
        signed_pre_key_id: u32,
        timestamp: SystemTime,
    ) -> Result<SignedPreKey, Error> {
        unsafe {
            let mut signed_pre_key = ptr::null_mut();

            let time_since_epoch = timestamp.duration_since(UNIX_EPOCH)?;

            sys::signal_protocol_key_helper_generate_signed_pre_key(
                &mut signed_pre_key,
                self.raw(),
                signed_pre_key_id,
                time_since_epoch.as_secs(),
                self.ctx.raw(),
            )
            .to_result()?;

            Ok(SignedPreKey::from_raw(signed_pre_key, &self.ctx))
        }
    }
}

impl Drop for IdentityKeyPair {
    fn drop(&mut self) {
        unsafe {
            sys::ratchet_identity_key_pair_destroy(self.raw.as_signal_base());
        }
    }
}

pub struct PreKeyList {
    raw: *mut sys::signal_protocol_key_helper_pre_key_list_node,
    ctx: Rc<ContextInner>,
}

impl Drop for PreKeyList {
    fn drop(&mut self) {
        unsafe {
            sys::signal_protocol_key_helper_key_list_free(self.raw);
        }
    }
}

pub struct SignedPreKey {
    raw: *mut sys::session_signed_pre_key,
    ctx: Rc<ContextInner>,
}

impl Drop for SignedPreKey {
    fn drop(&mut self) {
        unsafe {
            sys::session_signed_pre_key_destroy(self.raw.as_signal_base());
        }
    }
}

impl_wrapped! {
    sys::ratchet_identity_key_pair as IdentityKeyPair,
    sys::signal_protocol_key_helper_pre_key_list_node as PreKeyList,
    sys::session_signed_pre_key as SignedPreKey,
}
