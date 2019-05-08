use crate::{context::ContextInner, errors::InternalErrorCode, Wrapped};
use failure::Error;
use std::{
    marker::PhantomData,
    ptr,
    rc::Rc,
    slice,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
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
            .into_result()?;

            Ok(SignedPreKey::from_raw(signed_pre_key, &self.ctx))
        }
    }

    pub fn public_key(&self) -> Result<PublicKey, Error> {
        unsafe {
            let key = sys::ratchet_identity_key_pair_get_public(self.raw);

            if key.is_null() {
                Err(failure::err_msg("Unable to get the public key"))
            } else {
                Ok(PublicKey::from_raw(key, &self.ctx))
            }
        }
    }

    pub fn private_key(&self) -> Result<PrivateKey, Error> {
        unsafe {
            let key = sys::ratchet_identity_key_pair_get_private(self.raw);

            if key.is_null() {
                Err(failure::err_msg("Unable to get the private key"))
            } else {
                Ok(PrivateKey::from_raw(key, &self.ctx))
            }
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

pub struct PublicKey {
    raw: *mut sys::ec_public_key,
    #[allow(dead_code)]
    ctx: Rc<ContextInner>,
}

impl Drop for PublicKey {
    fn drop(&mut self) {
        unsafe {
            sys::ec_public_key_destroy(self.raw.as_signal_base());
        }
    }
}

pub struct PrivateKey {
    raw: *mut sys::ec_private_key,
    #[allow(dead_code)]
    ctx: Rc<ContextInner>,
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        unsafe {
            sys::ec_private_key_destroy(self.raw.as_signal_base());
        }
    }
}

pub struct PreKeyList {
    raw: *mut sys::signal_protocol_key_helper_pre_key_list_node,
    #[allow(dead_code)]
    ctx: Rc<ContextInner>,
}

impl PreKeyList {
    pub fn iter<'this>(
        &'this self,
    ) -> impl Iterator<Item = SessionPreKeyRef<'this>> + 'this {
        PreKeyListIter {
            raw: self.raw,
            _lifetime: PhantomData,
        }
    }
}

impl Drop for PreKeyList {
    fn drop(&mut self) {
        unsafe {
            sys::signal_protocol_key_helper_key_list_free(self.raw);
        }
    }
}

struct PreKeyListIter<'a> {
    raw: *mut sys::signal_protocol_key_helper_pre_key_list_node,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> Iterator for PreKeyListIter<'a> {
    type Item = SessionPreKeyRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.is_null() {
            return None;
        }

        unsafe {
            let head = self.raw;
            self.raw = sys::signal_protocol_key_helper_key_list_next(self.raw);
            let ptr = sys::signal_protocol_key_helper_key_list_element(head);

            if ptr.is_null() {
                None
            } else {
                Some(SessionPreKeyRef {
                    raw: ptr,
                    _lifetime: PhantomData,
                })
            }
        }
    }
}

pub struct SessionPreKeyRef<'a> {
    raw: *const sys::session_pre_key,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> SessionPreKeyRef<'a> {
    pub fn id(&self) -> u32 { unsafe { sys::session_pre_key_get_id(self.raw) } }
}

pub struct SignedPreKey {
    raw: *mut sys::session_signed_pre_key,
    #[allow(dead_code)]
    ctx: Rc<ContextInner>,
}

impl SignedPreKey {
    pub fn id(&self) -> u32 {
        unsafe { sys::session_signed_pre_key_get_id(self.raw) }
    }

    pub fn signature(&self) -> &[u8] {
        unsafe {
            let len = sys::session_signed_pre_key_get_signature_len(self.raw);
            assert!(len > 0);
            let ptr = sys::session_signed_pre_key_get_signature(self.raw);
            assert!(!ptr.is_null());

            slice::from_raw_parts(ptr, len)
        }
    }

    pub fn timestamp(&self) -> SystemTime {
        unsafe {
            let unix_timestamp =
                sys::session_signed_pre_key_get_timestamp(self.raw);
            SystemTime::UNIX_EPOCH + Duration::from_secs(unix_timestamp)
        }
    }

    pub fn key_pair(&self) -> Result<KeyPair, Error> {
        unsafe {
            let ptr = sys::session_signed_pre_key_get_key_pair(self.raw);

            if ptr.is_null() {
                Err(failure::err_msg("Unable to get the key pair"))
            } else {
                Ok(KeyPair::from_raw(ptr, &self.ctx))
            }
        }
    }
}

impl Drop for SignedPreKey {
    fn drop(&mut self) {
        unsafe {
            sys::session_signed_pre_key_destroy(self.raw.as_signal_base());
        }
    }
}

pub struct KeyPair {
    raw: *mut sys::ec_key_pair,
    #[allow(dead_code)]
    ctx: Rc<ContextInner>,
}

impl_wrapped! {
    sys::ratchet_identity_key_pair as IdentityKeyPair,
    sys::signal_protocol_key_helper_pre_key_list_node as PreKeyList,
    sys::session_signed_pre_key as SignedPreKey,
    sys::ec_public_key as PublicKey,
    sys::ec_private_key as PrivateKey,
    sys::ec_key_pair as KeyPair,
}
