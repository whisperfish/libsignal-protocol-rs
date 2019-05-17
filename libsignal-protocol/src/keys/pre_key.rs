use crate::{errors::FromInternalErrorCode, keys::KeyPair, raw_ptr::Raw};
use failure::Error;
use std::ptr;

#[derive(Clone)]
pub struct PreKey {
    pub(crate) raw: Raw<sys::session_pre_key>,
}

impl PreKey {
    pub fn new(id: u32, key_pair: &KeyPair) -> Result<PreKey, Error> {
        unsafe {
            let mut raw = ptr::null_mut();
            sys::session_pre_key_create(&mut raw, id, key_pair.raw.as_ptr())
                .into_result()?;

            Ok(PreKey {
                raw: Raw::from_ptr(raw),
            })
        }
    }

    pub fn id(&self) -> u32 {
        unsafe { sys::session_pre_key_get_id(self.raw.as_const_ptr()) }
    }

    pub fn key_pair(&self) -> KeyPair {
        unsafe {
            let raw =
                sys::session_pre_key_get_key_pair(self.raw.as_const_ptr());
            assert!(!raw.is_null());
            KeyPair {
                raw: Raw::copied_from(raw),
            }
        }
    }
}

impl_serializable!(PreKey, session_pre_key_serialize, foo);
