use std::ptr;

use failure::Error;

use crate::{
    errors::FromInternalErrorCode,
    keys::{PrivateKey, PublicKey},
    raw_ptr::Raw,
};

#[derive(Clone, Debug)]
pub struct IdentityKeyPair {
    pub(crate) raw: Raw<sys::ratchet_identity_key_pair>,
}

impl IdentityKeyPair {
    pub fn new(
        public_key: &PublicKey,
        private_key: &PrivateKey,
    ) -> Result<IdentityKeyPair, Error> {
        unsafe {
            let mut raw = ptr::null_mut();
            sys::ratchet_identity_key_pair_create(
                &mut raw,
                public_key.raw.as_ptr(),
                private_key.raw.as_ptr(),
            )
            .into_result()?;

            Ok(IdentityKeyPair {
                raw: Raw::from_ptr(raw),
            })
        }
    }

    pub fn public(&self) -> PublicKey {
        unsafe {
            let raw = sys::ratchet_identity_key_pair_get_public(
                self.raw.as_const_ptr(),
            );
            assert!(!raw.is_null());
            PublicKey {
                raw: Raw::copied_from(raw),
            }
        }
    }

    pub fn private(&self) -> PrivateKey {
        unsafe {
            let raw = sys::ratchet_identity_key_pair_get_private(
                self.raw.as_const_ptr(),
            );
            assert!(!raw.is_null());
            PrivateKey {
                raw: Raw::copied_from(raw),
            }
        }
    }
}

impl Drop for IdentityKeyPair {
    fn drop(&mut self) {
        unsafe {
            sys::ratchet_identity_key_pair_destroy(self.raw.as_ptr() as _)
        }
    }
}
impl_serializable!(IdentityKeyPair, ratchet_identity_key_pair_serialize, foo);
