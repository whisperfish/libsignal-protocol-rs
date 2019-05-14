use crate::{
    errors::FromInternalErrorCode,
    keys::{PrivateKey, PublicKey},
    raw_ptr::Raw,
};
use failure::Error;
use std::ptr;

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
}