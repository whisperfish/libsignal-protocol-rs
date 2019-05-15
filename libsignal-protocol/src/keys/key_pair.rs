use crate::{
    errors::FromInternalErrorCode,
    keys::{PrivateKey, PublicKey},
    raw_ptr::Raw,
};
use failure::Error;
use std::ptr;

#[derive(Clone)]
pub struct KeyPair {
    pub(crate) raw: Raw<sys::ec_key_pair>,
}

impl KeyPair {
    pub fn new(
        public_key: &PublicKey,
        private_key: &PrivateKey,
    ) -> Result<KeyPair, Error> {
        unsafe {
            let mut raw = ptr::null_mut();
            sys::ec_key_pair_create(
                &mut raw,
                public_key.raw.as_ptr(),
                private_key.raw.as_ptr(),
            )
            .into_result()?;

            Ok(KeyPair {
                raw: Raw::from_ptr(raw),
            })
        }
    }

    pub fn public(&self) -> Result<PublicKey, Error> {
        unsafe {
            let raw = sys::ec_key_pair_get_public(self.raw.as_ptr());

            if raw.is_null() {
                Err(failure::err_msg("Unable to get the public key"))
            } else {
                Ok(PublicKey {
                    raw: Raw::copied_from(raw),
                })
            }
        }
    }

    pub fn private(&self) -> Result<PrivateKey, Error> {
        unsafe {
            let raw = sys::ec_key_pair_get_private(self.raw.as_ptr());

            if raw.is_null() {
                Err(failure::err_msg("Unable to get the private key"))
            } else {
                Ok(PrivateKey {
                    raw: Raw::copied_from(raw),
                })
            }
        }
    }
}