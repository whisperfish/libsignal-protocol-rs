use crate::{
    errors::FromInternalErrorCode,
    keys::{PrivateKey, PublicKey},
    raw_ptr::Raw,
};
use failure::Error;
use std::{
    fmt::{self, Debug, Formatter},
    ptr,
};

/// A "ratcheting" key pair.
#[derive(Clone)]
pub struct IdentityKeyPair {
    pub(crate) raw: Raw<sys::ratchet_identity_key_pair>,
}

impl IdentityKeyPair {
    /// Create a new [`IdentityKeyPair`] out of its public and private keys.
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

    /// Get the public part of this key pair.
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

    /// Get the public part of this key pair.
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

impl Debug for IdentityKeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityKeyPair")
            .field("public", &self.public())
            .field("private", &self.private())
            .finish()
    }
}

impl_serializable!(IdentityKeyPair, ratchet_identity_key_pair_serialize, foo);
