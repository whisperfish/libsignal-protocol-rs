use crate::{
    errors::FromInternalErrorCode,
    keys::{PrivateKey, PublicKey},
    raw_ptr::Raw,
    Buffer,
};
use failure::Error;
use std::{io::Write, ptr};

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

    pub fn serialize_to<W: Write>(&self, mut writer: W) -> Result<(), Error> {
        let buffer = self.serialize()?;
        writer.write_all(buffer.as_slice())?;

        Ok(())
    }

    pub fn serialize(&self) -> Result<Buffer, Error> {
        unsafe {
            let mut buffer = ptr::null_mut();
            sys::ratchet_identity_key_pair_serialize(
                &mut buffer,
                self.raw.as_const_ptr(),
            )
            .into_result()?;
            Ok(Buffer::from_raw(buffer))
        }
    }

    pub fn public(&self) -> Result<PublicKey, Error> {
        unsafe {
            let raw = sys::ratchet_identity_key_pair_get_public(
                self.raw.as_const_ptr(),
            );
            assert!(!raw.is_null());
            Ok(PublicKey {
                raw: Raw::copied_from(raw),
            })
        }
    }
}
