use crate::{
    errors::{Error, FromInternalErrorCode},
    keys::PublicKey,
    raw_ptr::Raw,
    Buffer, Context,
};
use std::{
    cmp::{Ord, Ordering},
    ptr,
};

/// The private half of an elliptic curve key pair.
#[derive(Clone, Debug)]
pub struct PrivateKey {
    pub(crate) raw: Raw<sys::ec_private_key>,
}

impl PrivateKey {
    /// Decode a [`PrivateKey`] from raw key data.
    pub fn decode_point(
        ctx: &Context,
        key: &[u8],
    ) -> Result<PrivateKey, Error> {
        unsafe {
            let mut raw = ptr::null_mut();
            sys::curve_decode_private_point(
                &mut raw,
                key.as_ptr(),
                key.len(),
                ctx.raw(),
            )
            .into_result()?;

            Ok(PrivateKey {
                raw: Raw::from_ptr(raw),
            })
        }
    }

    /// Derive the public part of this key pair.
    pub fn generate_public_key(&self) -> Result<PublicKey, Error> {
        unsafe {
            let mut raw = ptr::null_mut();
            sys::curve_generate_public_key(&mut raw, self.raw.as_const_ptr())
                .into_result()?;

            Ok(PublicKey {
                raw: Raw::from_ptr(raw),
            })
        }
    }

    /// Get a copy of to the underlying private key data.
    pub fn to_bytes(&self) -> Result<Buffer, Error> {
        unsafe {
            let mut raw = ptr::null_mut();
            sys::ec_private_key_serialize(&mut raw, self.raw.as_const_ptr())
                .into_result()?;
            Ok(Buffer::from_raw(raw))
        }
    }

    /// Return this private key as a base64 encoded string.
    pub fn to_base64(&self) -> Result<String, Error> {
        Ok(base64::encode(self.to_bytes()?))
    }
}

impl Ord for PrivateKey {
    fn cmp(&self, other: &PrivateKey) -> Ordering {
        unsafe {
            sys::ec_private_key_compare(
                self.raw.as_const_ptr(),
                other.raw.as_const_ptr(),
            )
        }.cmp(&0)
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &PrivateKey) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for PrivateKey {}

impl PartialOrd for PrivateKey {
    fn partial_cmp(&self, other: &PrivateKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl_serializable!(PrivateKey, ec_private_key_serialize);
