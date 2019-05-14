use crate::{errors::FromInternalErrorCode, raw_ptr::Raw, Context};
use failure::Error;
use std::{
    cmp::{Ord, Ordering},
    ptr,
};

pub struct PublicKey {
    pub(crate) raw: Raw<sys::ec_public_key>,
}

impl PublicKey {
    pub fn decode_point(
        ctx: &Context,
        data: &[u8],
    ) -> Result<PublicKey, Error> {
        unsafe {
            let mut raw = ptr::null_mut();
            sys::curve_decode_point(
                &mut raw,
                data.as_ptr(),
                data.len(),
                ctx.raw(),
            )
            .into_result()?;

            Ok(PublicKey {
                raw: Raw::from_ptr(raw),
            })
        }
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &PublicKey) -> Ordering {
        let cmp = unsafe {
            sys::ec_public_key_compare(
                self.raw.as_const_ptr(),
                other.raw.as_const_ptr(),
            )
        };

        if cmp < 0 {
            Ordering::Less
        } else if cmp > 0 {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for PublicKey {}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &PublicKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
