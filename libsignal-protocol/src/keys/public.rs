use crate::{
    errors::{FromInternalErrorCode, InternalError},
    raw_ptr::Raw,
    Buffer, Context,
};
use failure::Error;
use std::{
    cmp::{Ord, Ordering},
    io::Write,
    ptr,
};

#[derive(Clone, Debug)]
pub struct PublicKey {
    pub(crate) raw: Raw<sys::ec_public_key>,
}

impl PublicKey {
    pub fn decode_point(ctx: &Context, key: &[u8]) -> Result<PublicKey, Error> {
        unsafe {
            let mut raw = ptr::null_mut();
            sys::curve_decode_point(
                &mut raw,
                key.as_ptr(),
                key.len(),
                ctx.raw(),
            )
            .into_result()?;

            Ok(PublicKey {
                raw: Raw::from_ptr(raw),
            })
        }
    }

    pub fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Error> {
        unsafe {
            let mut buffer = ptr::null_mut();
            sys::ec_public_key_serialize(&mut buffer, self.raw.as_const_ptr())
                .into_result()?;
            let buffer = Buffer::from_raw(buffer);

            writer.write_all(buffer.as_slice())?;

            Ok(())
        }
    }

    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        unsafe {
            let result = sys::curve_verify_signature(
                self.raw.as_const_ptr(),
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
                signature.len(),
            );

            if result == 1 {
                Ok(())
            } else if result == 0 {
                Err(failure::err_msg("Invalid signature"))
            } else if let Some(err) = InternalError::from_error_code(result) {
                Err(err.into())
            } else {
                Err(failure::format_err!("Unknown error code: {}", result))
            }
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
