use crate::{
    errors::FromInternalErrorCode, keys::KeyPair, raw_ptr::Raw, Buffer,
};
use failure::Error;
use std::{
    io::Write,
    ptr,
    time::{Duration, SystemTime},
};

pub struct SessionSignedPreKey {
    pub(crate) raw: Raw<sys::session_signed_pre_key>,
}

impl SessionSignedPreKey {
    pub fn new(
        id: u32,
        timestamp: SystemTime,
        key_pair: &KeyPair,
        signature: &[u8],
    ) -> Result<SessionSignedPreKey, Error> {
        unsafe {
            let mut raw = ptr::null_mut();
            let elapsed = timestamp.duration_since(SystemTime::UNIX_EPOCH)?;

            sys::session_signed_pre_key_create(
                &mut raw,
                id,
                elapsed.as_secs(),
                key_pair.raw.as_ptr(),
                signature.as_ptr(),
                signature.len(),
            )
            .into_result()?;

            Ok(SessionSignedPreKey {
                raw: Raw::from_ptr(raw),
            })
        }
    }

    pub fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Error> {
        unsafe {
            let mut buffer = ptr::null_mut();
            sys::session_signed_pre_key_serialize(
                &mut buffer,
                self.raw.as_const_ptr(),
            )
            .into_result()?;
            let buffer = Buffer::from_raw(buffer);

            writer.write_all(buffer.as_slice())?;

            Ok(())
        }
    }

    pub fn id(&self) -> u32 {
        unsafe { sys::session_signed_pre_key_get_id(self.raw.as_const_ptr()) }
    }

    pub fn timestamp(&self) -> SystemTime {
        unsafe {
            let ts = sys::session_signed_pre_key_get_timestamp(
                self.raw.as_const_ptr(),
            );
            SystemTime::UNIX_EPOCH + Duration::from_secs(ts)
        }
    }

    pub fn get_key_pair(&self) -> KeyPair {
        unsafe {
            let raw = sys::session_signed_pre_key_get_key_pair(
                self.raw.as_const_ptr(),
            );
            assert!(!raw.is_null());
            KeyPair {
                raw: Raw::copied_from(raw),
            }
        }
    }

    pub fn get_signature(&self) -> &[u8] {
        unsafe {
            let len = sys::session_signed_pre_key_get_signature_len(
                self.raw.as_const_ptr(),
            );
            let ptr = sys::session_signed_pre_key_get_signature(
                self.raw.as_const_ptr(),
            );

            std::slice::from_raw_parts(ptr, len)
        }
    }
}
