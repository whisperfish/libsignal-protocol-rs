
use crate::{raw_ptr::Raw, Buffer, Serializable};
use failure::Error;
use std::convert::TryFrom;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum CiphertextType {
    Signal = 2,
    PreKey = 3,
    SenderKey = 4,
    SenderKeyDistribution = 5,
}

/// An encrypted message ("ciphertext").
#[derive(Debug, Clone)]
pub struct CiphertextMessage {
    pub(crate) raw: Raw<sys::ciphertext_message>,
}

impl CiphertextMessage {
    pub fn get_type(&self) -> Result<CiphertextType, Error> {
        unsafe {
            let ty = sys::ciphertext_message_get_type(self.raw.as_ptr());

            match u32::try_from(ty).unwrap() {
                sys::CIPHERTEXT_PREKEY_TYPE => Ok(CiphertextType::PreKey),
                sys::CIPHERTEXT_SIGNAL_TYPE => Ok(CiphertextType::Signal),
                sys::CIPHERTEXT_SENDERKEY_TYPE => Ok(CiphertextType::SenderKey),
                sys::CIPHERTEXT_SENDERKEY_DISTRIBUTION_TYPE => {
                    Ok(CiphertextType::SenderKeyDistribution)
                },
                other => Err(failure::format_err!(
                    "Unknown ciphertext type: {}",
                    other
                )),
            }
        }
    }
}

impl Serializable for CiphertextMessage {
    fn deserialize(_data: &[u8]) -> Result<Self, failure::Error>
    where
        Self: Sized,
    {
        unimplemented!()
    }

    fn serialize(&self) -> Result<Buffer, failure::Error> {
        unsafe {
            let buffer =
                sys::ciphertext_message_get_serialized(self.raw.as_const_ptr());

            if buffer.is_null() {
                Err(failure::err_msg("Unable to serialize the message"))
            } else {
                Ok(Buffer::from_raw(buffer))
            }
        }
    }
}
