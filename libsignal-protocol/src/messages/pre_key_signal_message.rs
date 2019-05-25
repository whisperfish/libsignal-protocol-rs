use crate::{
    messages::{CiphertextMessage, CiphertextType},
    raw_ptr::Raw,
};
use failure::Error;
use std::convert::TryFrom;

#[derive(Debug, Clone)]
pub struct PreKeySignalMessage {
    pub(crate) raw: Raw<sys::pre_key_signal_message>,
}

impl TryFrom<CiphertextMessage> for PreKeySignalMessage {
    type Error = Error;

    fn try_from(other: CiphertextMessage) -> Result<Self, Self::Error> {
        if other.get_type()? != CiphertextType::PreKey {
            Err(failure::err_msg("Expected a pre-key ciphertext message"))
        } else {
            Ok(PreKeySignalMessage {
                raw: Raw::copied_from(
                    other.raw.as_ptr() as *mut sys::pre_key_signal_message
                ),
            })
        }
    }
}
