use crate::{
    messages::{CiphertextMessage, CiphertextType},
    raw_ptr::Raw,
};
use failure::Error;
use std::convert::TryFrom;

/// The base message type.
#[derive(Debug, Clone)]
pub struct SignalMessage {
    pub(crate) raw: Raw<sys::signal_message>,
}

impl TryFrom<CiphertextMessage> for SignalMessage {
    type Error = Error;

    fn try_from(other: CiphertextMessage) -> Result<Self, Self::Error> {
        if other.get_type()? != CiphertextType::Signal {
            Err(failure::err_msg("Expected a signal message"))
        } else {
            // safety: the `CiphertextType` check tells us this is actually a
            // pointer to a `signal_message`
            let raw = unsafe {
                Raw::copied_from(other.raw.as_ptr() as *mut sys::signal_message)
            };
            Ok(SignalMessage { raw })
        }
    }
}

impl From<SignalMessage> for CiphertextMessage {
    fn from(other: SignalMessage) -> CiphertextMessage {
        CiphertextMessage {
            raw: other.raw.upcast(),
        }
    }
}

impl_is_a!(sys::signal_message => sys::ciphertext_message);
