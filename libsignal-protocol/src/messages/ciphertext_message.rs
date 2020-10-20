use crate::{Buffer, ContextInner, Error, Serializable, errors::InternalError, raw_ptr::Raw};
use std::{convert::TryFrom, rc::Rc};

// For rustdoc link resolution
#[allow(unused_imports)]
use crate::messages::{PreKeySignalMessage, SignalMessage};

/// The type of ciphertext message.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum CiphertextType {
    /// A [`SignalMessage`].
    Signal = 2,
    /// A [`PreKeySignalMessage`].
    PreKey = 3,
    /// A sender key message.
    SenderKey = 4,
    /// A sender key distribution message.
    SenderKeyDistribution = 5,
}

/// The base class for a ciphertext message.
///
/// See also:
///
/// - [`SignalMessage`]
/// - [`PreKeySignalMessage`]
#[derive(Debug, Clone)]
pub struct CiphertextMessage {
    pub(crate) raw: Raw<sys::ciphertext_message>,
    pub(crate) _ctx: Rc<ContextInner>,
}

impl CiphertextMessage {
    /// Which type of message is this?
    pub fn get_type(&self) -> Result<CiphertextType, InternalError> {
        unsafe {
            let ty = sys::ciphertext_message_get_type(self.raw.as_ptr());

            match u32::try_from(ty).unwrap() {
                sys::CIPHERTEXT_PREKEY_TYPE => Ok(CiphertextType::PreKey),
                sys::CIPHERTEXT_SIGNAL_TYPE => Ok(CiphertextType::Signal),
                sys::CIPHERTEXT_SENDERKEY_TYPE => Ok(CiphertextType::SenderKey),
                sys::CIPHERTEXT_SENDERKEY_DISTRIBUTION_TYPE => {
                    Ok(CiphertextType::SenderKeyDistribution)
                },
                other => Err(InternalError::UnknownCiphertextType(other)),
            }
        }
    }
}

impl Serializable for CiphertextMessage {
    fn serialize(&self) -> Result<Buffer, Error> {
        unsafe {
            // get a reference to the *cached* serialized message
            let buffer =
                sys::ciphertext_message_get_serialized(self.raw.as_const_ptr());

            if buffer.is_null() {
                return Err(Error::InternalError(InternalError::SerializationError));
            }

            let temporary_not_owned_buffer = Buffer::from_raw(buffer);
            let copied = temporary_not_owned_buffer.clone();

            // We don't want to free our reference to the serialized message!
            std::mem::forget(temporary_not_owned_buffer);

            Ok(copied)
        }
    }
}
