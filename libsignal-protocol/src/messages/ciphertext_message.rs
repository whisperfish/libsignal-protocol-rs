use crate::{raw_ptr::Raw, Buffer, Serializable};

#[derive(Debug, Clone)]
pub struct CiphertextMessage {
    pub(crate) raw: Raw<sys::ciphertext_message>,
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
