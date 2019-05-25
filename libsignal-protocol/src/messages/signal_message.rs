use crate::raw_ptr::Raw;

/// The base message type.
#[derive(Debug, Clone)]
pub struct SignalMessage {
    pub(crate) raw: Raw<sys::signal_message>,
}
