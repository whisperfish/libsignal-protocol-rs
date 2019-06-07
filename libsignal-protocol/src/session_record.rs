use crate::{raw_ptr::Raw, SessionState};

/// The serialized state of a session.
#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub(crate) raw: Raw<sys::session_record>,
}

impl SessionRecord {
    /// Get the state.
    pub fn state(&self) -> SessionState {
        unsafe {
            let raw = sys::session_record_get_state(self.raw.as_ptr());
            assert!(!raw.is_null());
            SessionState {
                raw: Raw::copied_from(raw),
            }
        }
    }
}

impl_serializable!(
    SessionRecord,
    session_record_serialize,
    session_record_deserialize
);
