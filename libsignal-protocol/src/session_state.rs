use crate::raw_ptr::Raw;

/// The internal state associated with a session.
#[derive(Debug, Clone)]
pub struct SessionState {
    pub(crate) raw: Raw<sys::session_state>,
}

impl SessionState {
    /// Get the session version.
    pub fn version(&self) -> u32 {
        unsafe { sys::session_state_get_session_version(self.raw.as_ptr()) }
    }
}
