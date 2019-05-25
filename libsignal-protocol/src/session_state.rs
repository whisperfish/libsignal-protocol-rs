#![allow(missing_docs)]

use crate::raw_ptr::Raw;

#[derive(Debug, Clone)]
pub struct SessionState {
    pub(crate) raw: Raw<sys::session_state>,
}

impl SessionState {
    pub fn version(&self) -> u32 {
        unsafe { sys::session_state_get_session_version(self.raw.as_ptr()) }
    }
}
