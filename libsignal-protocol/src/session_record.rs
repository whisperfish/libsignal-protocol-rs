use crate::{raw_ptr::Raw, ContextInner, SessionState};
use std::rc::Rc;

/// The serialized state of a session.
#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub(crate) raw: Raw<sys::session_record>,
    pub(crate) ctx: Rc<ContextInner>,
}

impl SessionRecord {
    /// Get the state.
    pub fn state(&self) -> SessionState {
        unsafe {
            let raw = sys::session_record_get_state(self.raw.as_ptr());
            assert!(!raw.is_null());
            SessionState {
                raw: Raw::copied_from(raw),
                _ctx: Rc::clone(&self.ctx),
            }
        }
    }
}

impl_serializable!(SessionRecord, session_record_serialize);
impl_deserializable!(SessionRecord, session_record_deserialize, |raw, ctx| {
    SessionRecord {
        raw,
        ctx: Rc::clone(&ctx.0),
    }
});
