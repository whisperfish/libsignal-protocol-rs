use crate::ContextInner;
use std::rc::Rc;

pub struct PreKeyBundle {
    raw: *mut sys::session_pre_key_bundle,
    ctx: Rc<ContextInner>,
}

impl_wrapped!(sys::session_pre_key_bundle as PreKeyBundle);
