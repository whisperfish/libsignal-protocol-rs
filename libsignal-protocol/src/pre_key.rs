use crate::ContextInner;

use std::rc::Rc;
use sys::AsSignalTypeBase;

pub struct PreKey {
    raw: *mut sys::session_pre_key,
    #[allow(dead_code)]
    ctx: Rc<ContextInner>,
}

impl Drop for PreKey {
    fn drop(&mut self) {
        unsafe {
            sys::session_pre_key_destroy(self.raw.as_signal_base());
        }
    }
}

impl_wrapped!(sys::session_pre_key as PreKey);
