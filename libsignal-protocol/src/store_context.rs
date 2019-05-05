use libsignal_protocol_sys as sys;

use crate::context::ContextInner;
use crate::Wrapped;
use std::rc::Rc;

pub struct StoreContext {
    inner: Rc<StoreContextInner>,
}

impl StoreContext {
    pub(crate) fn new(
        raw: *mut sys::signal_protocol_store_context,
        ctx: &Rc<ContextInner>,
    ) -> StoreContext {
        let inner = unsafe { StoreContextInner::from_raw(raw, ctx) };
        StoreContext {
            inner: Rc::new(inner),
        }
    }
}

struct StoreContextInner {
    raw: *mut sys::signal_protocol_store_context,
    #[allow(dead_code)]
    ctx: Rc<ContextInner>,
}

impl Drop for StoreContextInner {
    fn drop(&mut self) {
        unsafe {
            sys::signal_protocol_store_context_destroy(self.raw);
        }
    }
}

impl_wrapped!(sys::signal_protocol_store_context as StoreContextInner);
