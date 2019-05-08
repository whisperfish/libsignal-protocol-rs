use crate::{context::ContextInner, Wrapped};
use std::rc::Rc;

pub struct StoreContext(pub(crate) Rc<StoreContextInner>);

impl StoreContext {
    pub(crate) fn new(
        raw: *mut sys::signal_protocol_store_context,
        ctx: &Rc<ContextInner>,
    ) -> StoreContext {
        let inner = unsafe { StoreContextInner::from_raw(raw, ctx) };
        StoreContext(Rc::new(inner))
    }

    pub(crate) fn raw(&self) -> *mut sys::signal_protocol_store_context {
        self.0.raw
    }
}

pub(crate) struct StoreContextInner {
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
