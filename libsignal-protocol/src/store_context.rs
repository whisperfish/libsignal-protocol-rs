use crate::context::ContextInner;
use std::rc::Rc;

pub struct StoreContext(pub(crate) Rc<StoreContextInner>);

impl StoreContext {
    pub(crate) fn new(
        raw: *mut sys::signal_protocol_store_context,
        ctx: &Rc<ContextInner>,
    ) -> StoreContext {
        StoreContext(Rc::new(StoreContextInner {
            raw,
            ctx: Rc::clone(ctx),
        }))
    }

    pub(crate) fn raw(&self) -> *mut sys::signal_protocol_store_context {
        self.0.raw
    }
}

pub(crate) struct StoreContextInner {
    raw: *mut sys::signal_protocol_store_context,
    // the global context must outlive `signal_protocol_store_context`
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
