use libsignal_protocol_sys as sys;

use crate::context::ContextInner;
use std::rc::Rc;

pub struct StoreContext {
    raw: *mut sys::signal_protocol_store_context,
    #[allow(dead_code)]
    ctx: Rc<ContextInner>,
}

impl_wrapped!(sys::signal_protocol_store_context as StoreContext);
