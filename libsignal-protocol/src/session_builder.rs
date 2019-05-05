use libsignal_protocol_sys as sys;

use crate::context::{Context, ContextInner};
use crate::store_context::{StoreContext, StoreContextInner};
use crate::{Address, Wrapped};
use std::ptr;
use std::rc::Rc;

pub struct SessionBuilder {
    raw: *mut sys::session_builder,
    _store_context: Rc<StoreContextInner>,
    _context: Rc<ContextInner>,
}

impl SessionBuilder {
    pub fn new(ctx: Context, store_context: StoreContext, address: Address) -> SessionBuilder {
        unsafe {
            let mut raw = ptr::null_mut();
            sys::session_builder_create(&mut raw, store_context.raw(), address.raw(), ctx.raw());

            SessionBuilder {
                raw,
                _store_context: store_context.0,
                _context: ctx.0,
            }
        }
    }
}

impl Drop for SessionBuilder {
    fn drop(&mut self) {
        unsafe {
            sys::session_builder_free(self.raw);
        }
    }
}
