use crate::address::Address;
use crate::context::{Context, ContextInner};
use crate::pre_key_bundle::PreKeyBundle;
use crate::store_context::{StoreContext, StoreContextInner};
use crate::Wrapped;
use std::ptr;
use std::rc::Rc;

pub struct SessionBuilder {
    raw: *mut sys::session_builder,
    _store_ctx: Rc<StoreContextInner>,
    _ctx: Rc<ContextInner>,
}

impl SessionBuilder {
    pub fn new(ctx: Context, store_context: StoreContext, address: Address) -> SessionBuilder {
        unsafe {
            let mut raw = ptr::null_mut();
            sys::session_builder_create(&mut raw, store_context.raw(), address.raw(), ctx.raw());

            SessionBuilder {
                raw,
                _store_ctx: store_context.0,
                _ctx: ctx.0,
            }
        }
    }

    pub fn process_pre_key_bundle(&self, pre_key_bundle: &PreKeyBundle) {
        unsafe {
            sys::session_builder_process_pre_key_bundle(self.raw, pre_key_bundle.raw_mut());
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
