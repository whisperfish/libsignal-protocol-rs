use crate::{
    address::Address,
    context::{Context, ContextInner},
    errors::{FromInternalErrorCode, InternalError},
    pre_key_bundle::PreKeyBundle,
    store_context::{StoreContext, StoreContextInner},
};
use std::{ptr, rc::Rc};

pub struct SessionBuilder {
    raw: *mut sys::session_builder,
    // both these fields must outlive `session_builder`
    _store_ctx: Rc<StoreContextInner>,
    _ctx: Rc<ContextInner>,
}

impl SessionBuilder {
    pub fn new(
        ctx: &Context,
        store_context: StoreContext,
        address: Address<'_>,
    ) -> SessionBuilder {
        unsafe {
            let mut raw = ptr::null_mut();
            sys::session_builder_create(
                &mut raw,
                store_context.raw(),
                address.raw(),
                ctx.raw(),
            );

            SessionBuilder {
                raw,
                _store_ctx: store_context.0,
                _ctx: Rc::clone(&ctx.0),
            }
        }
    }

    pub fn process_pre_key_bundle(
        &self,
        pre_key_bundle: &PreKeyBundle,
    ) -> Result<(), InternalError> {
        unsafe {
            sys::session_builder_process_pre_key_bundle(
                self.raw,
                pre_key_bundle.raw.as_ptr(),
            )
            .into_result()
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
