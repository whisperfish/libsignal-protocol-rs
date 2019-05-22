use crate::{context::ContextInner, errors::FromInternalErrorCode};
use failure::Error;
use std::{
    fmt::{self, Debug, Formatter},
    rc::Rc,
};

#[derive(Debug, Clone)]
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

    /// Get the registration ID.
    pub fn registration_id(&self) -> Result<u32, Error> {
        unsafe {
            let mut id = 0;
            sys::signal_protocol_identity_get_local_registration_id(
                self.raw(),
                &mut id,
            )
            .into_result()?;

            Ok(id)
        }
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

impl Debug for StoreContextInner {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("StoreContextInner").finish()
    }
}
