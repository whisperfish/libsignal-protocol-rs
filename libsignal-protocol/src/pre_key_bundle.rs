use crate::{keys::PublicKey, ContextInner, InternalError, Wrapped};
use std::{convert::TryInto, ptr, rc::Rc};

pub struct PreKeyBundle {
    raw: *mut sys::session_pre_key_bundle,
    #[allow(dead_code)]
    ctx: Rc<ContextInner>,
}

impl PreKeyBundle {
    pub fn new(
        registration_id: u32,
        device_id: u32,
        pre_key_id: u32,
        pre_key_public: &PublicKey,
        signed_pre_key_id: u32,
        signed_pre_key_public: &PublicKey,
        signature: &[u8],
        identity_key: &PublicKey,
    ) -> Result<PreKeyBundle, InternalError> {
        let mut raw = ptr::null_mut();

        unsafe {
            sys::session_pre_key_bundle_create(
                &mut raw,
                registration_id,
                device_id.try_into().unwrap(),
                pre_key_id,
                pre_key_public.raw_mut(),
                signed_pre_key_id,
                signed_pre_key_public.raw_mut(),
                signature.as_ptr(),
                signature.len(),
                identity_key.raw_mut(),
            );
        }
        unimplemented!()
    }
}

impl_wrapped!(sys::session_pre_key_bundle as PreKeyBundle);
