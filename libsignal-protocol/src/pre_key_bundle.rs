use crate::{keys::PublicKey, Context, ContextInner, Wrapped};
use failure::Error;
use std::{convert::TryInto, ptr, rc::Rc};

pub struct PreKeyBundleBuilder<'a> {
    ctx: Rc<ContextInner>,
    registration_id: Option<u32>,
    device_id: Option<u32>,
    pre_key_id: Option<u32>,
    pre_key_public: Option<&'a PublicKey>,
    signed_pre_key_id: Option<u32>,
    signed_pre_key_public: Option<&'a PublicKey>,
    signature: Option<&'a [u8]>,
    identity_key: Option<&'a PublicKey>,
}

impl<'a> PreKeyBundleBuilder<'a> {
    pub fn pre_key(mut self, id: u32, public_key: &'a PublicKey) -> Self {
        self.pre_key_id = Some(id);
        self.pre_key_public = Some(public_key);

        self
    }

    pub fn signed_pre_key(
        mut self,
        id: u32,
        signed_public_key: &'a PublicKey,
    ) -> Self {
        self.signed_pre_key_id = Some(id);
        self.signed_pre_key_public = Some(signed_public_key);

        self
    }

    pub fn signature(mut self, sig: &'a [u8]) -> Self {
        self.signature = Some(sig);
        self
    }

    pub fn registration_id(mut self, id: u32) -> Self {
        self.registration_id = Some(id);
        self
    }

    pub fn device_id(mut self, id: u32) -> Self {
        self.device_id = Some(id);
        self
    }

    pub fn identity_key(mut self, identity_key: &'a PublicKey) -> Self {
        self.identity_key = Some(identity_key);
        self
    }

    pub fn build(self) -> Result<PreKeyBundle, Error> {
        if let PreKeyBundleBuilder {
            ctx,
            registration_id: Some(registration_id),
            device_id: Some(device_id),
            pre_key_id: Some(pre_key_id),
            pre_key_public: Some(pre_key_public),
            signed_pre_key_id: Some(signed_pre_key_id),
            signed_pre_key_public: Some(signed_pre_key_public),
            signature: Some(signature),
            identity_key: Some(identity_key),
        } = self
        {
            unsafe {
                let mut raw = ptr::null_mut();

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
                Ok(PreKeyBundle::from_raw(raw, &ctx))
            }
        } else {
            Err(failure::err_msg("Not all builder methods were executed"))
        }
    }
}

pub struct PreKeyBundle {
    raw: *mut sys::session_pre_key_bundle,
    #[allow(dead_code)]
    ctx: Rc<ContextInner>,
}

impl PreKeyBundle {
    pub fn builder<'a>(ctx: &Context) -> PreKeyBundleBuilder<'a> {
        PreKeyBundleBuilder {
            ctx: Rc::clone(&ctx.0),
            registration_id: None,
            device_id: None,
            pre_key_id: None,
            pre_key_public: None,
            signed_pre_key_id: None,
            signed_pre_key_public: None,
            signature: None,
            identity_key: None,
        }
    }
}

impl_wrapped!(sys::session_pre_key_bundle as PreKeyBundle);
