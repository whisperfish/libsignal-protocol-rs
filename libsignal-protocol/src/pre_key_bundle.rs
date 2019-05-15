use crate::{keys::PublicKey, raw_ptr::Raw};
use failure::Error;
use std::{convert::TryInto, ptr};

pub struct PreKeyBundleBuilder {
    registration_id: Option<u32>,
    device_id: Option<u32>,
    pre_key_id: Option<u32>,
    pre_key_public: Option<PublicKey>,
    signed_pre_key_id: Option<u32>,
    signed_pre_key_public: Option<PublicKey>,
    signature: Option<Vec<u8>>,
    identity_key: Option<PublicKey>,
}

impl PreKeyBundleBuilder {
    pub fn pre_key(mut self, id: u32, public_key: &PublicKey) -> Self {
        self.pre_key_id = Some(id);
        self.pre_key_public = Some(public_key.clone());

        self
    }

    pub fn signed_pre_key(
        mut self,
        id: u32,
        signed_public_key: &PublicKey,
    ) -> Self {
        self.signed_pre_key_id = Some(id);
        self.signed_pre_key_public = Some(signed_public_key.clone());

        self
    }

    pub fn signature(mut self, sig: &[u8]) -> Self {
        self.signature = Some(sig.to_vec());
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

    pub fn identity_key(mut self, identity_key: &PublicKey) -> Self {
        self.identity_key = Some(identity_key.clone());
        self
    }

    pub fn build(self) -> Result<PreKeyBundle, Error> {
        if let PreKeyBundleBuilder {
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
                    pre_key_public.raw.as_ptr(),
                    signed_pre_key_id,
                    signed_pre_key_public.raw.as_ptr(),
                    signature.as_ptr(),
                    signature.len(),
                    identity_key.raw.as_ptr(),
                );
                Ok(PreKeyBundle {
                    raw: Raw::from_ptr(raw),
                })
            }
        } else {
            Err(failure::err_msg("Not all builder methods were executed"))
        }
    }
}

#[derive(Clone)]
pub struct PreKeyBundle {
    pub(crate) raw: Raw<sys::session_pre_key_bundle>,
}

impl PreKeyBundle {
    pub fn builder() -> PreKeyBundleBuilder {
        PreKeyBundleBuilder {
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
