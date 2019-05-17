use crate::{keys::PublicKey, raw_ptr::Raw};
use failure::{Error, ResultExt};
use std::{convert::TryFrom, ptr};

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

    fn get_registration_id(&self) -> Result<u32, Error> {
        self.registration_id
            .clone()
            .ok_or_else(|| failure::err_msg("a registration ID is required"))
    }

    fn get_device_id(&self) -> Result<i32, Error> {
        let id = self
            .device_id
            .clone()
            .ok_or_else(|| failure::err_msg("a device ID is required"))?;

        i32::try_from(id)
            .context("invalid device ID")
            .map_err(Error::from)
    }

    fn get_identity_key(&self) -> Result<*mut sys::ec_public_key, Error> {
        match self.identity_key {
            Some(ref key) => Ok(key.raw.as_ptr()),
            None => Err(failure::err_msg("Identity key is required")),
        }
    }

    fn get_pre_key(&self) -> Result<(u32, *mut sys::ec_public_key), Error> {
        if let PreKeyBundleBuilder {
            pre_key_id: Some(id),
            pre_key_public: Some(ref public),
            ..
        } = self
        {
            Ok((*id, public.raw.as_ptr()))
        } else {
            Err(failure::err_msg("PreKey ID and public key are required"))
        }
    }

    fn get_signed_pre_key(&self) -> (u32, *mut sys::ec_public_key) {
        if let PreKeyBundleBuilder {
            signed_pre_key_id: Some(id),
            signed_pre_key_public: Some(ref public),
            ..
        } = self
        {
            (*id, public.raw.as_ptr())
        } else {
            (0, ptr::null_mut())
        }
    }

    pub fn build(self) -> Result<PreKeyBundle, Error> {
        let registration_id = self.get_registration_id()?;
        let device_id = self.get_device_id()?;
        let (pre_key_id, pre_key_public) = self.get_pre_key()?;
        let (signed_pre_key_id, signed_pre_key_public) =
            self.get_signed_pre_key();
        let signature = self
            .signature
            .as_ref()
            .map(|sig| sig.as_slice())
            .unwrap_or(&[]);
        let identity_key = self.get_identity_key()?;

        unsafe {
            let mut raw = ptr::null_mut();

            sys::session_pre_key_bundle_create(
                &mut raw,
                registration_id,
                device_id,
                pre_key_id,
                pre_key_public,
                signed_pre_key_id,
                signed_pre_key_public,
                signature.as_ptr(),
                signature.len(),
                identity_key,
            );
            Ok(PreKeyBundle {
                raw: Raw::from_ptr(raw),
            })
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
