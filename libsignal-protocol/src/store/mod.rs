pub(crate) mod identity_key_store;
pub(crate) mod pre_key_store;
pub(crate) mod session_store;
pub(crate) mod signed_pre_key_store;

pub use self::{
    identity_key_store::IdentityKeyStore,
    pre_key_store::PreKeyStore,
    session_store::{SerializedSession, SessionStore},
    signed_pre_key_store::SignedPreKeyStore,
};

#[cfg(feature = "in-memory-store")]
pub mod in_memory_store {
    use crate::{keys::IdentityKeyPair, Address, InternalError};
    use std::{borrow::ToOwned, collections::HashMap, sync::Mutex};

    pub struct InMemoryIdentityKeyStore<'a> {
        trusted_keys: Mutex<HashMap<Address<'a>, Vec<u8>>>,
        local_registration_id: u32,
        identity_key_pair: IdentityKeyPair,
    }

    impl<'a> InMemoryIdentityKeyStore<'a> {
        pub fn new(
            identity_key_pair: IdentityKeyPair,
            local_registration_id: u32,
        ) -> Self {
            Self {
                trusted_keys: Mutex::new(HashMap::new()),
                local_registration_id,
                identity_key_pair,
            }
        }
    }

    impl<'a> super::IdentityKeyStore<'a> for InMemoryIdentityKeyStore<'a> {
        fn identity_key_pair(&self) -> Result<IdentityKeyPair, InternalError> {
            Ok(self.identity_key_pair.clone())
        }

        fn local_registration_id(&self) -> Result<u32, InternalError> {
            Ok(self.local_registration_id)
        }

        fn save_identity(
            &self,
            address: Address<'a>,
            identity_key: &[u8],
        ) -> Result<bool, InternalError> {
            let mut guard = self
                .trusted_keys
                .lock()
                .map_err(|_| InternalError::Unknown)?;
            let existing = guard.contains_key(&address);
            if !existing {
                guard.insert(address, identity_key.to_owned());
                Ok(true)
            } else {
                Ok(false)
            }
        }

        fn is_trusted_identity(
            &self,
            address: Address,
            identity_key: &[u8],
        ) -> Result<bool, InternalError> {
            let guard = self
                .trusted_keys
                .lock()
                .map_err(|_| InternalError::Unknown)?;
            let identity = guard.get(&address);
            let is_trusted = identity.is_none() || {
                if let Some(data) = identity {
                    data.as_slice() == identity_key
                } else {
                    false
                }
            };
            Ok(is_trusted)
        }
    }
}
