use crate::{
    keys::IdentityKeyPair, stores::IdentityKeyStore, Address, Buffer,
    InternalError, Serializable,
};
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
};

/// An in-memory [`IdentityKeyStore`].
#[derive(Debug)]
pub struct BasicIdentityKeyStore {
    registration_id: u32,
    identity: IdentityKeyPair,
    trusted_identities: RefCell<HashMap<Address, Vec<u8>>>,
    /// Should recipients be trusted the first time they are contacted?
    pub trust_on_first_message: bool,
}

impl BasicIdentityKeyStore {
    /// Create a new [`BasicIdentityKeyStore`].
    pub fn new(
        registration_id: u32,
        identity: &IdentityKeyPair,
    ) -> BasicIdentityKeyStore {
        BasicIdentityKeyStore {
            registration_id,
            trust_on_first_message: true,
            identity: identity.clone(),
            trusted_identities: Default::default(),
        }
    }
}

impl IdentityKeyStore for BasicIdentityKeyStore {
    fn local_registration_id(&self) -> Result<u32, InternalError> {
        Ok(self.registration_id)
    }

    fn identity_key_pair(&self) -> Result<(Buffer, Buffer), InternalError> {
        let private = self
            .identity
            .private()
            .serialize()
            .map_err(|_| InternalError::Unknown)?;
        let public = self
            .identity
            .public()
            .serialize()
            .map_err(|_| InternalError::Unknown)?;

        Ok((private, public))
    }

    fn is_trusted_identity(
        &self,
        address: Address,
        identity_key: &[u8],
    ) -> Result<bool, InternalError> {
        let identities = self.trusted_identities.borrow();

        if let Some(identity) = identities.get(&address) {
            Ok(identity_key == identity.as_slice())
        } else {
            Ok(self.trust_on_first_message)
        }
    }
}
