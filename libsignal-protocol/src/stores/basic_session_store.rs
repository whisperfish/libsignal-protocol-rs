use crate::{
    stores::{SerializedSession, SessionStore},
    Address, InternalError,
};
use std::{cell::RefCell, collections::HashMap};

/// An in-memory [`SessionStore`].
#[derive(Debug, Default, Clone)]
pub struct BasicSessionStore {
    sessions: RefCell<HashMap<Address, SerializedSession>>,
}

impl SessionStore for BasicSessionStore {
    fn load_session(
        &self,
        address: Address,
    ) -> Result<Option<SerializedSession>, InternalError> {
        Ok(self.sessions.borrow().get(&address).cloned())
    }

    fn get_sub_device_sessions(
        &self,
        _name: &[u8],
    ) -> Result<Vec<i32>, InternalError> {
        unimplemented!()
    }
}
