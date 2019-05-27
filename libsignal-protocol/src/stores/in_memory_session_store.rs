use crate::{
    stores::{SerializedSession, SessionStore},
    Address, InternalError,
};
use std::{cell::RefCell, collections::HashMap};

/// An in-memory [`SessionStore`].
#[derive(Debug, Default, Clone)]
pub struct InMemorySessionStore {
    sessions: RefCell<HashMap<Address, SerializedSession>>,
}

impl SessionStore for InMemorySessionStore {
    fn load_session(
        &self,
        address: Address,
    ) -> Result<Option<SerializedSession>, InternalError> {
        Ok(self.sessions.borrow().get(&address).cloned())
    }

    fn get_sub_device_sessions(
        &self,
        name: &[u8],
    ) -> Result<Vec<i32>, InternalError> {
        Ok(self
            .sessions
            .borrow()
            .keys()
            .filter_map(|addr| {
                if addr.bytes() == name {
                    Some(addr.device_id())
                } else {
                    None
                }
            })
            .collect())
    }

    fn store_session(
        &self,
        addr: Address,
        session: SerializedSession,
    ) -> Result<(), InternalError> {
        self.sessions.borrow_mut().insert(addr, session);
        Ok(())
    }

    fn delete_session(&self, addr: Address) -> Result<(), InternalError> {
        self.sessions.borrow_mut().remove(&addr);
        Ok(())
    }

    fn delete_all_sessions(&self, name: &[u8]) -> Result<usize, InternalError> {
        let mut sessions = self.sessions.borrow_mut();

        let to_delete: Vec<_> = sessions
            .keys()
            .filter(|addr| addr.bytes() == name)
            .cloned()
            .collect();

        for addr in &to_delete {
            sessions.remove(addr);
        }

        Ok(to_delete.len())
    }

    fn contains_session(&self, addr: Address) -> Result<bool, InternalError> {
        Ok(self.sessions.borrow().contains_key(&addr))
    }
}
