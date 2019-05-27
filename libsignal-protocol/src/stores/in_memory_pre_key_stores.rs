use crate::{
    stores::{PreKeyStore, SignedPreKeyStore},
    InternalError,
};
use std::{
    cell::RefCell,
    collections::HashMap,
    io::{self, Write},
};

/// An in-memory [`PreKeyStore`].
#[derive(Debug, Default, PartialEq, Clone)]
pub struct InMemoryPreKeyStore(Inner);

impl PreKeyStore for InMemoryPreKeyStore {
    fn load(&self, id: u32, writer: &mut dyn Write) -> io::Result<()> {
        self.0.load(id, writer)
    }

    fn store(&self, id: u32, body: &[u8]) -> Result<(), InternalError> {
        self.0.store(id, body)
    }

    fn contains(&self, id: u32) -> bool { self.0.contains(id) }

    fn remove(&self, id: u32) -> Result<(), InternalError> { self.0.remove(id) }
}

/// An in-memory [`SignedPreKeyStore`].
#[derive(Debug, Default, PartialEq, Clone)]
pub struct InMemorySignedPreKeyStore(Inner);

impl SignedPreKeyStore for InMemorySignedPreKeyStore {
    fn load(&self, id: u32, writer: &mut dyn Write) -> io::Result<()> {
        self.0.load(id, writer)
    }

    fn store(&self, id: u32, body: &[u8]) -> Result<(), InternalError> {
        self.0.store(id, body)
    }

    fn contains(&self, id: u32) -> bool { self.0.contains(id) }

    fn remove(&self, id: u32) -> Result<(), InternalError> { self.0.remove(id) }
}

#[derive(Debug, Default, PartialEq, Clone)]
struct Inner {
    keys: RefCell<HashMap<u32, Vec<u8>>>,
}

impl Inner {
    fn load(&self, id: u32, writer: &mut dyn Write) -> io::Result<()> {
        match self.keys.borrow().get(&id) {
            Some(bytes) => writer.write_all(bytes),
            None => unimplemented!(),
        }
    }

    fn store(&self, id: u32, body: &[u8]) -> Result<(), InternalError> {
        self.keys.borrow_mut().insert(id, body.to_vec());
        Ok(())
    }

    fn contains(&self, id: u32) -> bool { self.keys.borrow().contains_key(&id) }

    fn remove(&self, id: u32) -> Result<(), InternalError> {
        self.keys.borrow_mut().remove(&id);
        Ok(())
    }
}
