#![allow(dead_code)]

use libsignal_protocol::{
    crypto::{Crypto, Sha256Hmac, Sha512Digest},
    Address, Buffer, IdentityKeyStore, InternalError, PreKeyStore,
    SessionStore, SignalCipherType, SignedPreKeyStore,
};
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    io::{self, Write},
};

pub(crate) struct MockCrypto<C> {
    inner: C,
    random_func:
        Option<Box<Fn(&mut [u8]) -> Result<(), InternalError> + 'static>>,
}

impl<C: Crypto> MockCrypto<C> {
    pub fn new(inner: C) -> MockCrypto<C> {
        MockCrypto {
            inner,
            random_func: None,
        }
    }

    pub fn random_func<F>(mut self, func: F) -> Self
    where
        F: Fn(&mut [u8]) -> Result<(), InternalError> + 'static,
    {
        self.random_func = Some(Box::new(func));
        self
    }
}

impl<C: Crypto> Crypto for MockCrypto<C> {
    fn fill_random(&self, buffer: &mut [u8]) -> Result<(), InternalError> {
        if let Some(ref random_func) = self.random_func {
            random_func(buffer)
        } else {
            self.inner.fill_random(buffer)
        }
    }

    fn hmac_sha256(
        &self,
        key: &[u8],
    ) -> Result<Box<dyn Sha256Hmac>, InternalError> {
        self.inner.hmac_sha256(key)
    }

    fn sha512_digest(&self) -> Result<Box<dyn Sha512Digest>, InternalError> {
        self.inner.sha512_digest()
    }

    fn encrypt(
        &self,
        cipher: SignalCipherType,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, InternalError> {
        self.inner.encrypt(cipher, key, iv, data)
    }

    fn decrypt(
        &self,
        cipher: SignalCipherType,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, InternalError> {
        self.inner.decrypt(cipher, key, iv, data)
    }
}

pub fn fake_random_generator() -> impl Fn(&mut [u8]) -> Result<(), InternalError>
{
    let test_next_random = Cell::new(0);

    move |data| {
        for i in 0..data.len() {
            data[i] = test_next_random.get();
            test_next_random.set(test_next_random.get().wrapping_add(1));
        }

        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct BasicPreKeyStore {}

impl PreKeyStore for BasicPreKeyStore {
    fn load(&self, _id: u32, _writer: &mut dyn Write) -> io::Result<()> {
        unimplemented!()
    }

    fn store(&self, _id: u32, _body: &[u8]) -> Result<(), InternalError> {
        unimplemented!()
    }

    fn contains(&self, _id: u32) -> bool { unimplemented!() }

    fn remove(&self, _id: u32) -> Result<(), InternalError> { unimplemented!() }
}

#[derive(Debug, Default)]
pub struct BasicSignedPreKeyStore {}

impl SignedPreKeyStore for BasicSignedPreKeyStore {
    fn load(&self, _id: u32, _writer: &mut dyn Write) -> io::Result<()> {
        unimplemented!()
    }

    fn store(&self, _id: u32, _body: &[u8]) -> Result<(), InternalError> {
        unimplemented!()
    }

    fn contains(&self, _id: u32) -> bool { unimplemented!() }

    fn remove(&self, _id: u32) -> Result<(), InternalError> { unimplemented!() }
}

#[derive(Default)]
pub struct BasicSessionStore {
    sessions: RefCell<HashMap<OwnedAddress, (Buffer, Buffer)>>,
}

impl SessionStore for BasicSessionStore {
    fn load_session(
        &self,
        address: Address,
    ) -> Result<(Buffer, Buffer), InternalError> {
        let address = OwnedAddress::from(address);

        self.sessions
            .borrow()
            .get(&address)
            .cloned()
            .ok_or(InternalError::Unknown)
    }

    fn get_sub_device_sessions(&self) { unimplemented!() }
}

#[derive(Debug, Default)]
pub struct BasicIdentityKeyStore {
    registration_id: Cell<u32>,
    trusted_identities: RefCell<Vec<(OwnedAddress, Vec<u8>)>>,
}

#[derive(Debug, Hash, PartialEq, Eq)]
struct OwnedAddress {
    name: Vec<u8>,
    id: i32,
}

impl<'a> PartialEq<Address<'a>> for OwnedAddress {
    fn eq(&self, other: &Address<'a>) -> bool {
        self.id == other.device_id() && self.name.as_slice() == other.bytes()
    }
}

impl<'a> From<Address<'a>> for OwnedAddress {
    fn from(other: Address<'a>) -> OwnedAddress {
        OwnedAddress {
            name: other.bytes().to_vec(),
            id: other.device_id(),
        }
    }
}

impl IdentityKeyStore for BasicIdentityKeyStore {
    fn local_registration_id(&self) -> Result<u32, InternalError> {
        Ok(self.registration_id.get())
    }

    fn is_trusted_identity(
        &self,
        address: Address<'_>,
        identity_key: &[u8],
    ) -> Result<bool, InternalError> {
        let identities = self.trusted_identities.borrow();

        match identities.iter().position(|(addr, _)| *addr == address) {
            // if we already know this address, check the keys match
            Some(ix) => Ok(identities[ix].1.as_slice() == identity_key),
            // otherwise, blindly trust this unknown identity
            None => Ok(true),
        }
    }
}
