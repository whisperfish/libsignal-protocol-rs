use crate::{buffer::Buffer, errors::InternalError};
use std::{
    io::{self, Write},
    os::raw::{c_int, c_void},
};

/// Something which can store signed pre-keys without inspecting their contents.
pub trait SignedPreKeyStore {
    /// Load a signed pre-key.
    fn load(&self, id: u32, writer: &mut dyn Write) -> io::Result<()>;
    /// Store a signed pre-key.
    fn store(&self, id: u32, body: &[u8]) -> Result<(), InternalError>;
    /// Is the signed pre-key with this ID present in the store?
    fn contains(&self, id: u32) -> bool;
    /// Remove a signed pre-key from the store.
    fn remove(&self, id: u32) -> Result<(), InternalError>;
}

pub(crate) fn new_vtable<P>(
    store: P,
) -> sys::signal_protocol_signed_pre_key_store
where
    P: SignedPreKeyStore + 'static,
{
    let state: Box<State> = Box::new(State(Box::new(store)));

    sys::signal_protocol_signed_pre_key_store {
        user_data: Box::into_raw(state) as *mut c_void,
        load_signed_pre_key: Some(load_signed_pre_key),
        store_signed_pre_key: Some(store_signed_pre_key),
        contains_signed_pre_key: Some(contains_signed_pre_key),
        remove_signed_pre_key: Some(remove_signed_pre_key),
        destroy_func: Some(destroy_func),
    }
}

struct State(Box<dyn SignedPreKeyStore>);

unsafe extern "C" fn load_signed_pre_key(
    record: *mut *mut sys::signal_buffer,
    pre_key_id: u32,
    user_data: *mut c_void,
) -> c_int {
    assert!(!user_data.is_null());
    assert!(!record.is_null());
    let user_data = &*(user_data as *const State);
    let mut buffer = Buffer::new();

    match user_data.0.load(pre_key_id, &mut buffer) {
        Ok(_) => {
            *record = buffer.into_raw();
            sys::SG_SUCCESS as c_int
        },
        Err(_) => InternalError::Unknown.code(),
    }
}

unsafe extern "C" fn store_signed_pre_key(
    pre_key_id: u32,
    record: *mut u8,
    record_len: usize,
    user_data: *mut c_void,
) -> c_int {
    assert!(!user_data.is_null());
    assert!(!record.is_null());
    let user_data = &*(user_data as *const State);
    let data = std::slice::from_raw_parts(record, record_len);

    match user_data.0.store(pre_key_id, data) {
        Ok(_) => sys::SG_SUCCESS as c_int,
        Err(e) => e.code(),
    }
}

unsafe extern "C" fn contains_signed_pre_key(
    pre_key_id: u32,
    user_data: *mut c_void,
) -> c_int {
    assert!(!user_data.is_null());
    let user_data = &*(user_data as *const State);

    user_data.0.contains(pre_key_id) as c_int
}

unsafe extern "C" fn remove_signed_pre_key(
    pre_key_id: u32,
    user_data: *mut c_void,
) -> c_int {
    assert!(!user_data.is_null());
    let user_data = &*(user_data as *const State);

    match user_data.0.remove(pre_key_id) {
        Ok(_) => sys::SG_SUCCESS as c_int,
        Err(e) => e.code(),
    }
}

unsafe extern "C" fn destroy_func(user_data: *mut c_void) {
    if !user_data.is_null() {
        let user_data = Box::from_raw(user_data as *mut State);
        drop(user_data);
    }
}
