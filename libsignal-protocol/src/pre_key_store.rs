use libsignal_protocol_sys as sys;

use crate::buffer::Buffer;
use crate::errors::InternalError;
use std::io::{self, Write};
use std::os::raw::{c_int, c_void};
use std::pin::Pin;

pub trait PreKeyStore {
    fn load_pre_key(&self, id: u32, writer: &mut dyn Write) -> io::Result<()>;
    fn store_pre_key(&self, id: u32, body: &[u8]) -> Result<(), InternalError>;
    fn contains_pre_key(&self, id: u32) -> Result<(), InternalError>;
    fn remove_pre_key(&self, id: u32) -> Result<(), InternalError>;
}

pub(crate) struct PreKeyStoreVtable {
    vtable: sys::signal_protocol_pre_key_store,
    state: Pin<Box<State>>,
}

impl PreKeyStoreVtable {
    pub fn new<P: PreKeyStore + 'static>(store: P) -> PreKeyStoreVtable {
        let mut state: Pin<Box<State>> = Box::pin(State(Box::new(store)));

        let vtable = sys::signal_protocol_pre_key_store {
            user_data: state.as_mut().get_mut() as *mut State as *mut c_void,
            load_pre_key: Some(load_pre_key),
            store_pre_key: Some(store_pre_key),
            contains_pre_key: Some(contains_pre_key),
            remove_pre_key: Some(remove_pre_key),
            destroy_func: Some(destroy_func),
        };

        PreKeyStoreVtable { vtable, state }
    }
}

struct State(Box<dyn PreKeyStore>);

unsafe extern "C" fn load_pre_key(
    record: *mut *mut sys::signal_buffer,
    pre_key_id: u32,
    user_data: *mut c_void,
) -> c_int {
    assert!(!user_data.is_null());
    assert!(!record.is_null());
    let user_data = &*(user_data as *const State);
    let mut buffer = Buffer::new();

    match user_data.0.load_pre_key(pre_key_id, &mut buffer) {
        Ok(_) => {
            *record = buffer.into_raw();
            sys::SG_SUCCESS as c_int
        }
        Err(e) => InternalError::Unknown.code(),
    }
}

unsafe extern "C" fn store_pre_key(
    pre_key_id: u32,
    record: *mut u8,
    record_len: usize,
    user_data: *mut c_void,
) -> c_int {
    assert!(!user_data.is_null());
    assert!(!record.is_null());
    let user_data = &*(user_data as *const State);
    let data = std::slice::from_raw_parts(record, record_len);

    match user_data.0.store_pre_key(pre_key_id, data) {
        Ok(_) => sys::SG_SUCCESS as c_int,
        Err(e) => e.code(),
    }
}

unsafe extern "C" fn contains_pre_key(pre_key_id: u32, user_data: *mut c_void) -> c_int {
    assert!(!user_data.is_null());
    let user_data = &*(user_data as *const State);

    match user_data.0.contains_pre_key(pre_key_id) {
        Ok(_) => sys::SG_SUCCESS as c_int,
        Err(e) => e.code(),
    }
}

unsafe extern "C" fn remove_pre_key(pre_key_id: u32, user_data: *mut c_void) -> c_int {
    assert!(!user_data.is_null());
    let user_data = &*(user_data as *const State);

    match user_data.0.remove_pre_key(pre_key_id) {
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
