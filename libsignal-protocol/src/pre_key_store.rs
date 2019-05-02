use libsignal_protocol_sys as sys;

use std::os::raw::{c_int, c_void};
use std::pin::Pin;

pub trait PreKeyStore {}

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
    _record: *mut *mut sys::signal_buffer,
    _pre_key_id: u32,
    _user_data: *mut c_void,
) -> c_int {
    unimplemented!()
}

unsafe extern "C" fn store_pre_key(
    _pre_key_id: u32,
    _record: *mut u8,
    _record_len: usize,
    _user_data: *mut c_void,
) -> c_int {
    unimplemented!()
}

unsafe extern "C" fn contains_pre_key(_pre_key_id: u32, _user_data: *mut c_void) -> c_int {
    unimplemented!()
}

unsafe extern "C" fn remove_pre_key(_pre_key_id: u32, _user_data: *mut c_void) -> c_int {
    unimplemented!()
}

unsafe extern "C" fn destroy_func(user_data: *mut c_void) {
    let user_data = Box::from_raw(user_data as *mut State);
    drop(user_data);
}
