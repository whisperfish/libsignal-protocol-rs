use crate::{errors::InternalError, Address, Buffer};
use std::os::raw::{c_char, c_int, c_void};

pub trait SessionStore {
    fn load_session(
        &self,
        address: &Address,
    ) -> Result<(Buffer, Buffer), InternalError>;
    fn get_sub_devuce_sessions(&self);
}

pub(crate) fn new_vtable<S: SessionStore + 'static>(
    session_store: S,
) -> sys::signal_protocol_session_store {
    let state: Box<State> = Box::new(State(Box::new(session_store)));

    sys::signal_protocol_session_store {
        user_data: Box::into_raw(state) as *mut c_void,
        load_session_func: Some(load_session_func),
        get_sub_device_sessions_func: Some(get_sub_device_sessions_func),
        store_session_func: Some(store_session_func),
        contains_session_func: Some(contains_session_func),
        delete_session_func: Some(delete_session_func),
        delete_all_sessions_func: Some(delete_all_sessions_func),
        destroy_func: Some(destroy_func),
    }
}

struct State(Box<dyn SessionStore>);

unsafe extern "C" fn load_session_func(
    _record: *mut *mut sys::signal_buffer,
    _user_record: *mut *mut sys::signal_buffer,
    _address: *const sys::signal_protocol_address,
    _user_data: *mut c_void,
) -> c_int {
    unimplemented!()
}

unsafe extern "C" fn get_sub_device_sessions_func(
    _sessions: *mut *mut sys::signal_int_list,
    _name: *const c_char,
    _name_len: usize,
    _user_data: *mut c_void,
) -> c_int {
    unimplemented!()
}

unsafe extern "C" fn store_session_func(
    _address: *const sys::signal_protocol_address,
    _record: *mut u8,
    _record_len: usize,
    _user_record: *mut u8,
    _user_record_len: usize,
    _user_data: *mut c_void,
) -> c_int {
    unimplemented!()
}

unsafe extern "C" fn contains_session_func(
    _address: *const sys::signal_protocol_address,
    _user_data: *mut c_void,
) -> c_int {
    unimplemented!()
}

unsafe extern "C" fn delete_session_func(
    _address: *const sys::signal_protocol_address,
    _user_data: *mut c_void,
) -> c_int {
    unimplemented!()
}

unsafe extern "C" fn delete_all_sessions_func(
    _name: *const c_char,
    _name_len: usize,
    _user_data: *mut c_void,
) -> c_int {
    unimplemented!()
}

unsafe extern "C" fn destroy_func(user_data: *mut c_void) {
    let user_data = Box::from_raw(user_data as *mut State);
    drop(user_data);
}
