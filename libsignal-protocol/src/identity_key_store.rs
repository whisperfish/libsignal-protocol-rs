use libsignal_protocol_sys as sys;

use std::os::raw::{c_int, c_void};

pub trait IdentityKeyStore {}

pub(crate) fn new_vtable<I: IdentityKeyStore + 'static>(
    identity_key_store: I,
) -> sys::signal_protocol_identity_key_store {
    let state: Box<State> = Box::new(State(Box::new(identity_key_store)));

    sys::signal_protocol_identity_key_store {
        user_data: Box::into_raw(state) as *mut c_void,
        get_identity_key_pair: Some(get_identity_key_pair),
        get_local_registration_id: Some(get_local_registration_id),
        save_identity: Some(save_identity),
        is_trusted_identity: Some(is_trusted_identity),
        destroy_func: Some(destroy_func),
    }
}

struct State(Box<dyn IdentityKeyStore>);

unsafe extern "C" fn get_identity_key_pair(
    _public_data: *mut *mut sys::signal_buffer,
    _private_data: *mut *mut sys::signal_buffer,
    _user_data: *mut c_void,
) -> c_int {
    unimplemented!()
}

unsafe extern "C" fn get_local_registration_id(
    _user_data: *mut c_void,
    _registration_id: *mut u32,
) -> c_int {
    unimplemented!()
}

unsafe extern "C" fn save_identity(
    _address: *const sys::signal_protocol_address,
    _key_data: *mut u8,
    _key_len: usize,
    _user_data: *mut c_void,
) -> c_int {
    unimplemented!()
}

unsafe extern "C" fn is_trusted_identity(
    _address: *const sys::signal_protocol_address,
    _key_data: *mut u8,
    _key_len: usize,
    _user_data: *mut c_void,
) -> c_int {
    unimplemented!()
}

unsafe extern "C" fn destroy_func(_user_data: *mut c_void) {
    unimplemented!()
}
