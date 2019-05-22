use crate::{errors::InternalError, Address, Buffer};
use std::os::raw::{c_char, c_int, c_void};

/// A serialized session.
#[derive(Debug, Clone, PartialEq)]
pub struct SerializedSession {
    /// The session itself.
    pub session: Buffer,
    /// Extra data attached by the user (e.g. a name or other information).
    pub extra_data: Option<Buffer>,
}

/// Something which can store the sessions established with recipients.
pub trait SessionStore {
    /// Get a copy of the serialized session record corresponding to the
    /// provided recipient [`Address`].
    fn load_session(
        &self,
        address: Address<'_>,
    ) -> Result<Option<SerializedSession>, InternalError>;

    /// Get the IDs of all known devices with active sessions for a recipient.
    fn get_sub_device_sessions(
        &self,
        name: &[u8],
    ) -> Result<Vec<i32>, InternalError>;
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
    record: *mut *mut sys::signal_buffer,
    user_record: *mut *mut sys::signal_buffer,
    address: *const sys::signal_protocol_address,
    user_data: *mut c_void,
) -> c_int {
    assert!(!record.is_null());
    assert!(!user_record.is_null());
    assert!(!address.is_null());
    assert!(!user_data.is_null());

    let state = &*(user_data as *const State);
    let address = Address::from_ptr(address);

    match state.0.load_session(address) {
        Ok(Some(SerializedSession {
            session,
            extra_data,
        })) => {
            *record = session.into_raw();
            if let Some(extra_data) = extra_data {
                *user_record = extra_data.into_raw();
            }

            1
        },
        Ok(None) => 0,
        Err(e) => e.code(),
    }
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
