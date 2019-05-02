use libsignal_protocol_sys as sys;

pub trait SessionStore { }

// pub struct signal_protocol_session_store {
//     pub load_session_func: Option<unsafe extern "C" fn(record: *mut *mut signal_buffer, user_record: *mut *mut signal_buffer, address: *const signal_protocol_address, user_data: *mut c_void) -> c_int>,
//     pub get_sub_device_sessions_func: Option<unsafe extern "C" fn(sessions: *mut *mut signal_int_list, name: *const c_char, name_len: usize, user_data: *mut c_void) -> c_int>,
//     pub store_session_func: Option<unsafe extern "C" fn(address: *const signal_protocol_address, record: *mut u8, record_len: usize, user_record: *mut u8, user_record_len: usize, user_data: *mut c_void) -> c_int>,
//     pub contains_session_func: Option<unsafe extern "C" fn(address: *const signal_protocol_address, user_data: *mut c_void) -> c_int>,
//     pub delete_session_func: Option<unsafe extern "C" fn(address: *const signal_protocol_address, user_data: *mut c_void) -> c_int>,
//     pub delete_all_sessions_func: Option<unsafe extern "C" fn(name: *const c_char, name_len: usize, user_data: *mut c_void) -> c_int>,
//     pub destroy_func: Option<unsafe extern "C" fn(user_data: *mut c_void)>,
//     pub user_data: *mut c_void,
// }