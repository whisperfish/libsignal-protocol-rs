use crate::{errors::InternalError, Address, Buffer};
use std::os::raw::{c_int, c_void};

pub trait IdentityKeyStore {
    // Get the local client's identity key pair.
    fn identity_key_pair(&self) -> Result<(Buffer, Buffer), InternalError>;

    /// Get the local client's registration ID.
    ///
    /// Clients should maintain a registration ID, a random number
    /// between 1 and 16380 that's generated once at install time.
    fn local_registration_id(&self) -> Result<u32, InternalError>;

    /// Verify a remote client's identity key.
    /// Determine whether a remote client's identity is trusted.  Convention is
    /// that the TextSecure protocol is 'trust on first use.'  This means that
    /// an identity key is considered 'trusted' if there is no entry for the
    /// recipient in the local store, or if it matches the saved key for a
    /// recipient in the local store.  Only if it mismatches an entry in the
    /// local store is it considered 'untrusted.'
    fn is_trusted_identity(
        &self,
        address: Address<'_>,
        identity_key: &[u8],
    ) -> Result<bool, InternalError>;
}

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
    user_data: *mut c_void,
    registration_id: *mut u32,
) -> c_int {
    let user_data = &*(user_data as *const State);

    match user_data.0.local_registration_id() {
        Ok(id) => {
            *registration_id = id;
            sys::SG_SUCCESS as c_int
        },
        Err(e) => e.code(),
    }
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
    address: *const sys::signal_protocol_address,
    key_data: *mut u8,
    key_len: usize,
    user_data: *mut c_void,
) -> c_int {
    assert!(!address.is_null());
    assert!(!key_data.is_null());
    assert!(!user_data.is_null());

    let user_data = &*(user_data as *const State);
    let address = Address::from_raw(sys::signal_protocol_address {
        name: (*address).name,
        name_len: (*address).name_len,
        device_id: (*address).device_id,
    });
    let key = std::slice::from_raw_parts(key_data, key_len);

    match user_data.0.is_trusted_identity(address, key) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(e) => e.code(),
    }
}

unsafe extern "C" fn destroy_func(user_data: *mut c_void) {
    if !user_data.is_null() {
        let user_data = Box::from_raw(user_data as *mut State);
        drop(user_data);
    }
}
