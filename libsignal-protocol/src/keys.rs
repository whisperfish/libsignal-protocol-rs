use libsignal_protocol_sys as sys;

pub struct IdentityKeyPair(*mut sys::ratchet_identity_key_pair);

pub struct PreKeyList(*mut sys::signal_protocol_key_helper_pre_key_list_node);

pub struct SignedPreKey(*mut sys::session_signed_pre_key);

impl_wrapped! {
    sys::ratchet_identity_key_pair as IdentityKeyPair,
    sys::signal_protocol_key_helper_pre_key_list_node as PreKeyList,
    sys::session_signed_pre_key as SignedPreKey,
}
