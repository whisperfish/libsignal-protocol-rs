#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub mod protobuf {
    include!(concat!(env!("OUT_DIR"), "/protobuf.rs"));
}

pub trait AsSignalTypeBase {
    fn as_signal_base(self) -> *mut signal_type_base;
}

macro_rules! impl_signal_type_base {
    ($type:ty) => {
        impl AsSignalTypeBase for *mut $type {
            fn as_signal_base(self) -> *mut signal_type_base {
                // NOTE: It is assumed that a signal_type_base is the first
                // element inside this struct and it's #[repr(C)]
                self as *mut signal_type_base
            }
        }
    };
    ($($type:ty),* $(,)*) => {
        $(
            impl_signal_type_base!($type);
        )*
    };
}

impl_signal_type_base! {
    ratchet_identity_key_pair, session_signed_pre_key, ec_public_key,
    ec_private_key, 
}
