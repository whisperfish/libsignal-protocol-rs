use std::mem;

/// A wrapper around `libsignal-protocol`'s native reference counted pointers.
#[derive(Debug)]
pub struct Raw<T: SignalType>(*mut T);

impl<T: SignalType> Raw<T> {
    /// Create a new [`Raw<T>`] from an owned pointer (doesn't affect reference
    /// count).
    pub fn from_ptr(raw: *mut T) -> Raw<T> { Raw(raw) }

    /// Create a new [`Raw<T>`] after bumping the reference count.
    pub fn copied_from(raw: *mut T) -> Raw<T> {
        unsafe {
            sys::signal_type_ref(SignalType::as_signal_base(raw));
        }

        Raw::from_ptr(raw)
    }

    pub fn as_ptr(&self) -> *mut T { self.0 }

    pub fn as_const_ptr(&self) -> *const T { self.0 }

    pub fn into_inner(self) -> *mut T {
        let ptr = self.0;
        mem::forget(self);
        ptr
    }

    pub fn ptr_eq(&self, other: &Raw<T>) -> bool { self.0 == other.0 }
}

impl<T: SignalType> Clone for Raw<T> {
    fn clone(&self) -> Raw<T> { Raw::copied_from(self.0) }
}

impl<T: SignalType> Drop for Raw<T> {
    fn drop(&mut self) {
        unsafe {
            sys::signal_type_unref(SignalType::as_signal_base(self.0));
        }
    }
}

pub trait SignalType {
    unsafe fn as_signal_base(this: *mut Self) -> *mut sys::signal_type_base;
}

macro_rules! impl_signal_type_base {
    ($type:ty) => {
        impl SignalType for $type {
            unsafe fn as_signal_base(this: *mut Self) -> *mut sys::signal_type_base {
                // NOTE: It is assumed that a signal_type_base is the first
                // element inside this struct and it's #[repr(C)]
                this as *mut sys::signal_type_base
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
    sys::ratchet_identity_key_pair, sys::session_signed_pre_key,
    sys::ec_public_key, sys::ec_private_key, sys::session_pre_key,
    sys::ec_key_pair,
}