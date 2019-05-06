use libsignal_protocol_sys as sys;
use std::ffi::CString;
use std::pin::Pin;

pub struct Address {
    raw: sys::signal_protocol_address,
    // Note: self.raw has a raw pointer into this field.
    _name: Pin<CString>,
}

impl Address {
    pub fn new<S: AsRef<str>>(name: S, device_id: i32) -> Address {
        let name = name.as_ref();
        let len = name.len();

        let name =
            Pin::new(CString::new(name).expect("The name shouldn't contain any null characters"));
        let raw = sys::signal_protocol_address {
            name: name.as_ptr(),
            name_len: len,
            device_id,
        };

        Address { raw, _name: name }
    }

    pub(crate) fn raw(&self) -> *const sys::signal_protocol_address {
        &self.raw
    }
}
