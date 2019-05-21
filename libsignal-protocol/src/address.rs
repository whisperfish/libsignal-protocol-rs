use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    marker::PhantomData,
    os::raw::c_char,
};

use libsignal_protocol_sys as sys;

pub struct Address<'a> {
    raw: sys::signal_protocol_address,
    _string_lifetime: PhantomData<&'a ()>,
}

impl<'a> Address<'a> {
    pub fn new(name: &'a str, device_id: i32) -> Address<'a> {
        let raw = sys::signal_protocol_address {
            name: name.as_ptr() as *const c_char,
            name_len: name.len(),
            device_id,
        };

        Address::from_raw(raw)
    }

    pub fn from_raw(raw: sys::signal_protocol_address) -> Address<'a> {
        Address {
            raw,
            _string_lifetime: PhantomData,
        }
    }

    pub unsafe fn from_ptr(
        raw: *const sys::signal_protocol_address,
    ) -> Address<'a> {
        Address::from_raw(sys::signal_protocol_address {
            name: (*raw).name,
            name_len: (*raw).name_len,
            device_id: (*raw).device_id,
        })
    }

    pub(crate) fn raw(&self) -> *const sys::signal_protocol_address {
        &self.raw
    }

    pub fn bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self.raw.name as *const u8,
                self.raw.name_len,
            )
        }
    }

    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(self.bytes())
    }

    pub fn device_id(&self) -> i32 { self.raw.device_id }

    pub fn name(&self) -> &str {
        unsafe {
            let buf = std::slice::from_raw_parts(
                self.raw.name as *const u8,
                self.raw.name_len,
            );
            // i think it is safe here to use *_unchecked version of that
            // function, since we pass `&str` to the `new` method
            // so it must be a valid utf8 !
            std::str::from_utf8_unchecked(buf)
        }
    }
}

impl<'a> Clone for Address<'a> {
    fn clone(&self) -> Address<'a> {
        Address::from_raw(sys::signal_protocol_address {
            name: self.raw.name,
            name_len: self.raw.name_len,
            device_id: self.raw.device_id,
        })
    }
}

impl<'a> Ord for Address<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.device_id().cmp(&other.device_id())
    }
}

impl<'a> PartialEq for Address<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.name() == other.name() && self.device_id() == other.device_id()
    }
}

impl<'a> PartialOrd for Address<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> Hash for Address<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_i32(self.device_id());
        state.write(self.bytes());
    }
}

impl<'a> Eq for Address<'a> {}
