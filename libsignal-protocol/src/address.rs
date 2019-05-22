use libsignal_protocol_sys as sys;
use std::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    os::raw::c_char,
};

/// A reference to a signal address (recipient name, device ID tuple).
pub struct Address<'a> {
    raw: sys::signal_protocol_address,
    _string_lifetime: PhantomData<&'a ()>,
}

impl<'a> Address<'a> {
    /// Create a new [`Address`].
    pub fn new(name: &'a str, device_id: i32) -> Address<'a> {
        let raw = sys::signal_protocol_address {
            name: name.as_ptr() as *const c_char,
            name_len: name.len(),
            device_id,
        };

        unsafe { Address::from_raw(raw) }
    }

    /// Create a new [`Address`] from the raw struct.
    /// 
    /// # Safety
    /// 
    /// The `name` pointed to by the [`sys::signal_protocol_address`] must 
    /// outlive this [`Address`].
    pub(crate) unsafe fn from_raw(
        raw: sys::signal_protocol_address,
    ) -> Address<'a> {
        Address {
            raw,
            _string_lifetime: PhantomData,
        }
    }

    /// Create an [`Address`] from a pointer to the raw struct.
    /// 
    /// # Safety
    /// 
    /// (See the notes on [`Address::from_raw`])
    pub(crate) unsafe fn from_ptr(
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

    /// Get a string of bytes identifying a recipient (usually their name as a
    /// utf-8 string).
    ///
    /// You may also be looking for the [`Address::as_str`] method.
    pub fn bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self.raw.name as *const u8,
                self.raw.name_len,
            )
        }
    }

    /// Get the name attached to this address, converted to a `&str`.
    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(self.bytes())
    }

    /// Get the device ID attached to this address.
    pub fn device_id(&self) -> i32 { self.raw.device_id }
}

impl<'a> Clone for Address<'a> {
    fn clone(&self) -> Address<'a> {
        unsafe {
            Address::from_raw(sys::signal_protocol_address {
                name: self.raw.name,
                name_len: self.raw.name_len,
                device_id: self.raw.device_id,
            })
        }
    }
}

impl<'a> Debug for Address<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("Address");

        match self.as_str() {
            Ok(name) => {
                f.field("name", &name);
            },
            Err(_) => {
                f.field("name", &self.bytes());
            },
        }

        f.field("device_id", &self.device_id()).finish()
    }
}
