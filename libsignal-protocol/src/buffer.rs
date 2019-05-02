use libsignal_protocol_sys as sys;

use crate::context::ContextInner;
use crate::Wrapped;
use std::mem;
use std::rc::Rc;

const DEFAULT_BUFFER_SIZE: usize = 1024;

pub struct Buffer {
    raw: *mut sys::signal_buffer,
}

impl Buffer {
    pub fn new() -> Buffer {
        Buffer::with_capacity(DEFAULT_BUFFER_SIZE)
    }

    pub fn with_capacity(capacity: usize) -> Buffer {
        let raw = unsafe { sys::signal_buffer_alloc(capacity) };
        assert!(!raw.is_null());
        Buffer { raw }
    }

    pub fn len(&self) -> usize {
        unsafe { sys::signal_buffer_len(self.raw) }
    }

    pub fn into_raw(self) -> *mut sys::signal_buffer {
        let raw = self.raw;
        mem::forget(self);
        raw
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            let ptr = sys::signal_buffer_data(self.raw);
            assert!(!ptr.is_null());
            std::slice::from_raw_parts(ptr, self.len())
        }
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe {
            let len = self.len();
            let ptr = sys::signal_buffer_data(self.raw);
            assert!(!ptr.is_null());
            std::slice::from_raw_parts_mut(ptr, len)
        }
    }

    pub fn append(&mut self, data: &[u8]) {
        unsafe {
            sys::signal_buffer_append(self.raw, data.as_ptr(), data.len());
        }
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for Buffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_slice_mut()
    }
}

impl Clone for Buffer {
    fn clone(&self) -> Buffer {
        unsafe {
            let raw = sys::signal_buffer_copy(self.raw);
            assert!(!raw.is_null());
            Buffer { raw }
        }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        unsafe {
            sys::signal_buffer_free(self.raw);
        }
    }
}

impl Wrapped for Buffer {
    type Raw = sys::signal_buffer;

    unsafe fn from_raw(raw: *mut Self::Raw, _ctx: &Rc<ContextInner>) -> Self {
        Buffer { raw }
    }

    fn raw(&self) -> *const Self::Raw {
        self.raw
    }

    fn raw_mut(&mut self) -> *mut Self::Raw {
        self.raw
    }
}
