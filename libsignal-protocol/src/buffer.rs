use libsignal_protocol_sys as sys;

use crate::context::ContextInner;
use crate::Wrapped;
use std::mem;
use std::ops::{Index, IndexMut};
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

impl<T> Index<T> for Buffer
where
    [u8]: Index<T>,
{
    type Output = <[u8] as Index<T>>::Output;

    fn index(&self, ix: T) -> &Self::Output {
        self.as_slice().index(ix)
    }
}

impl<T> IndexMut<T> for Buffer
where
    [u8]: IndexMut<T>,
{
    fn index_mut(&mut self, ix: T) -> &mut Self::Output {
        self.as_slice_mut().index_mut(ix)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_delete() {
        let buffer = Buffer::new();
        drop(buffer);
    }

    #[test]
    fn create_with_capacity() {
        let cap = 12345;
        let buffer = Buffer::with_capacity(cap);
        assert_eq!(buffer.len(), cap);
    }

    #[test]
    fn get_an_item() {
        let mut buffer = Buffer::new();
        buffer[10] = 0xde;
        buffer[11] = 0xad;
        buffer[12] = 0xbe;
        buffer[13] = 0xef;

        let dead_beef = &buffer[10..14];
        assert_eq!(dead_beef, &[0xde, 0xad, 0xbe, 0xef]);
    }
}
