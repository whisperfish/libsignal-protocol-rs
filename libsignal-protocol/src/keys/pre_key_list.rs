use crate::{keys::PreKey, raw_ptr::Raw};
use std::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

pub struct PreKeyList {
    head: *mut sys::signal_protocol_key_helper_pre_key_list_node,
}

impl PreKeyList {
    pub(crate) fn from_raw(
        head: *mut sys::signal_protocol_key_helper_pre_key_list_node,
    ) -> PreKeyList {
        PreKeyList { head }
    }

    pub fn iter<'this>(&'this self) -> impl Iterator<Item = PreKey> + 'this {
        PreKeyListIter {
            head: self.head,
            _lifetime: PhantomData,
        }
    }
}

impl Drop for PreKeyList {
    fn drop(&mut self) {
        unsafe {
            sys::signal_protocol_key_helper_key_list_free(self.head);
        }
    }
}

impl Debug for PreKeyList {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PreKeyList").finish()
    }
}

pub struct PreKeyListIter<'a> {
    _lifetime: PhantomData<&'a ()>,
    head: *mut sys::signal_protocol_key_helper_pre_key_list_node,
}

impl<'a> Iterator for PreKeyListIter<'a> {
    type Item = PreKey;

    fn next(&mut self) -> Option<Self::Item> {
        if self.head.is_null() {
            return None;
        }

        unsafe {
            let elem =
                sys::signal_protocol_key_helper_key_list_element(self.head);
            assert!(!elem.is_null());

            self.head =
                sys::signal_protocol_key_helper_key_list_next(self.head);

            Some(PreKey {
                raw: Raw::copied_from(elem),
            })
        }
    }
}
