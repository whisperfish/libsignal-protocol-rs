macro_rules! impl_serializable {
    ($name:ty, $serialize:ident, $deserialize:ident) => {
        impl $crate::Serializable for $name {
            fn deserialize(_data: &[u8]) -> Result<Self, failure::Error>
            where
                Self: Sized,
            {
                unimplemented!()
            }

            fn serialize(&self) -> Result<$crate::Buffer, failure::Error> {
                #[allow(unused_imports)]
                use $crate::errors::FromInternalErrorCode;

                unsafe {
                    let mut buffer = std::ptr::null_mut();
                    sys::$serialize(&mut buffer, self.raw.as_const_ptr())
                        .into_result()?;
                    Ok($crate::Buffer::from_raw(buffer))
                }
            }
        }
    };
}

macro_rules! impl_is_a {
    ($child:ty => $parent:ty) => {
        unsafe impl $crate::raw_ptr::IsA<$parent> for $child {
            unsafe fn upcast(this: *mut Self) -> *mut $parent {
                this as *mut $parent
            }
        }
    };
    ($($child:ty => $parent:ty),* $(,)*) => {
        $(
            impl_is_a!($child => $parent);
        )*
    };
}
