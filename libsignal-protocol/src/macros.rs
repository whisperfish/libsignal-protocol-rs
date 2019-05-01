macro_rules! impl_wrapped {
    ($raw:ty as $wrapper:ident) => {
        impl $crate::Wrapped for $wrapper {
            type Raw = $raw;

            unsafe fn from_raw(raw: *mut Self::Raw) -> Self {
                assert!(!raw.is_null());
                $wrapper(raw)
            }

            fn raw(&self) -> *const Self::Raw {
                self.0
            }
            fn raw_mut(&mut self) -> *mut Self::Raw {
                self.0
            }
        }
    };
    ( $($raw:ty as $wrapper:ident),* $(,)* ) => {
        $(
            impl_wrapped!($raw as $wrapper);
        )*
    };
}
