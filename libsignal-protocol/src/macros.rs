macro_rules! impl_wrapped {
    ($raw:ty as $wrapper:ident) => {
        impl $crate::Wrapped for $wrapper {
            type Raw = $raw;

            unsafe fn from_raw(raw: *mut Self::Raw, ctx: &std::rc::Rc<$crate::ContextInner>) -> Self {
                assert!(!raw.is_null());
                $wrapper { raw, ctx: Rc::clone(ctx) }
            }

            fn raw(&self) -> *const Self::Raw {
                self.raw
            }
            fn raw_mut(&self) -> *mut Self::Raw {
                self.raw
            }
        }
    };
    ( $($raw:ty as $wrapper:ident),* $(,)* ) => {
        $(
            impl_wrapped!($raw as $wrapper);
        )*
    };
}
