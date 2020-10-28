macro_rules! impl_serializable {
    ($name:ty, $serialize:ident) => {
        impl $crate::Serializable for $name {
            fn serialize(
                &self,
            ) -> Result<$crate::Buffer, $crate::errors::Error> {
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

macro_rules! impl_deserializable {
    ($name:ty, $deserialize:ident) => {
        impl_deserializable!($name, $deserialize, |raw, ctx| Self {
            raw,
            _ctx: std::rc::Rc::clone(&ctx.0),
        });
    };
    ($name:ty, $deserialize:ident, |$raw:ident, $ctx:ident| $constructed:expr) => {
        #[allow(unused_imports)]
        impl $crate::Deserializable for $name {
            fn deserialize(
                ctx: &$crate::Context,
                data: &[u8],
            ) -> Result<Self, $crate::errors::Error> {
                use $crate::errors::FromInternalErrorCode;

                let mut raw = std::mem::MaybeUninit::uninit();

                unsafe {
                    sys::$deserialize(
                        raw.as_mut_ptr(),
                        data.as_ptr(),
                        data.len() as _,
                        ctx.raw(),
                    )
                    .into_result()?;

                    let $raw =
                        $crate::raw_ptr::Raw::from_ptr(raw.assume_init());
                    let $ctx = ctx;

                    Ok($constructed)
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

/// An an alternative to [`assert!()`] for functions called from C.
macro_rules! signal_assert {
    ($condition:expr) => {
        signal_assert!($condition, $crate::InternalError::InvalidArgument);
    };
    ($condition:expr, $ret:expr) => {
        if !$condition {
            ::log::error!(
                "Assertion failed at {}#{}: {}",
                file!(),
                line!(),
                stringify!($condition),
            );
            let bt = backtrace::Backtrace::new();
            ::log::error!("{:?}", bt);

            return $ret.into();
        }
    };
}

macro_rules! signal_catch_unwind {
    ($operation:expr) => {
        match ::std::panic::catch_unwind(|| $operation) {
            Ok(got) => got,
            Err(panic_error) => {
                let msg = if let Some(m) = panic_error.downcast_ref::<&str>() {
                    m
                } else if let Some(m) = panic_error.downcast_ref::<String>() {
                    m.as_str()
                } else {
                    "Unknown panic"
                };

                ::log::error!(
                    "The expression `{}` panicked at {}#{}: {}",
                    stringify!($operation),
                    file!(),
                    line!(),
                    msg
                );

                return $crate::InternalError::Unknown.into();
            }
        }
    };
}
