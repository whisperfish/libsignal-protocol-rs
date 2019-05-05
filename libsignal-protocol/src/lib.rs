#[macro_use]
mod macros;
mod buffer;
mod context;
mod crypto;
mod errors;
mod identity_key_store;
pub mod keys;
mod pre_key_store;
mod session_builder;
mod session_store;
mod signed_pre_key_store;
mod store_context;

pub use crate::buffer::Buffer;
pub use crate::context::Context;
pub use crate::crypto::{Crypto, DefaultCrypto};
pub use crate::errors::InternalError;
pub use crate::identity_key_store::IdentityKeyStore;
pub use crate::pre_key_store::PreKeyStore;
pub use crate::session_builder::SessionBuilder;
pub use crate::session_store::SessionStore;
pub use crate::signed_pre_key_store::SignedPreKeyStore;
pub use crate::store_context::StoreContext;

use crate::context::ContextInner;
use libsignal_protocol_sys as sys;
use std::rc::Rc;

pub(crate) trait Wrapped: Sized {
    type Raw: ?Sized;

    unsafe fn from_raw(raw: *mut Self::Raw, ctx: &Rc<ContextInner>) -> Self;
    fn raw(&self) -> *const Self::Raw;
    fn raw_mut(&mut self) -> *mut Self::Raw;
}

pub struct Address {
    raw: *mut sys::signal_protocol_address,
    ctx: Rc<ContextInner>,
}

impl_wrapped!(sys::signal_protocol_address as Address);
