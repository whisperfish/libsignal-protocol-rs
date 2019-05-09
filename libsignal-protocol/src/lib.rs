extern crate libsignal_protocol_sys as sys;

#[macro_use]
mod macros;
mod address;
mod buffer;
mod context;
mod crypto;
mod errors;
mod identity_key_store;
pub mod keys;
mod pre_key;
mod session_builder;

mod pre_key_store;

mod pre_key_bundle;
mod session_store;
mod signed_pre_key_store;
mod store_context;

pub use crate::{
    address::Address,
    buffer::Buffer,
    context::Context,
    crypto::{Crypto, DefaultCrypto},
    errors::InternalError,
    identity_key_store::IdentityKeyStore,
    pre_key_bundle::PreKeyBundle,
    pre_key::PreKey,
    pre_key_store::PreKeyStore,
    session_builder::SessionBuilder,
    session_store::SessionStore,
    signed_pre_key_store::SignedPreKeyStore,
    store_context::StoreContext,
};

use crate::context::ContextInner;
use std::rc::Rc;

pub(crate) trait Wrapped: Sized {
    type Raw: ?Sized;

    unsafe fn from_raw(raw: *mut Self::Raw, ctx: &Rc<ContextInner>) -> Self;
    fn raw(&self) -> *const Self::Raw;
    fn raw_mut(&self) -> *mut Self::Raw;
}
