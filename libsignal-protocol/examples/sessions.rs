//! signal_protocol_store_context *store_context;
//! signal_protocol_store_context_create(&store_context, context);
//! signal_protocol_store_context_set_session_store(store_context, &session_store);
//! signal_protocol_store_context_set_pre_key_store(store_context, &pre_key_store);
//! signal_protocol_store_context_set_signed_pre_key_store(store_context, &signed_pre_key_store);
//! signal_protocol_store_context_set_identity_key_store(store_context, &identity_key_store);

use libsignal_protocol::Context;
use failure::Error;

fn main() -> Result<(), Error> {
    let ctx = Context::default();
    let mut store_ctx = ctx.new_store_context()?;

    Ok(())
}