//! Generate the identity keys, registration ID, and prekeys.
//!
//! A rust equivalent of the [Client Install Time][cit] example from
//! `libsignal-protocol-c`'s README.
//!
//! ```c
//! ratchet_identity_key_pair *identity_key_pair;
//! uint32_t registration_id;
//! signal_protocol_key_helper_pre_key_list_node *pre_keys_head;
//! session_signed_pre_key *signed_pre_key;
//!
//! signal_protocol_key_helper_generate_identity_key_pair(&identity_key_pair, global_context);
//! signal_protocol_key_helper_generate_registration_id(&registration_id, 0, global_context);
//! signal_protocol_key_helper_generate_pre_keys(&pre_keys_head, start_id, 100, global_context);
//! signal_protocol_key_helper_generate_signed_pre_key(&signed_pre_key, identity_key_pair, 5, timestamp, global_context);
//!
//! /* Store identity_key_pair somewhere durable and safe. */
//! /* Store registration_id somewhere durable and safe. */
//!
//! /* Store pre keys in the pre key store. */
//! /* Store signed pre key in the signed pre key store. */
//! ```
//!
//! cit: https://github.com/signalapp/libsignal-protocol-c#client-install-time

use failure::Error;
use libsignal_protocol::Context;
use std::time::SystemTime;

fn main() -> Result<(), Error> {
    let ctx = Context::default();
    let extended_range = 0;
    let start = 123;
    let pre_key_count = 20;

    let identity_key_pair = ctx.generate_identity_key_pair()?;
    let signed_pre_key =
        ctx.generate_signed_pre_key(&identity_key_pair, 5, SystemTime::now())?;
    println!(
        "Signed pre key ID: {} at {:?}",
        signed_pre_key.id(),
        signed_pre_key.timestamp()
    );

    let registration_id = ctx.generate_registration_id(extended_range)?;
    println!("Registration ID: {}", registration_id);

    let pre_keys = ctx.generate_pre_keys(start, pre_key_count)?;

    let pre_key_ids: Vec<_> = pre_keys
        .iter()
        .map(|session_key| session_key.id())
        .collect();

    println!("Pre Key session IDs:");
    println!("{:?}", pre_key_ids);

    Ok(())
}
