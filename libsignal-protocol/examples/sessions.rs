//! Create a signal session.
//!
//! A rust equivalent of the [Building A Session][bas] example from
//! `libsignal-protocol-c`'s README.
//!
//! ```c
//! /* Create the data store context, and add all the callbacks to it */
//! signal_protocol_store_context *store_context;
//! signal_protocol_store_context_create(&store_context, context);
//! signal_protocol_store_context_set_session_store(store_context, &session_store);
//! signal_protocol_store_context_set_pre_key_store(store_context, &pre_key_store);
//! signal_protocol_store_context_set_signed_pre_key_store(store_context, &signed_pre_key_store);
//! signal_protocol_store_context_set_identity_key_store(store_context, &identity_key_store);
//!
//! /* Instantiate a session_builder for a recipient address. */
//! signal_protocol_address address = {
//!     "+14159998888", 12, 1
//! };
//! session_builder *builder;
//! session_builder_create(&builder, store_context, &address, global_context);
//!
//! /* Build a session with a pre key retrieved from the server. */
//! session_builder_process_pre_key_bundle(builder, retrieved_pre_key);
//!
//! /* Create the session cipher and encrypt the message */
//! session_cipher *cipher;
//! session_cipher_create(&cipher, store_context, &address, global_context);
//!
//! ciphertext_message *encrypted_message;
//! session_cipher_encrypt(cipher, message, message_len, &encrypted_message);
//!
//! /* Get the serialized content and deliver it */
//! signal_buffer *serialized = ciphertext_message_get_serialized(encrypted_message);
//!
//! deliver(signal_buffer_data(serialized), signal_buffer_len(serialized));
//!
//! /* Cleanup */
//! SIGNAL_UNREF(encrypted_message);
//! session_cipher_free(cipher);
//! session_builder_free(builder);
//! signal_protocol_store_context_destroy(store_context);
//! ```
//!
//! [bas]: https://github.com/signalapp/libsignal-protocol-c#building-a-session

#[path = "../tests/helpers/mod.rs"]
mod helpers;

use self::helpers::{
    BasicIdentityKeyStore, BasicPreKeyStore, BasicSessionStore,
    BasicSignedPreKeyStore,
};
use failure::Error;
use libsignal_protocol::{
    Address, Context, PreKeyBundle, Serializable, SessionBuilder, SessionCipher,
};

fn main() -> Result<(), Error> {
    let ctx = Context::default();

    let pre_key_store = BasicPreKeyStore::default();
    let signed_pre_key_store = BasicSignedPreKeyStore::default();
    let session_store = BasicSessionStore::default();
    let identity_key_store = BasicIdentityKeyStore::default();

    let store_ctx = ctx.store_context(
        pre_key_store,
        signed_pre_key_store,
        session_store,
        identity_key_store,
    )?;

    let addr = Address::new("+14159998888", 1);

    // Instantiate a session_builder for a recipient address.
    let session_builder = SessionBuilder::new(&ctx, &store_ctx, addr.clone());

    let pre_key_bundle = PreKeyBundle::builder().build()?;

    // Build a session with a pre key retrieved from the server.
    session_builder.process_pre_key_bundle(&pre_key_bundle)?;

    let cipher = SessionCipher::new(&ctx, &store_ctx, addr.clone())?;
    let message = "Hello, World!";
    let encrypted_message = cipher.encrypt(message.as_bytes())?;

    let serialized = encrypted_message.serialize()?;

    println!("Encrypted Message: {:?}", serialized.as_slice());

    Ok(())
}
