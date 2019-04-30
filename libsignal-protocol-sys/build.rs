extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    let dst = cmake::build("libsignal-protocol-c");

    println!("cargo:rustc-link-search=native={}", dst.display());
    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=signal-protocol-c");

    main_library_bindings();
    protobuf_bindings();
}

fn main_library_bindings() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg("-Ilibsignal-protocol-c/src")
        .blacklist_function("fingerprint_generator_create")
        .blacklist_type("_.*")
        .whitelist_function("alice_.*")
        .whitelist_function("bob_.*")
        .whitelist_function("ciphertext_.*")
        .whitelist_function("curve_.*")
        .whitelist_function("device_.*")
        .whitelist_function("displayable_.*")
        .whitelist_function("ec_.*")
        .whitelist_function("fingerprint_.*")
        .whitelist_function("group_cipher_.*")
        .whitelist_function("group_session_.*")
        .whitelist_function("pre_key_.*")
        .whitelist_function("ratchet_.*")
        .whitelist_function("ratcheting_.*")
        .whitelist_function("scannable_.*")
        .whitelist_function("sender_.*")
        .whitelist_function("session_.*")
        .whitelist_function("signal_.*")
        .whitelist_function("symmetric_.*")
        .whitelist_var("CIPHERTEXT_.*")
        .whitelist_var("CURVE_.*")
        .whitelist_var("KEY_EXCHANGE_.*")
        .whitelist_var("PRE_KEY_.*")
        .whitelist_var("RATCHET_.*")
        .whitelist_var("SG_.*")
        .whitelist_var("SIGNAL_.*")
        .rustfmt_bindings(true)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn protobuf_bindings() {

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindgen::Builder::default()
        .header("libsignal-protocol-c/src/protobuf-c/protobuf-c.h")
        .clang_arg("-Ilibsignal-protocol-c/src/protobuf-c")
        .whitelist_function("protobuf_.*")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("protobuf.rs"))
        .expect("Couldn't write bindings!");
}