extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    let dst = cmake::build("libsignal-protocol-c");
    println!("cargo:rustc-link-search=native={}", dst.display());
    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=signal-protocol-c");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg("-Ilibsignal-protocol-c/src")
        .clang_arg("-Ilibsignal-protocol-c/src/protobuf-c")
        .whitelist_function("signal_.*")
        .whitelist_function("session_.*")
        .whitelist_function("protobuf_.*")
        .whitelist_var("SG_.*")
        .whitelist_var("SIGNAL_.*")
        .rustfmt_bindings(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
