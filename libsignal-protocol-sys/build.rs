extern crate bindgen;

use std::{env, path::PathBuf};

fn main() {
    let dst = cmake::build("libsignal-protocol-c");

    println!("cargo:rustc-link-search=native={}", dst.display());
    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=signal-protocol-c");
}
