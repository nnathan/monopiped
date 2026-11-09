use std::env;
use std::path::PathBuf;

use bindgen::CargoCallbacks;

fn main() {
    // bindgen only tracks headers, so a change to the C source needs declaring.
    println!("cargo:rerun-if-changed=Monocypher/src/monocypher.c");

    // Compile monocypher from the source in the submodule.
    cc::Build::new()
        .file("Monocypher/src/monocypher.c")
        .include("Monocypher/src")
        .compile("monocypher");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        .allowlist_function("crypto_blake2b")
        .allowlist_function("crypto_blake2b_keyed")
        .allowlist_function("crypto_aead_.*lock")
        .allowlist_type("crypto_blake2b_ctx")
        .allowlist_function("crypto_blake2b_(init|update|final)")
        .allowlist_function("crypto_blake2b_keyed_init")
        .allowlist_function("crypto_verify(16|32|64)")
        .allowlist_function("crypto_wipe")
        .allowlist_function("crypto_poly1305(_init|_update|_final)?")
        .allowlist_type("crypto_poly1305_ctx")
        .allowlist_function("crypto_chacha20_(h|djb|ietf|x)")
        .allowlist_function("crypto_aead_(init_x|init_djb|init_ietf|write|read)")
        .allowlist_type("crypto_aead_ctx")
        .allowlist_function("crypto_eddsa_(key_pair|sign|check|to_x25519)")
        .allowlist_function("crypto_eddsa_(trim_scalar|reduce|mul_add|scalarbase|check_equation)")
        .allowlist_function("crypto_x25519_public_key")
        .allowlist_function("crypto_x25519")
        .allowlist_function("crypto_x25519_(to_eddsa|inverse|dirty_small|dirty_fast)")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
