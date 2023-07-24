use std::env;
use std::path::PathBuf;
use std::process::Command;
use std::io::Write;

use bindgen::CargoCallbacks;

fn main() {
    // Fetch Monocypher git submodule
    let output = Command::new("git")
            .args([
                "submodule",
                "update",
                "--init",
                "--depth=1",
        ])
        .output()
        .expect("Failed execute git!");

    std::io::stderr().write_all(&output.stdout).unwrap();
    std::io::stderr().write_all(&output.stderr).unwrap();

    if !output.status.success() {
        panic!("git submodule update failed! exit code: {}", output.status);
    }

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
        .allowlist_function("crypto_x25519_public_key")
        .allowlist_function("crypto_x25519")
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
