# mini-monocypher-sys

mini-monocypher-sys provides bindgen generated C bindings to [Monocypher](https://monocypher.org/) C library. It currently exposes only a subset of functionality which is exposed as an api by mini-monocypher crate.

## Status

The current bindings are generated:

  - `crypto_blake2b_*` functions
  - `crypto_aead_{lock,unlock}`
  - `crypto_x25519_*` functions
  - `crypto_verify{16,32,64}`
  - `crypto_wipe`
  - `crypto_poly1305*` functions
