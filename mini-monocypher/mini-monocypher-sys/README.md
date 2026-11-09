# mini-monocypher-sys

mini-monocypher-sys provides bindgen generated C bindings to [Monocypher](https://monocypher.org/) C library. It currently exposes only a subset of functionality which is exposed as an api by mini-monocypher crate.

## Status

The current bindings are generated:

  - `crypto_blake2b_*` functions
  - `crypto_aead_{lock,unlock}`
  - `crypto_aead_{init_x,init_djb,init_ietf,write,read}`
  - `crypto_x25519`
  - `crypto_x25519_public_key`
  - `crypto_x25519_{to_eddsa,inverse,dirty_small,dirty_fast}`
  - `crypto_eddsa_*` functions
  - `crypto_elligator_*` functions
  - `crypto_argon2`
  - `crypto_sha512*` functions, including HMAC and HKDF
  - `crypto_ed25519_*` functions
  - `crypto_verify{16,32,64}`
  - `crypto_wipe`
  - `crypto_poly1305*` functions
  - `crypto_chacha20_{h,djb,ietf,x}`
