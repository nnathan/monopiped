# mini-monocypher

mini-monocypher is provides API bindings to [Monocypher](https://monocypher.org/) via the raw FFI bindings provided by mini-monocypher-sys.

## Status

Not all of Monocypher API surfacce has been provided by mini-monocypher.
This is since hte main consumer (at the time of writing) is Monopiped
which only needs a subset of functionality. Over time more support will
be added until the library is full-fledged.

The current API supported:

  - `crypto_blake2b_*` functions
  - `crypto_aead_{lock,unlock}`
  - `crypto_aead_{init_x,init_djb,init_ietf,write,read}`
  - `crypto_x25519`
  - `crypto_x25519_public_key`
  - `crypto_x25519_{to_eddsa,inverse,dirty_small,dirty_fast}`
  - `crypto_eddsa_*` functions (the low-level building blocks are in the `hazmat` module)
  - `crypto_elligator_*` functions
  - `crypto_verify{16,32,64}`
  - `crypto_wipe`
  - `crypto_poly1305*` functions
  - `crypto_chacha20_{h,djb,ietf,x}`

## Known limitations

Monocypher allows the input and output of some functions, such as encryption
and decryption, to be the same or overlapping buffers. Rust does not allow a
buffer to be borrowed both mutably and immutably, so these bindings require
separate buffers.
