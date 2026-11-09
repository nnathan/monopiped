# mini-monocypher

mini-monocypher provides API bindings to [Monocypher](https://monocypher.org/) via the raw FFI bindings provided by mini-monocypher-sys.

## Status

mini-monocypher binds the full public API of Monocypher 4.0.3, including the
optional SHA-512 and Ed25519 functions. Functions keep their C names and
argument order, so the [Monocypher manual](https://monocypher.org/manual/)
applies directly.

The bindings differ from C in these ways:

  - Fixed-size parameters such as `key[32]` are arrays such as `&[u8; 32]`.
  - A pointer and its size are a single slice.
  - `Option` is used where a NULL pointer is meaningful or the parameter is
    optional, such as additional data.
  - Functions returning an `int` status return a `Result`.
  - Invalid buffer sizes and parameter limits panic instead of being undefined
    behaviour. Rules that cannot be checked, such as never reusing a nonce, are
    still the caller's responsibility.
  - Contexts are opaque, are created with a `*_ctx_new` function, and are wiped
    when they go out of scope.
  - The Argon2 algorithm is an enum, usable by the same names as in C.
  - The low-level EdDSA building blocks are in the `hazmat` module.

## Known limitations

Monocypher allows the input and output of some functions, such as encryption
and decryption, to be the same or overlapping buffers. Rust does not allow a
buffer to be borrowed both mutably and immutably, so these bindings require
separate buffers.
