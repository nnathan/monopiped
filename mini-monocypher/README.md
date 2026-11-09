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

## History

Before Claude there had been one version of this release, 0.1.0, where mini-monocypher was hand written in the era where LLMs and code generation had not taken over. The plan was always to get to fidelity with the Monocypher API, but it would have been a time consuming task.

In the era of Claude Code and high quality models it made sense to use one here. The quality of the code would be great for a small project like this because incrementally supporting the Monocypher API is very much a mechanical process, and Monocypher itself is incredibly LLM friendly. So I unleashed the LLM on this repository, but because it is cryptography related I reviewed all of the code that was generated.

I stayed in the loop to decide which Rust safety features to use while keeping fidelity with the C API and avoiding idiomatic Rust abstraction which would make the API too foreign for someone that has used Monocypher before.

I can attest that Claude has done a better job than I could ever do and at breakneck speed.

Thanks to Claude, as of version 0.3.0 we have fidelity with Monocypher 4.0.3.

## Known limitations

Monocypher allows the input and output of some functions, such as encryption
and decryption, to be the same or overlapping buffers. Rust does not allow a
buffer to be borrowed both mutably and immutably, so these bindings require
separate buffers.
