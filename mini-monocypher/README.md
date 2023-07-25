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
  - `crypto_x25519_*` functions
