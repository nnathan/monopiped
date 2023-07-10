# Monopiped

Monopiped is a pastiche of Colin Percival's [spiped](https://www.tarsnap.com/spiped.html).

## Motivation

Originally Monopiped was intended to modify spiped and replace crypto primitives by those available in [Monocypher](https://monocypher.org/) (e.g. X25519 instead of finite field Diffie-Hellman, ChaCha20Poly1305 instead of AES-CTR+HMAC, etc.).

However since inception there was no progress on this front.

The idea pivoted from being a modification of spiped to instead a reinterpretation in Rust, primarily as a technical exercise for the author to learn Rust and dabble in cryptography and sockets.

## Aspirations

~Currently the program implements a one thread per connection model. To minimise resources and improve scalability (as if it's needed) maybe the model will be switched to asynchronous network I/O using Tokio.~

It would also be nice to support proxying over WebSockets.
