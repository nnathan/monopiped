# Monopiped

Experimental prototype of reimplementing [spiped](https://www.tarsnap.com/spiped.html) using [Monocypher](https://monocypher.org/).

The primary difference is there will be an un-keyed mode that will perform a key-exchange using Elligator2 to allow obfuscation of TCP protocols. The keyed mode will just be an unauthenticated Curve25519 Diffie-Hellman exchange encrypted under a pre-shared key with ChaCha20-Poly1305.

But so far... nothing to see here yet.
