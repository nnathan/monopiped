# Provenance of vectors.h

`vectors.h` is an unmodified copy of `tests/vectors.h` from the Monocypher 4.0.3
release tarball. It is not in Monocypher's git repository, as it is generated
when a release is made. It is used by `../upstream.rs` and is not part of the
published crate.

- Source: https://monocypher.org/download/monocypher-4.0.3.tar.gz
- Tarball SHA-512: `40904ada5c7ee4f7741733e38b69a30a4b0561cbffba5ffe7c2dce16136d540251ec0d9056ff606510d3b5b708fb8a40db7e0870d4a0b2dc17ba2bfb880f8965`
- vectors.h SHA-256: `d899dc1592a0280d9f5cd694da6bfdbff23db7d7a8d86ced957ce0d2d0113f0d`
- vectors.h SHA-512: `c6b83b5c6cbdbe16e6dae4b056940b7c3a561ce5bef3196e9961f05974b6f2d00fc37f517857e913044503beed72952b48ec6e48ce7f41ef255a449ac40d142a`

The tarball hash matches the checksum Monocypher publishes at
https://monocypher.org/download/monocypher-4.0.3.tar.gz.sha512. `../upstream.rs`
checks the SHA-512 of this file.

The file is a fixed artifact of that release. It combines official vectors with
vectors generated using libsodium and ed25519-donna. Regenerating it has not
been tried, so treat the hashes above as identifying this copy rather than as
proof that a regenerated file would be identical.

Monocypher is dual-licensed under BSD-2-Clause or CC0-1.0, see its LICENCE.md.
