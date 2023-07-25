//! # mini-monocypher
//!
//! A C-like Rust API for [`Monocypher`]
//!
//! This documentation covers the usage of Monocypher through these bindings,
//! but for the intricacies regarding cryptographic usage and security hygiene
//! it is recommended to refer to the [`Monocypher` manual].
//!
//! [`Monocypher`]: https://monocypher.org/
//! [`Monocypher` manual]: https://monocypher.org/manual/

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![deny(missing_docs)]

use std::error::Error;
use std::fmt;

/// Errors returned by Monocypher
#[derive(Debug)]
pub enum ErrorKind {
    /// Decryption failed due to incorrect nonce, integrity failure
    /// in ciphertext, or incorrect MAC.
    AuthenticationFailure,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "authentication failure trying to decrypt ciphertext")
    }
}

impl Error for ErrorKind {}

/// Computes a BLAKE2b hash for a message.
///
/// The output hash is written to `hash` which must have a length
/// between 1 and 64. Anything below 32 is discouraged when using
/// BLAKE2b as a general purpose hash function.
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_blake2b;
///
/// let mut hash = [0u8; 32];
/// let message = b"Lorem ipsum";
/// crypto_blake2b(&mut hash, message);
/// ```
///
/// # Panics
///
/// This function can panic if `hash.len()` is not between 1 and 64.
pub fn crypto_blake2b(hash: &mut [u8], message: &[u8]) {
    assert!(hash.len() > 0 && hash.len() <= 64);

    let hash_buf = hash.as_mut_ptr();
    let message_buf = message.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_blake2b(hash_buf, hash.len(), message_buf, message.len());
    }
}

/// Computes a BLAKE2b Message Authentication Code (MAC) for a message.
///
/// The output MAC is written to `hash` which must have a length
/// between 1 and 64. The input key material `key` must have a length
/// between 0 and 64.
///
/// # Examples
///
/// In this example we will derive a receive and transmit key from input key
/// material.
///
/// ```
/// use mini_monocypher::crypto_blake2b_keyed;
///
/// use rand_core::{OsRng, RngCore};
/// let mut input_key = [0u8; 32];
/// let mut rx_key = [0u8; 32];
/// let mut tx_key = [0u8; 32];
///
/// // usually key material comes from somewhere but for this example
/// // we will just fill with cryptographic random bytes
/// OsRng.fill_bytes(&mut input_key);
///
/// crypto_blake2b_keyed(&mut rx_key, &input_key, b"receive");
/// crypto_blake2b_keyed(&mut tx_key, &input_key, b"transmit");
/// ```
///
/// # Panics
///
/// This function can panic if `hash.len()` is not between 1 and 64,
/// or if `key.len()` is >64.
pub fn crypto_blake2b_keyed(hash: &mut [u8], key: &[u8], message: &[u8]) {
    assert!(hash.len() > 0 && hash.len() <= 64);
    assert!(key.len() <= 64);

    let hash_buf = hash.as_mut_ptr();
    let key_buf = key.as_ptr();
    let message_buf = message.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_blake2b_keyed(
            hash_buf,
            hash.len(),
            key_buf,
            key.len(),
            message_buf,
            message.len(),
        );
    }
}

/// BLAKE2b context for use with incremental interface.
type crypto_blake2b_ctx = mini_monocypher_sys::crypto_blake2b_ctx;

/// Returns a BLAKE2b context for use with the incremental interface.
/// Needs to be initialised with [`crypto_blake2b_init`].
pub fn crypto_blake2b_ctx_new() -> crypto_blake2b_ctx {
    crypto_blake2b_ctx {
        hash: [0u64; 8],
        input_offset: [0u64; 2],
        input: [0u64; 16],
        input_idx: 0,
        hash_size: 0,
    }
}

/// Initialises a BLAKE2B context for use with the incremental interface.
///
/// `hash_size` specifies the output hash length and must be between 1 and 64.
///
/// Use this interface if you don't want handle streams of data or large files
/// without using too much memory.
///
/// # Examples
///
/// This example demonstrates using the incremental interface.
///
/// ```
/// use mini_monocypher::{
///   crypto_blake2b_ctx_new,
///   crypto_blake2b_init,
///   crypto_blake2b_update,
///   crypto_blake2b_final,
/// };
///
/// let mut hash = [0u8; 32];
/// let mut ctx = crypto_blake2b_ctx_new();
///
/// crypto_blake2b_init(&mut ctx, hash.len());
/// crypto_blake2b_update(&mut ctx, b"Lorem");
/// crypto_blake2b_update(&mut ctx, b" ");
/// crypto_blake2b_update(&mut ctx, b"ipsum");
/// crypto_blake2b_final(&mut ctx, &mut hash);
/// ```
///
/// # Panics
///
/// The function will panic if `hash_size` is not between 1 and 64.
pub fn crypto_blake2b_init(ctx: &mut crypto_blake2b_ctx, hash_size: usize) {
    assert!(hash_size > 0 && hash_size <= 64);

    let ctx_ptr = ctx as *mut crypto_blake2b_ctx;

    unsafe {
        mini_monocypher_sys::crypto_blake2b_init(ctx_ptr, hash_size);
    }
}

/// Incrementally computes a BLAKE2b hash based on `ctx` and a message.
///
/// See [`crypto_blake2b_init`] for a full example of using the incremental
/// interface.
pub fn crypto_blake2b_update(ctx: &mut crypto_blake2b_ctx, message: &[u8]) {
    let ctx_ptr = ctx as *mut crypto_blake2b_ctx;
    let message_buf = message.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_blake2b_update(ctx_ptr, message_buf, message.len());
    }
}

/// Computes the final BLAKE2b hash based on `ctx`. The output of the hash
/// will reside in `hash`.
///
/// `hash.len()` must be at least the size specified as
/// `hash_size` in [`crypto_blake2b_init`] and cannot be greater than 64.
///
/// See [`crypto_blake2b_init`] for a full example of using the incremental
/// interface.
///
/// # Panics
///
/// This function will panic if `hash.len()` is >64.
pub fn crypto_blake2b_final(ctx: &mut crypto_blake2b_ctx, hash: &mut [u8]) {
    assert!(hash.len() > 0 && hash.len() <= 64);
    let ctx_ptr = ctx as *mut crypto_blake2b_ctx;
    let hash_buf = hash.as_mut_ptr();

    unsafe {
        mini_monocypher_sys::crypto_blake2b_final(ctx_ptr, hash_buf);
    }
}

/// Encrypts and authenticates a plaintext. The output can then be decrypted
/// by [`crypto_aead_unlock`].
///
/// Given a 32-byte cryptographic quality `key`, and a 24-byte unique or
/// random `nonce`, (optional) additional data `ad`, encrypts `plain_text` into
/// `cipher_text` and `mac`.
///
/// `cipher_text.len()` must be >= `plain_text.len()`.
///
/// It is recommended to read the AEAD section of the [`Monocypher` manual]
/// for the full intricacies on using the `crypto_aead_{lock,unlock}` interface.
///
/// # Examples
///
/// This example is a full end to end example of encryption and decryption:
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::{crypto_aead_lock, crypto_aead_unlock};
///
/// let mut key = [0u8; 32];
/// let mut nonce = [0u8; 24];
/// let ad = b"authentication data";
/// let plaintext = b"hello world";
/// let mut aead_ciphertext = [0u8; 11+16]; // plaintext.len() + MAC
///
/// OsRng.fill_bytes(&mut key);
/// OsRng.fill_bytes(&mut nonce);
///
/// // encrypt
///
/// // note: the aead_ciphertext is the ciphertext (size is plaintext.len())
/// // concatenated with the MAC. If using random nonce, you would also want
/// // to include nonce as part of the aead_ciphertext as well.
/// let (ciphertext_detached, mac) = aead_ciphertext.split_at_mut(plaintext.len());
///
/// crypto_aead_lock(
///     ciphertext_detached,
///     mac,
///     &key,
///     &nonce,
///     Some(ad),
///     plaintext,
/// );
///
/// // decrypt
///
/// let mut plaintext = [0u8; 11];
///
/// crypto_aead_unlock(
///     &mut plaintext,
///     &aead_ciphertext[(aead_ciphertext.len() - 16)..],
///     &key,
///     &nonce,
///     Some(ad),
///     &aead_ciphertext[..aead_ciphertext.len() - 16]
/// ).expect("decryption should succeed");
/// ```
///
/// # Panics
///
/// This function panics if `mac.len() != 16` or `key.len() != 32`
/// or `nonce.len() != 24` or if `cipher_text.len() < plain_text.len()`.
///
/// [`Monocypher` manual]: (https://monocypher.org/manual/aead)
pub fn crypto_aead_lock(
    cipher_text: &mut [u8],
    mac: &mut [u8],
    key: &[u8],
    nonce: &[u8],
    ad: Option<&[u8]>,
    plain_text: &[u8],
) {
    assert!(mac.len() == 16);
    assert!(key.len() == 32);
    assert!(nonce.len() == 24);
    assert!(cipher_text.len() >= plain_text.len());

    let cipher_text_buf = cipher_text.as_mut_ptr();
    let mac_buf = mac.as_mut_ptr();
    let key_buf = key.as_ptr();
    let nonce_buf = nonce.as_ptr();
    let (ad_buf, ad_len) = match ad {
        None => (std::ptr::null(), 0),
        Some(x) => (x.as_ptr(), x.len()),
    };
    let plain_text_buf = plain_text.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_aead_lock(
            cipher_text_buf,
            mac_buf,
            key_buf,
            nonce_buf,
            ad_buf,
            ad_len,
            plain_text_buf,
            plain_text.len(),
        );
    }
}

/// Decrypts an authenticated ciphertext. Returns `()` if successful,
/// or [`ErrorKind`] if there is a decryption failure.
///
/// Given a 32-byte cryptographic quality `key`, a 24-byte `nonce`,
/// (optional) additional data `ad`, decrypt `cipher_text` and 16-byte `mac` into
/// `plain_text`.
///
/// `plain_text.len()` must be >= `cipher_text.len()`.
///
/// See [`crypto_aead_lock`] for a full round trip example of performing
/// a lock (encrypt) and unlock (decrypt).
///
/// It crypto_aead_lockis recommended to read the AEAD section of the [`Monocypher` manual]
/// for the full intricacies on using the `crypto_aead_{lock,unlock}` interface.
///
/// # Panics
///
/// This function panics if `mac.len() != 16` or `key.len() != 32`
/// or `nonce.len() != 24` or if `plain_text.len() < cipher_text.len()`.
///
/// [`Monocypher` manual]: (https://monocypher.org/manual/aead)
pub fn crypto_aead_unlock(
    plain_text: &mut [u8],
    mac: &[u8],
    key: &[u8],
    nonce: &[u8],
    ad: Option<&[u8]>,
    cipher_text: &[u8],
) -> Result<(), ErrorKind> {
    assert!(mac.len() == 16);
    assert!(key.len() == 32);
    assert!(nonce.len() == 24);
    assert!(plain_text.len() >= cipher_text.len());

    let plain_text_buf = plain_text.as_mut_ptr();
    let mac_buf = mac.as_ptr();
    let key_buf = key.as_ptr();
    let nonce_buf = nonce.as_ptr();
    let (ad_buf, ad_len) = match ad {
        None => (std::ptr::null(), 0),
        Some(x) => (x.as_ptr(), x.len()),
    };
    let cipher_text_buf = cipher_text.as_ptr();

    unsafe {
        let result = mini_monocypher_sys::crypto_aead_unlock(
            plain_text_buf,
            mac_buf,
            key_buf,
            nonce_buf,
            ad_buf,
            ad_len,
            cipher_text_buf,
            cipher_text.len(),
        );

        if result != 0 {
            return Err(ErrorKind::AuthenticationFailure);
        }
    }

    Ok(())
}

/// Generate an X25519 public key from a secret key.
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::crypto_x25519_public_key;
///
/// let mut secret_key = [0u8; 32];
/// let mut public_key = [0u8; 32];
///
/// OsRng.fill_bytes(&mut secret_key);
/// crypto_x25519_public_key(&mut public_key, &secret_key);
/// ```
pub fn crypto_x25519_public_key(public_key: &mut [u8], secret_key: &[u8]) {
    assert!(public_key.len() == 32);
    assert!(secret_key.len() == 32);

    let pub_buf = public_key.as_mut_ptr();
    let secret_buf = secret_key.as_ptr();

    unsafe { mini_monocypher_sys::crypto_x25519_public_key(pub_buf, secret_buf) }
}

/// Perform an X25519 key exchange between `your_secret_key` and `their_public_key`.
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::{crypto_x25519, crypto_x25519_public_key};
///
/// let mut your_secret_key = [0u8; 32];
/// OsRng.fill_bytes(&mut your_secret_key);
///
/// // generate other party's public key
/// let mut their_secret_key = [0u8; 32]; // assume you don't know this
/// let mut their_public_key = [0u8; 32];
/// OsRng.fill_bytes(&mut their_secret_key);
/// crypto_x25519_public_key(&mut their_public_key, &their_secret_key);
///
/// // assume you only have: your_secret_key and their_public_key
/// let mut shared_secret = [0u8; 32];
/// crypto_x25519(&mut shared_secret, &your_secret_key, &their_public_key);
///
/// // to use shared_secret, use a crypto_blake2b as a KDF
/// // or crypto_blake2b_keyed with key=shared_secret to derive
/// // multiple keys
/// ```
pub fn crypto_x25519(
    raw_shared_secret: &mut [u8],
    your_secret_key: &[u8],
    their_public_key: &[u8],
) {
    assert!(raw_shared_secret.len() == 32);
    assert!(your_secret_key.len() == 32);
    assert!(their_public_key.len() == 32);

    let raw_buf = raw_shared_secret.as_mut_ptr();
    let secret_buf = your_secret_key.as_ptr();
    let pub_buf = their_public_key.as_ptr();

    unsafe { mini_monocypher_sys::crypto_x25519(raw_buf, secret_buf, pub_buf) }
}
