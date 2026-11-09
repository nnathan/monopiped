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
#[non_exhaustive]
pub enum ErrorKind {
    /// Decryption failed due to incorrect nonce, integrity failure
    /// in ciphertext, or incorrect MAC.
    AuthenticationFailure,
    /// A constant time comparison found the inputs are different.
    Mismatch,
    /// A signature is not valid for the given public key and message.
    InvalidSignature,
    /// A public key cannot be hidden by [`crypto_elligator_rev`].
    UnsuitableForHiding,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ErrorKind::AuthenticationFailure => {
                write!(f, "authentication failure trying to decrypt ciphertext")
            }
            ErrorKind::Mismatch => write!(f, "inputs to constant time comparison are different"),
            ErrorKind::InvalidSignature => write!(f, "invalid signature"),
            ErrorKind::UnsuitableForHiding => write!(f, "public key is unsuitable for hiding"),
        }
    }
}

impl Error for ErrorKind {}

/// Computes a BLAKE2b hash for a message.
///
/// The output hash is written to `hash` which must have a length
/// between 1 and 64. Anything below 32 is discouraged when using
/// BLAKE2b as a general purpose hash function.
///
/// It is recommended to read the [`Monocypher` manual] before using this
/// function.
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
///
/// [`Monocypher` manual]: https://monocypher.org/manual/blake2b
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
///
/// The contents are private as Monocypher trusts them when writing to memory.
///
/// As added safety over Monocypher, the context is also wiped when it goes out
/// of scope, which covers a context abandoned before [`crypto_blake2b_final`].
/// Copies left behind when the context was moved are not affected.
#[repr(transparent)]
pub struct crypto_blake2b_ctx(mini_monocypher_sys::crypto_blake2b_ctx);

impl Drop for crypto_blake2b_ctx {
    fn drop(&mut self) {
        let ctx_ptr = &mut self.0 as *mut mini_monocypher_sys::crypto_blake2b_ctx;

        unsafe {
            mini_monocypher_sys::crypto_wipe(
                ctx_ptr.cast(),
                std::mem::size_of::<mini_monocypher_sys::crypto_blake2b_ctx>(),
            );
        }
    }
}

/// Returns a BLAKE2b context for use with the incremental interface.
/// Needs to be initialised with [`crypto_blake2b_init`].
pub fn crypto_blake2b_ctx_new() -> crypto_blake2b_ctx {
    crypto_blake2b_ctx(mini_monocypher_sys::crypto_blake2b_ctx {
        hash: [0u64; 8],
        input_offset: [0u64; 2],
        input: [0u64; 16],
        input_idx: 0,
        hash_size: 0,
    })
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

    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_blake2b_ctx;

    unsafe {
        mini_monocypher_sys::crypto_blake2b_init(ctx_ptr, hash_size);
    }
}

/// Initialises a BLAKE2b context for computing a Message Authentication Code
/// (MAC) with the incremental interface.
///
/// `hash_size` specifies the output hash length and must be between 1 and 64.
/// The input key material `key` must have a length between 0 and 64. An empty
/// `key` is equivalent to using [`crypto_blake2b_init`].
///
/// # Examples
///
/// This example computes a MAC over a message supplied in pieces.
///
/// ```
/// use mini_monocypher::{
///   crypto_blake2b_ctx_new,
///   crypto_blake2b_keyed_init,
///   crypto_blake2b_update,
///   crypto_blake2b_final,
/// };
///
/// let mut mac = [0u8; 32];
/// let key = [0x42u8; 32];
/// let mut ctx = crypto_blake2b_ctx_new();
///
/// crypto_blake2b_keyed_init(&mut ctx, mac.len(), &key);
/// crypto_blake2b_update(&mut ctx, b"Lorem");
/// crypto_blake2b_update(&mut ctx, b" ");
/// crypto_blake2b_update(&mut ctx, b"ipsum");
/// crypto_blake2b_final(&mut ctx, &mut mac);
/// ```
///
/// # Panics
///
/// This function can panic if `hash_size` is not between 1 and 64,
/// or if `key.len()` is >64.
pub fn crypto_blake2b_keyed_init(ctx: &mut crypto_blake2b_ctx, hash_size: usize, key: &[u8]) {
    assert!(hash_size > 0 && hash_size <= 64);
    assert!(key.len() <= 64);

    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_blake2b_ctx;
    let key_buf = key.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_blake2b_keyed_init(ctx_ptr, hash_size, key_buf, key.len());
    }
}

/// Incrementally computes a BLAKE2b hash based on `ctx` and a message.
///
/// See [`crypto_blake2b_init`] for a full example of using the incremental
/// interface.
pub fn crypto_blake2b_update(ctx: &mut crypto_blake2b_ctx, message: &[u8]) {
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_blake2b_ctx;
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
/// This function will panic if `hash.len()` is >64 or is less than the
/// `hash_size` specified in [`crypto_blake2b_init`].
pub fn crypto_blake2b_final(ctx: &mut crypto_blake2b_ctx, hash: &mut [u8]) {
    assert!(hash.len() > 0 && hash.len() <= 64);
    assert!(hash.len() >= ctx.0.hash_size);
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_blake2b_ctx;
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
/// Unlike Monocypher, `cipher_text` and `plain_text` cannot be the same buffer
/// for in-place encryption, as Rust does not allow a buffer to be borrowed
/// both mutably and immutably. Separate buffers must be used.
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
///     mac.try_into().unwrap(),
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
///     aead_ciphertext[(aead_ciphertext.len() - 16)..].try_into().unwrap(),
///     &key,
///     &nonce,
///     Some(ad),
///     &aead_ciphertext[..aead_ciphertext.len() - 16]
/// ).expect("decryption should succeed");
/// ```
///
/// # Panics
///
/// This function panics if `cipher_text.len() < plain_text.len()`.
///
/// [`Monocypher` manual]: https://monocypher.org/manual/aead
pub fn crypto_aead_lock(
    cipher_text: &mut [u8],
    mac: &mut [u8; 16],
    key: &[u8; 32],
    nonce: &[u8; 24],
    ad: Option<&[u8]>,
    plain_text: &[u8],
) {
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
/// Unlike Monocypher, `plain_text` and `cipher_text` cannot be the same buffer
/// for in-place decryption, as Rust does not allow a buffer to be borrowed
/// both mutably and immutably. Separate buffers must be used.
///
/// See [`crypto_aead_lock`] for a full round trip example of performing
/// a lock (encrypt) and unlock (decrypt).
///
/// It crypto_aead_lockis recommended to read the AEAD section of the [`Monocypher` manual]
/// for the full intricacies on using the `crypto_aead_{lock,unlock}` interface.
///
/// # Panics
///
/// This function panics if `plain_text.len() < cipher_text.len()`.
///
/// [`Monocypher` manual]: https://monocypher.org/manual/aead
pub fn crypto_aead_unlock(
    plain_text: &mut [u8],
    mac: &[u8; 16],
    key: &[u8; 32],
    nonce: &[u8; 24],
    ad: Option<&[u8]>,
    cipher_text: &[u8],
) -> Result<(), ErrorKind> {
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
pub fn crypto_x25519_public_key(public_key: &mut [u8; 32], secret_key: &[u8; 32]) {
    let pub_buf = public_key.as_mut_ptr();
    let secret_buf = secret_key.as_ptr();

    unsafe { mini_monocypher_sys::crypto_x25519_public_key(pub_buf, secret_buf) }
}

/// Perform an X25519 key exchange between `your_secret_key` and `their_public_key`.
///
/// It is recommended to read the [`Monocypher` manual] before using this
/// function.
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
///
/// [`Monocypher` manual]: https://monocypher.org/manual/x25519
pub fn crypto_x25519(
    raw_shared_secret: &mut [u8; 32],
    your_secret_key: &[u8; 32],
    their_public_key: &[u8; 32],
) {
    let raw_buf = raw_shared_secret.as_mut_ptr();
    let secret_buf = your_secret_key.as_ptr();
    let pub_buf = their_public_key.as_ptr();

    unsafe { mini_monocypher_sys::crypto_x25519(raw_buf, secret_buf, pub_buf) }
}

/// Compares two 16-byte buffers in constant time. Returns `()` if they are
/// equal, or [`ErrorKind::Mismatch`] if they are different.
///
/// Use this instead of `==` when comparing secrets such as MACs, as the time
/// taken by this function does not depend on the contents of the buffers.
///
/// It is recommended to read the [`Monocypher` manual] before using this
/// function.
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_verify16;
///
/// let a = [1u8; 16];
/// let b = [1u8; 16];
/// let c = [2u8; 16];
///
/// assert!(crypto_verify16(&a, &b).is_ok());
/// assert!(crypto_verify16(&a, &c).is_err());
/// ```
///
/// [`Monocypher` manual]: https://monocypher.org/manual/verify
pub fn crypto_verify16(a: &[u8; 16], b: &[u8; 16]) -> Result<(), ErrorKind> {
    let a_buf = a.as_ptr();
    let b_buf = b.as_ptr();

    let result = unsafe { mini_monocypher_sys::crypto_verify16(a_buf, b_buf) };

    if result != 0 {
        return Err(ErrorKind::Mismatch);
    }

    Ok(())
}

/// Compares two 32-byte buffers in constant time. Returns `()` if they are
/// equal, or [`ErrorKind::Mismatch`] if they are different.
///
/// Use this instead of `==` when comparing secrets such as MACs, as the time
/// taken by this function does not depend on the contents of the buffers.
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_verify32;
///
/// let a = [1u8; 32];
/// let b = [1u8; 32];
/// let c = [2u8; 32];
///
/// assert!(crypto_verify32(&a, &b).is_ok());
/// assert!(crypto_verify32(&a, &c).is_err());
/// ```
pub fn crypto_verify32(a: &[u8; 32], b: &[u8; 32]) -> Result<(), ErrorKind> {
    let a_buf = a.as_ptr();
    let b_buf = b.as_ptr();

    let result = unsafe { mini_monocypher_sys::crypto_verify32(a_buf, b_buf) };

    if result != 0 {
        return Err(ErrorKind::Mismatch);
    }

    Ok(())
}

/// Compares two 64-byte buffers in constant time. Returns `()` if they are
/// equal, or [`ErrorKind::Mismatch`] if they are different.
///
/// Use this instead of `==` when comparing secrets such as MACs, as the time
/// taken by this function does not depend on the contents of the buffers.
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_verify64;
///
/// let a = [1u8; 64];
/// let b = [1u8; 64];
/// let c = [2u8; 64];
///
/// assert!(crypto_verify64(&a, &b).is_ok());
/// assert!(crypto_verify64(&a, &c).is_err());
/// ```
pub fn crypto_verify64(a: &[u8; 64], b: &[u8; 64]) -> Result<(), ErrorKind> {
    let a_buf = a.as_ptr();
    let b_buf = b.as_ptr();

    let result = unsafe { mini_monocypher_sys::crypto_verify64(a_buf, b_buf) };

    if result != 0 {
        return Err(ErrorKind::Mismatch);
    }

    Ok(())
}

/// Erases `secret` by overwriting it with zeroes, in a way the compiler will
/// not optimise away.
///
/// This only erases the memory `secret` refers to. Copies of the data left
/// behind when a value was moved or copied are not affected.
///
/// It is recommended to read the [`Monocypher` manual] before using this
/// function.
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_wipe;
///
/// let mut secret = [0x42u8; 32];
/// crypto_wipe(&mut secret);
/// assert_eq!(secret, [0u8; 32]);
/// ```
///
/// [`Monocypher` manual]: https://monocypher.org/manual/wipe
pub fn crypto_wipe(secret: &mut [u8]) {
    let secret_buf = secret.as_mut_ptr().cast();

    unsafe { mini_monocypher_sys::crypto_wipe(secret_buf, secret.len()) }
}

/// Computes a Poly1305 Message Authentication Code (MAC) for a message.
///
/// Poly1305 is a one-time authenticator: a `key` must only ever be used for
/// a single message, and must be random and secret. For general use prefer
/// [`crypto_aead_lock`] or [`crypto_blake2b_keyed`].
///
/// It is recommended to read the Poly1305 section of the [`Monocypher` manual]
/// before using this function.
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::crypto_poly1305;
///
/// let mut key = [0u8; 32];
/// let mut mac = [0u8; 16];
///
/// OsRng.fill_bytes(&mut key);
/// crypto_poly1305(&mut mac, b"Lorem ipsum", &key);
/// ```
///
/// [`Monocypher` manual]: https://monocypher.org/manual/poly1305
pub fn crypto_poly1305(mac: &mut [u8; 16], message: &[u8], key: &[u8; 32]) {
    let mac_buf = mac.as_mut_ptr();
    let message_buf = message.as_ptr();
    let key_buf = key.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_poly1305(mac_buf, message_buf, message.len(), key_buf);
    }
}

/// Poly1305 context for use with incremental interface.
///
/// The contents are private as Monocypher trusts them when writing to memory.
///
/// As added safety over Monocypher, the context is also wiped when it goes out
/// of scope, which covers a context abandoned before [`crypto_poly1305_final`].
/// Copies left behind when the context was moved are not affected.
#[repr(transparent)]
pub struct crypto_poly1305_ctx(mini_monocypher_sys::crypto_poly1305_ctx);

impl Drop for crypto_poly1305_ctx {
    fn drop(&mut self) {
        let ctx_ptr = &mut self.0 as *mut mini_monocypher_sys::crypto_poly1305_ctx;

        unsafe {
            mini_monocypher_sys::crypto_wipe(
                ctx_ptr.cast(),
                std::mem::size_of::<mini_monocypher_sys::crypto_poly1305_ctx>(),
            );
        }
    }
}

/// Returns a Poly1305 context for use with the incremental interface.
///
/// The context must be initialised with [`crypto_poly1305_init`]. As with
/// Monocypher, this is not checked: skipping it silently produces an
/// all-zero MAC.
pub fn crypto_poly1305_ctx_new() -> crypto_poly1305_ctx {
    crypto_poly1305_ctx(mini_monocypher_sys::crypto_poly1305_ctx {
        c: [0u8; 16],
        c_idx: 0,
        r: [0u32; 4],
        pad: [0u32; 4],
        h: [0u32; 5],
    })
}

/// Initialises a Poly1305 context for use with the incremental interface.
///
/// See [`crypto_poly1305`] for the restrictions on `key`.
///
/// # Examples
///
/// This example demonstrates using the incremental interface.
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::{
///   crypto_poly1305_ctx_new,
///   crypto_poly1305_init,
///   crypto_poly1305_update,
///   crypto_poly1305_final,
/// };
///
/// let mut key = [0u8; 32];
/// let mut mac = [0u8; 16];
/// let mut ctx = crypto_poly1305_ctx_new();
///
/// OsRng.fill_bytes(&mut key);
///
/// crypto_poly1305_init(&mut ctx, &key);
/// crypto_poly1305_update(&mut ctx, b"Lorem");
/// crypto_poly1305_update(&mut ctx, b" ");
/// crypto_poly1305_update(&mut ctx, b"ipsum");
/// crypto_poly1305_final(&mut ctx, &mut mac);
/// ```
pub fn crypto_poly1305_init(ctx: &mut crypto_poly1305_ctx, key: &[u8; 32]) {
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_poly1305_ctx;
    let key_buf = key.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_poly1305_init(ctx_ptr, key_buf);
    }
}

/// Incrementally computes a Poly1305 MAC based on `ctx` and a message.
///
/// See [`crypto_poly1305_init`] for a full example of using the incremental
/// interface.
pub fn crypto_poly1305_update(ctx: &mut crypto_poly1305_ctx, message: &[u8]) {
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_poly1305_ctx;
    let message_buf = message.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_poly1305_update(ctx_ptr, message_buf, message.len());
    }
}

/// Computes the final Poly1305 MAC based on `ctx`. The output will reside
/// in `mac`.
///
/// `ctx` is wiped afterwards, and must be initialised again before reuse.
///
/// See [`crypto_poly1305_init`] for a full example of using the incremental
/// interface.
pub fn crypto_poly1305_final(ctx: &mut crypto_poly1305_ctx, mac: &mut [u8; 16]) {
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_poly1305_ctx;
    let mac_buf = mac.as_mut_ptr();

    unsafe {
        mini_monocypher_sys::crypto_poly1305_final(ctx_ptr, mac_buf);
    }
}

/// Derives a 32-byte value `out` from a 32-byte `key` and 16-byte `input`.
///
/// This is the HChaCha20 function, used to hash X25519 shared secrets and to
/// build the extended nonce of [`crypto_chacha20_x`].
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_chacha20_h;
///
/// let key = [1u8; 32];
/// let input = [2u8; 16];
/// let mut out = [0u8; 32];
///
/// crypto_chacha20_h(&mut out, &key, &input);
/// ```
pub fn crypto_chacha20_h(out: &mut [u8; 32], key: &[u8; 32], input: &[u8; 16]) {
    let out_buf = out.as_mut_ptr();
    let key_buf = key.as_ptr();
    let input_buf = input.as_ptr();

    unsafe { mini_monocypher_sys::crypto_chacha20_h(out_buf, key_buf, input_buf) }
}

/// Encrypts `plain_text` into `cipher_text` using an 8-byte `nonce`, or decrypts as
/// decryption is the same operation.
///
/// An 8-byte nonce is too small to be selected at random. Prefer
/// [`crypto_chacha20_x`] unless compatibility requires otherwise.
///
/// Returns the counter to pass as `ctr` to continue from where this call
/// stopped. See [`crypto_chacha20_x`] for details of the other arguments.
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_chacha20_djb;
///
/// let key = [1u8; 32];
/// let nonce = [2u8; 8];
/// let plain_text = b"Lorem ipsum";
/// let mut cipher_text = [0u8; 11];
///
/// crypto_chacha20_djb(&mut cipher_text, Some(plain_text), &key, &nonce, 0);
/// ```
///
/// # Panics
///
/// This function panics if `plain_text` is longer than `cipher_text`.
pub fn crypto_chacha20_djb(
    cipher_text: &mut [u8],
    plain_text: Option<&[u8]>,
    key: &[u8; 32],
    nonce: &[u8; 8],
    ctr: u64,
) -> u64 {
    let (plain_text_buf, text_size) = match plain_text {
        None => (std::ptr::null(), cipher_text.len()),
        Some(x) => {
            assert!(cipher_text.len() >= x.len());
            (x.as_ptr(), x.len())
        }
    };
    let cipher_text_buf = cipher_text.as_mut_ptr();
    let key_buf = key.as_ptr();
    let nonce_buf = nonce.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_chacha20_djb(
            cipher_text_buf,
            plain_text_buf,
            text_size,
            key_buf,
            nonce_buf,
            ctr,
        )
    }
}

/// Encrypts `plain_text` into `cipher_text` using a 12-byte `nonce` as described in RFC 8439, or decrypts as
/// decryption is the same operation.
///
/// A 12-byte nonce is too small to be selected at random. Prefer
/// [`crypto_chacha20_x`] unless compatibility requires otherwise.
///
/// Returns the counter to pass as `ctr` to continue from where this call
/// stopped. See [`crypto_chacha20_x`] for details of the other arguments.
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_chacha20_ietf;
///
/// let key = [1u8; 32];
/// let nonce = [2u8; 12];
/// let plain_text = b"Lorem ipsum";
/// let mut cipher_text = [0u8; 11];
///
/// crypto_chacha20_ietf(&mut cipher_text, Some(plain_text), &key, &nonce, 0);
/// ```
///
/// # Panics
///
/// This function panics if `plain_text` is longer than `cipher_text`.
pub fn crypto_chacha20_ietf(
    cipher_text: &mut [u8],
    plain_text: Option<&[u8]>,
    key: &[u8; 32],
    nonce: &[u8; 12],
    ctr: u32,
) -> u32 {
    let (plain_text_buf, text_size) = match plain_text {
        None => (std::ptr::null(), cipher_text.len()),
        Some(x) => {
            assert!(cipher_text.len() >= x.len());
            (x.as_ptr(), x.len())
        }
    };
    let cipher_text_buf = cipher_text.as_mut_ptr();
    let key_buf = key.as_ptr();
    let nonce_buf = nonce.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_chacha20_ietf(
            cipher_text_buf,
            plain_text_buf,
            text_size,
            key_buf,
            nonce_buf,
            ctr,
        )
    }
}

/// Encrypts `plain_text` into `cipher_text` using a 24-byte `nonce`, or decrypts as
/// decryption is the same operation.
///
/// This is a low-level primitive with no authentication, so prefer
/// [`crypto_aead_lock`] for general use. A `nonce` must never be reused with
/// the same `key`. A 24-byte nonce is large enough to be selected at random.
///
/// Only the first `plain_text.len()` bytes of `cipher_text` are written, any
/// remaining bytes are left untouched. If `plain_text` is [`None`], all of
/// `cipher_text` is filled with the raw ChaCha20 stream.
///
/// `ctr` is the number of 64-byte blocks to skip from the start of the stream
/// and should normally be 0.
///
/// Unlike Monocypher, `cipher_text` and `plain_text` cannot be the same buffer
/// for in-place encryption, as Rust does not allow a buffer to be borrowed
/// both mutably and immutably. Separate buffers must be used.
///
/// Returns the counter to pass as `ctr` to continue from where this call
/// stopped.
///
/// It is recommended to read the [`Monocypher` manual] before using this
/// function.
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_chacha20_x;
///
/// let key = [1u8; 32];
/// let nonce = [2u8; 24];
/// let plain_text = b"Lorem ipsum";
/// let mut cipher_text = [0u8; 11];
///
/// crypto_chacha20_x(&mut cipher_text, Some(plain_text), &key, &nonce, 0);
/// ```
///
/// # Panics
///
/// This function panics if `plain_text` is longer than `cipher_text`.
///
/// [`Monocypher` manual]: https://monocypher.org/manual/chacha20
pub fn crypto_chacha20_x(
    cipher_text: &mut [u8],
    plain_text: Option<&[u8]>,
    key: &[u8; 32],
    nonce: &[u8; 24],
    ctr: u64,
) -> u64 {
    let (plain_text_buf, text_size) = match plain_text {
        None => (std::ptr::null(), cipher_text.len()),
        Some(x) => {
            assert!(cipher_text.len() >= x.len());
            (x.as_ptr(), x.len())
        }
    };
    let cipher_text_buf = cipher_text.as_mut_ptr();
    let key_buf = key.as_ptr();
    let nonce_buf = nonce.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_chacha20_x(
            cipher_text_buf,
            plain_text_buf,
            text_size,
            key_buf,
            nonce_buf,
            ctr,
        )
    }
}

/// AEAD context for use with the incremental interface.
///
/// The contents are private as they include key material, and the context
/// cannot be copied as that would reuse the same key stream.
///
/// Monocypher says to wipe the context with `crypto_wipe` once the last chunk
/// has been processed. As added safety, this is done automatically when the
/// context goes out of scope. Copies left behind when the context was moved
/// are not affected.
#[repr(transparent)]
pub struct crypto_aead_ctx(mini_monocypher_sys::crypto_aead_ctx);

impl Drop for crypto_aead_ctx {
    fn drop(&mut self) {
        let ctx_ptr = &mut self.0 as *mut mini_monocypher_sys::crypto_aead_ctx;

        unsafe {
            mini_monocypher_sys::crypto_wipe(
                ctx_ptr.cast(),
                std::mem::size_of::<mini_monocypher_sys::crypto_aead_ctx>(),
            );
        }
    }
}

/// Returns an AEAD context for use with the incremental interface.
///
/// The context must be initialised with [`crypto_aead_init_x`],
/// [`crypto_aead_init_djb`], or [`crypto_aead_init_ietf`].
///
/// **Warning:** as with Monocypher, this is not checked. Skipping
/// initialisation silently encrypts with an all-zero key, so anyone can
/// decrypt the result.
pub fn crypto_aead_ctx_new() -> crypto_aead_ctx {
    crypto_aead_ctx(mini_monocypher_sys::crypto_aead_ctx {
        counter: 0,
        key: [0u8; 32],
        nonce: [0u8; 8],
    })
}

/// Initialises an AEAD context for use with the incremental interface, using
/// a 24-byte `nonce` that can be selected at random.
///
/// A `nonce` must never be reused with the same `key`.
///
/// See [`crypto_aead_write`] for a full example of using the incremental
/// interface.
pub fn crypto_aead_init_x(ctx: &mut crypto_aead_ctx, key: &[u8; 32], nonce: &[u8; 24]) {
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_aead_ctx;
    let key_buf = key.as_ptr();
    let nonce_buf = nonce.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_aead_init_x(ctx_ptr, key_buf, nonce_buf);
    }
}

/// Initialises an AEAD context for use with the incremental interface, using
/// an 8-byte `nonce` that is too small to be selected at random.
///
/// A `nonce` must never be reused with the same `key`.
///
/// See [`crypto_aead_write`] for a full example of using the incremental
/// interface.
pub fn crypto_aead_init_djb(ctx: &mut crypto_aead_ctx, key: &[u8; 32], nonce: &[u8; 8]) {
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_aead_ctx;
    let key_buf = key.as_ptr();
    let nonce_buf = nonce.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_aead_init_djb(ctx_ptr, key_buf, nonce_buf);
    }
}

/// Initialises an AEAD context for use with the incremental interface, using
/// a 12-byte `nonce` that is too small to be selected at random.
/// Each chunk is limited to 2^38 - 64 bytes.
///
/// A `nonce` must never be reused with the same `key`.
///
/// See [`crypto_aead_write`] for a full example of using the incremental
/// interface.
pub fn crypto_aead_init_ietf(ctx: &mut crypto_aead_ctx, key: &[u8; 32], nonce: &[u8; 12]) {
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_aead_ctx;
    let key_buf = key.as_ptr();
    let nonce_buf = nonce.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_aead_init_ietf(ctx_ptr, key_buf, nonce_buf);
    }
}

/// Encrypts and authenticates one chunk of a stream. The output can then be
/// decrypted by [`crypto_aead_read`], with chunks read in the order written.
///
/// Reordered chunks are detected, but truncation is not: the last chunk must
/// be marked by the caller, for example by using `ad` to mark it differently.
///
/// Only the first `plain_text.len()` bytes of `cipher_text` are written, any
/// remaining bytes are left untouched.
///
/// Unlike Monocypher, `cipher_text` and `plain_text` cannot be the same buffer
/// for in-place encryption, as Rust does not allow a buffer to be borrowed
/// both mutably and immutably. Separate buffers must be used.
///
/// It is recommended to read the AEAD section of the [`Monocypher` manual]
/// for the full intricacies on using the incremental interface.
///
/// # Examples
///
/// This example encrypts and decrypts a stream of two chunks.
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::{
///   crypto_aead_ctx_new,
///   crypto_aead_init_x,
///   crypto_aead_write,
///   crypto_aead_read,
/// };
///
/// let mut key = [0u8; 32];
/// let mut nonce = [0u8; 24];
///
/// OsRng.fill_bytes(&mut key);
/// OsRng.fill_bytes(&mut nonce);
///
/// let mut cipher_text = [[0u8; 5]; 2];
/// let mut mac = [[0u8; 16]; 2];
///
/// let mut ctx = crypto_aead_ctx_new();
/// crypto_aead_init_x(&mut ctx, &key, &nonce);
/// crypto_aead_write(&mut ctx, &mut cipher_text[0], &mut mac[0], None, b"Lorem");
/// crypto_aead_write(&mut ctx, &mut cipher_text[1], &mut mac[1], None, b"ipsum");
///
/// let mut plain_text = [0u8; 5];
///
/// let mut ctx = crypto_aead_ctx_new();
/// crypto_aead_init_x(&mut ctx, &key, &nonce);
/// crypto_aead_read(&mut ctx, &mut plain_text, &mac[0], None, &cipher_text[0])
///     .expect("decryption should succeed");
/// assert_eq!(&plain_text, b"Lorem");
/// crypto_aead_read(&mut ctx, &mut plain_text, &mac[1], None, &cipher_text[1])
///     .expect("decryption should succeed");
/// assert_eq!(&plain_text, b"ipsum");
/// ```
///
/// # Panics
///
/// This function panics if `cipher_text.len() < plain_text.len()`.
///
/// [`Monocypher` manual]: https://monocypher.org/manual/aead
pub fn crypto_aead_write(
    ctx: &mut crypto_aead_ctx,
    cipher_text: &mut [u8],
    mac: &mut [u8; 16],
    ad: Option<&[u8]>,
    plain_text: &[u8],
) {
    assert!(cipher_text.len() >= plain_text.len());

    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_aead_ctx;
    let cipher_text_buf = cipher_text.as_mut_ptr();
    let mac_buf = mac.as_mut_ptr();
    let (ad_buf, ad_len) = match ad {
        None => (std::ptr::null(), 0),
        Some(x) => (x.as_ptr(), x.len()),
    };
    let plain_text_buf = plain_text.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_aead_write(
            ctx_ptr,
            cipher_text_buf,
            mac_buf,
            ad_buf,
            ad_len,
            plain_text_buf,
            plain_text.len(),
        );
    }
}

/// Decrypts one authenticated chunk of a stream. Returns `()` if successful,
/// or [`ErrorKind::AuthenticationFailure`] if there is a decryption failure.
///
/// On failure nothing is written to `plain_text` and `ctx` is unchanged.
///
/// Only the first `cipher_text.len()` bytes of `plain_text` are written, any
/// remaining bytes are left untouched.
///
/// Unlike Monocypher, `plain_text` and `cipher_text` cannot be the same buffer
/// for in-place decryption, as Rust does not allow a buffer to be borrowed
/// both mutably and immutably. Separate buffers must be used.
///
/// See [`crypto_aead_write`] for a full example of using the incremental
/// interface.
///
/// # Panics
///
/// This function panics if `plain_text.len() < cipher_text.len()`.
pub fn crypto_aead_read(
    ctx: &mut crypto_aead_ctx,
    plain_text: &mut [u8],
    mac: &[u8; 16],
    ad: Option<&[u8]>,
    cipher_text: &[u8],
) -> Result<(), ErrorKind> {
    assert!(plain_text.len() >= cipher_text.len());

    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_aead_ctx;
    let plain_text_buf = plain_text.as_mut_ptr();
    let mac_buf = mac.as_ptr();
    let (ad_buf, ad_len) = match ad {
        None => (std::ptr::null(), 0),
        Some(x) => (x.as_ptr(), x.len()),
    };
    let cipher_text_buf = cipher_text.as_ptr();

    let result = unsafe {
        mini_monocypher_sys::crypto_aead_read(
            ctx_ptr,
            plain_text_buf,
            mac_buf,
            ad_buf,
            ad_len,
            cipher_text_buf,
            cipher_text.len(),
        )
    };

    if result != 0 {
        return Err(ErrorKind::AuthenticationFailure);
    }

    Ok(())
}

/// Converts an X25519 public key to an EdDSA public key.
///
/// This only converts public keys, not secret keys.
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::{crypto_x25519_public_key, crypto_x25519_to_eddsa};
///
/// let mut secret_key = [0u8; 32];
/// let mut public_key = [0u8; 32];
/// let mut eddsa = [0u8; 32];
///
/// OsRng.fill_bytes(&mut secret_key);
/// crypto_x25519_public_key(&mut public_key, &secret_key);
/// crypto_x25519_to_eddsa(&mut eddsa, &public_key);
/// ```
pub fn crypto_x25519_to_eddsa(eddsa: &mut [u8; 32], x25519: &[u8; 32]) {
    let eddsa_buf = eddsa.as_mut_ptr();
    let x25519_buf = x25519.as_ptr();

    unsafe { mini_monocypher_sys::crypto_x25519_to_eddsa(eddsa_buf, x25519_buf) }
}

/// Performs the inverse of [`crypto_x25519`], writing the original point to
/// `blind_salt`. This is used for blinding in protocols such as OPRF.
///
/// Be aware that exponential blinding is less secure than Diffie-Hellman key
/// exchange.
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::{
///   crypto_x25519,
///   crypto_x25519_inverse,
///   crypto_x25519_public_key,
/// };
///
/// let mut b = [0u8; 32];
/// let mut private_key = [0u8; 32];
/// let mut base = [0u8; 32];
/// let mut curve_point = [0u8; 32];
/// let mut blind_salt = [0u8; 32];
///
/// OsRng.fill_bytes(&mut b);
/// OsRng.fill_bytes(&mut private_key);
///
/// crypto_x25519_public_key(&mut base, &b);
/// crypto_x25519(&mut curve_point, &private_key, &base);
/// crypto_x25519_inverse(&mut blind_salt, &private_key, &curve_point);
///
/// assert_eq!(blind_salt, base);
/// ```
pub fn crypto_x25519_inverse(
    blind_salt: &mut [u8; 32],
    private_key: &[u8; 32],
    curve_point: &[u8; 32],
) {
    let blind_salt_buf = blind_salt.as_mut_ptr();
    let private_key_buf = private_key.as_ptr();
    let curve_point_buf = curve_point.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_x25519_inverse(
            blind_salt_buf,
            private_key_buf,
            curve_point_buf,
        )
    }
}

/// Generates an X25519 public key for use with Elligator, with smaller code.
///
/// The public key is compatible with [`crypto_x25519`], but this function
/// leaks 3 bits of the secret key. Only use it for ephemeral keys that will be
/// hidden with Elligator, otherwise use [`crypto_x25519_public_key`].
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::crypto_x25519_dirty_small;
///
/// let mut sk = [0u8; 32];
/// let mut pk = [0u8; 32];
///
/// OsRng.fill_bytes(&mut sk);
/// crypto_x25519_dirty_small(&mut pk, &sk);
/// ```
pub fn crypto_x25519_dirty_small(pk: &mut [u8; 32], sk: &[u8; 32]) {
    let pk_buf = pk.as_mut_ptr();
    let sk_buf = sk.as_ptr();

    unsafe { mini_monocypher_sys::crypto_x25519_dirty_small(pk_buf, sk_buf) }
}

/// Generates an X25519 public key for use with Elligator, optimised for speed.
///
/// The public key is compatible with [`crypto_x25519`], but this function
/// leaks 3 bits of the secret key. Only use it for ephemeral keys that will be
/// hidden with Elligator, otherwise use [`crypto_x25519_public_key`].
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::crypto_x25519_dirty_fast;
///
/// let mut sk = [0u8; 32];
/// let mut pk = [0u8; 32];
///
/// OsRng.fill_bytes(&mut sk);
/// crypto_x25519_dirty_fast(&mut pk, &sk);
/// ```
pub fn crypto_x25519_dirty_fast(pk: &mut [u8; 32], sk: &[u8; 32]) {
    let pk_buf = pk.as_mut_ptr();
    let sk_buf = sk.as_ptr();

    unsafe { mini_monocypher_sys::crypto_x25519_dirty_fast(pk_buf, sk_buf) }
}

/// Computes an EdDSA key pair from a random `seed`.
///
/// The `seed` must be freshly generated and only used once, and is wiped by
/// this function. `secret_key` is made up of the seed and the public key, and
/// should be treated as a unit.
///
/// See [`crypto_eddsa_sign`] for a full example of signing and checking.
pub fn crypto_eddsa_key_pair(
    secret_key: &mut [u8; 64],
    public_key: &mut [u8; 32],
    seed: &mut [u8; 32],
) {
    let secret_key_buf = secret_key.as_mut_ptr();
    let public_key_buf = public_key.as_mut_ptr();
    let seed_buf = seed.as_mut_ptr();

    unsafe { mini_monocypher_sys::crypto_eddsa_key_pair(secret_key_buf, public_key_buf, seed_buf) }
}

/// Signs `message` with `secret_key`. The output can be checked by
/// [`crypto_eddsa_check`].
///
/// This uses BLAKE2b as the underlying hash, so it is not compatible with
/// Ed25519.
///
/// Unlike Monocypher, `signature` and `message` cannot overlap, as Rust does
/// not allow a buffer to be borrowed both mutably and immutably.
///
/// It is recommended to read the [`Monocypher` manual] before using this
/// function.
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::{crypto_eddsa_check, crypto_eddsa_key_pair, crypto_eddsa_sign};
///
/// let mut seed = [0u8; 32];
/// let mut secret_key = [0u8; 64];
/// let mut public_key = [0u8; 32];
/// let mut signature = [0u8; 64];
///
/// OsRng.fill_bytes(&mut seed);
/// crypto_eddsa_key_pair(&mut secret_key, &mut public_key, &mut seed);
///
/// crypto_eddsa_sign(&mut signature, &secret_key, b"Lorem ipsum");
/// crypto_eddsa_check(&signature, &public_key, b"Lorem ipsum")
///     .expect("signature should be valid");
/// ```
///
/// [`Monocypher` manual]: https://monocypher.org/manual/eddsa
pub fn crypto_eddsa_sign(signature: &mut [u8; 64], secret_key: &[u8; 64], message: &[u8]) {
    let signature_buf = signature.as_mut_ptr();
    let secret_key_buf = secret_key.as_ptr();
    let message_buf = message.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_eddsa_sign(
            signature_buf,
            secret_key_buf,
            message_buf,
            message.len(),
        );
    }
}

/// Checks that `signature` is genuine for `public_key` and `message`.
/// Returns `()` if it is, or [`ErrorKind::InvalidSignature`] if it is not.
///
/// This does not run in constant time. See [`crypto_eddsa_sign`] for a full
/// example of signing and checking.
pub fn crypto_eddsa_check(
    signature: &[u8; 64],
    public_key: &[u8; 32],
    message: &[u8],
) -> Result<(), ErrorKind> {
    let signature_buf = signature.as_ptr();
    let public_key_buf = public_key.as_ptr();
    let message_buf = message.as_ptr();

    let result = unsafe {
        mini_monocypher_sys::crypto_eddsa_check(
            signature_buf,
            public_key_buf,
            message_buf,
            message.len(),
        )
    };

    if result != 0 {
        return Err(ErrorKind::InvalidSignature);
    }

    Ok(())
}

/// Converts an EdDSA public key to an X25519 public key.
///
/// This ignores the sign of the x coordinate of `eddsa`. The inverse operation
/// is [`crypto_x25519_to_eddsa`].
pub fn crypto_eddsa_to_x25519(x25519: &mut [u8; 32], eddsa: &[u8; 32]) {
    let x25519_buf = x25519.as_mut_ptr();
    let eddsa_buf = eddsa.as_ptr();

    unsafe { mini_monocypher_sys::crypto_eddsa_to_x25519(x25519_buf, eddsa_buf) }
}

/// Generates an X25519 secret key and a public key disguised as random noise
/// from a random `seed`.
///
/// This is an advanced feature for protocols that need all communications to
/// be indistinguishable from random noise. It is intended for ephemeral keys
/// only, and the keys are not compatible with [`crypto_eddsa_sign`]. The real
/// public key can be recovered with [`crypto_elligator_map`].
///
/// The `seed` is wiped by this function. The execution time is unpredictable
/// as it may take many attempts to generate a suitable key pair.
///
/// It is recommended to read the [`Monocypher` manual] before using this
/// function.
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::crypto_elligator_key_pair;
///
/// let mut seed = [0u8; 32];
/// let mut hidden = [0u8; 32];
/// let mut secret_key = [0u8; 32];
///
/// OsRng.fill_bytes(&mut seed);
/// crypto_elligator_key_pair(&mut hidden, &mut secret_key, &mut seed);
/// ```
///
/// [`Monocypher` manual]: https://monocypher.org/manual/elligator
pub fn crypto_elligator_key_pair(
    hidden: &mut [u8; 32],
    secret_key: &mut [u8; 32],
    seed: &mut [u8; 32],
) {
    let hidden_buf = hidden.as_mut_ptr();
    let secret_key_buf = secret_key.as_mut_ptr();
    let seed_buf = seed.as_mut_ptr();

    unsafe { mini_monocypher_sys::crypto_elligator_key_pair(hidden_buf, secret_key_buf, seed_buf) }
}

/// Disguises the public key `curve` as random noise, writing the result to
/// `hidden`. The inverse operation is [`crypto_elligator_map`].
///
/// `curve` must be generated by [`crypto_x25519_dirty_fast`] or
/// [`crypto_x25519_dirty_small`], and `tweak` must be chosen at random.
///
/// Returns [`ErrorKind::UnsuitableForHiding`] if the key cannot be hidden, which
/// happens for about half of all keys and is not a failure of the program. Do
/// not use `hidden` in that case. Instead try again with a new key pair, as
/// changing `tweak` does not help. Once a suitable key is found, this function
/// always succeeds for it.
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::{crypto_elligator_rev, crypto_x25519_dirty_fast};
///
/// let mut secret_key = [0u8; 32];
/// let mut public_key = [0u8; 32];
/// let mut hidden = [0u8; 32];
///
/// loop {
///     OsRng.fill_bytes(&mut secret_key);
///     crypto_x25519_dirty_fast(&mut public_key, &secret_key);
///
///     let tweak = OsRng.next_u32() as u8;
///     if crypto_elligator_rev(&mut hidden, &public_key, tweak).is_ok() {
///         break;
///     }
/// }
/// ```
pub fn crypto_elligator_rev(
    hidden: &mut [u8; 32],
    curve: &[u8; 32],
    tweak: u8,
) -> Result<(), ErrorKind> {
    let hidden_buf = hidden.as_mut_ptr();
    let curve_buf = curve.as_ptr();

    let result = unsafe { mini_monocypher_sys::crypto_elligator_rev(hidden_buf, curve_buf, tweak) };

    if result != 0 {
        return Err(ErrorKind::UnsuitableForHiding);
    }

    Ok(())
}

/// Recovers the public key disguised in `hidden`, writing it to `curve`. This
/// is the inverse of [`crypto_elligator_rev`].
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::{crypto_elligator_key_pair, crypto_elligator_map};
///
/// let mut seed = [0u8; 32];
/// let mut hidden = [0u8; 32];
/// let mut secret_key = [0u8; 32];
/// let mut curve = [0u8; 32];
///
/// OsRng.fill_bytes(&mut seed);
/// crypto_elligator_key_pair(&mut hidden, &mut secret_key, &mut seed);
/// crypto_elligator_map(&mut curve, &hidden);
/// ```
pub fn crypto_elligator_map(curve: &mut [u8; 32], hidden: &[u8; 32]) {
    let curve_buf = curve.as_mut_ptr();
    let hidden_buf = hidden.as_ptr();

    unsafe { mini_monocypher_sys::crypto_elligator_map(curve_buf, hidden_buf) }
}

/// Dangerous low-level building blocks ("hazardous materials").
///
/// These are memory safe, but using them directly allows many kinds of
/// catastrophic misuse. Most users want [`crypto_eddsa_sign`] and
/// [`crypto_eddsa_check`] instead.
pub mod hazmat {
    use super::ErrorKind;

    /// Trims a 32-byte value `input` into a valid scalar `out`, by clearing and
    /// setting the bits required by X25519 and EdDSA.
    ///
    /// **Warning:** this is a dangerous low-level building block. Using it directly
    /// allows many kinds of catastrophic misuse, including leaking the secret key.
    /// Read the [`Monocypher` manual] and do not use this if you do not understand
    /// it.
    ///
    /// [`Monocypher` manual]: https://monocypher.org/manual/eddsa
    pub fn crypto_eddsa_trim_scalar(out: &mut [u8; 32], input: &[u8; 32]) {
        let out_buf = out.as_mut_ptr();
        let input_buf = input.as_ptr();

        unsafe { mini_monocypher_sys::crypto_eddsa_trim_scalar(out_buf, input_buf) }
    }

    /// Reduces a 64-byte value `expanded` modulo the order of the curve, writing
    /// the result to `reduced`.
    ///
    /// **Warning:** this is a dangerous low-level building block. Using it directly
    /// allows many kinds of catastrophic misuse, including leaking the secret key.
    /// Read the [`Monocypher` manual] and do not use this if you do not understand
    /// it.
    ///
    /// [`Monocypher` manual]: https://monocypher.org/manual/eddsa
    pub fn crypto_eddsa_reduce(reduced: &mut [u8; 32], expanded: &[u8; 64]) {
        let reduced_buf = reduced.as_mut_ptr();
        let expanded_buf = expanded.as_ptr();

        unsafe { mini_monocypher_sys::crypto_eddsa_reduce(reduced_buf, expanded_buf) }
    }

    /// Computes `r = a * b + c` modulo the order of the curve.
    ///
    /// **Warning:** this is a dangerous low-level building block. Using it directly
    /// allows many kinds of catastrophic misuse, including leaking the secret key.
    /// Read the [`Monocypher` manual] and do not use this if you do not understand
    /// it.
    ///
    /// [`Monocypher` manual]: https://monocypher.org/manual/eddsa
    pub fn crypto_eddsa_mul_add(r: &mut [u8; 32], a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) {
        let r_buf = r.as_mut_ptr();
        let a_buf = a.as_ptr();
        let b_buf = b.as_ptr();
        let c_buf = c.as_ptr();

        unsafe { mini_monocypher_sys::crypto_eddsa_mul_add(r_buf, a_buf, b_buf, c_buf) }
    }

    /// Multiplies the base point of the curve by `scalar`, writing the compressed
    /// result to `point`.
    ///
    /// **Warning:** this is a dangerous low-level building block. Using it directly
    /// allows many kinds of catastrophic misuse, including leaking the secret key.
    /// Read the [`Monocypher` manual] and do not use this if you do not understand
    /// it.
    ///
    /// [`Monocypher` manual]: https://monocypher.org/manual/eddsa
    pub fn crypto_eddsa_scalarbase(point: &mut [u8; 32], scalar: &[u8; 32]) {
        let point_buf = point.as_mut_ptr();
        let scalar_buf = scalar.as_ptr();

        unsafe { mini_monocypher_sys::crypto_eddsa_scalarbase(point_buf, scalar_buf) }
    }

    /// Checks the EdDSA verification equation for `signature`, `public_key`, and
    /// the reduced hash `h_ram`. Returns `()` if it holds, or
    /// [`ErrorKind::InvalidSignature`] if it does not.
    ///
    /// **Warning:** this is a dangerous low-level building block. Using it directly
    /// allows many kinds of catastrophic misuse, including leaking the secret key.
    /// Read the [`Monocypher` manual] and do not use this if you do not understand
    /// it.
    ///
    /// [`Monocypher` manual]: https://monocypher.org/manual/eddsa
    pub fn crypto_eddsa_check_equation(
        signature: &[u8; 64],
        public_key: &[u8; 32],
        h_ram: &[u8; 32],
    ) -> Result<(), ErrorKind> {
        let signature_buf = signature.as_ptr();
        let public_key_buf = public_key.as_ptr();
        let h_ram_buf = h_ram.as_ptr();

        let result = unsafe {
            mini_monocypher_sys::crypto_eddsa_check_equation(
                signature_buf,
                public_key_buf,
                h_ram_buf,
            )
        };

        if result != 0 {
            return Err(ErrorKind::InvalidSignature);
        }

        Ok(())
    }
}
