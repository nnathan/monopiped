#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub fn crypto_blake2b(hash: &mut [u8], message: &[u8]) {
    assert!(hash.len() > 0 && hash.len() <= 64);

    let hash_buf = hash.as_mut_ptr();
    let message_buf = message.as_ptr();

    unsafe {
        monocypher_sys::crypto_blake2b(
            hash_buf,
            hash.len(),
            message_buf,
            message.len(),
        );
    }
}

pub fn crypto_blake2b_keyed(hash: &mut [u8], key: &[u8], message: &[u8]) {
    assert!(hash.len() > 0 && hash.len() <= 64);
    assert!(key.len() <= 64);

    let hash_buf = hash.as_mut_ptr();
    let key_buf = key.as_ptr();
    let message_buf = message.as_ptr();

    unsafe {
        monocypher_sys::crypto_blake2b_keyed(
            hash_buf,
            hash.len(),
            key_buf,
            key.len(),
            message_buf,
            message.len(),
        );
    }
}

type crypto_blake2b_ctx = monocypher_sys::crypto_blake2b_ctx;

pub fn crypto_blake2b_ctx_new() -> crypto_blake2b_ctx {
    let ctx = crypto_blake2b_ctx {
        hash: [0u64; 8],
        input_offset: [0u64; 2],
        input: [0u64; 16],
        input_idx: 0,
        hash_size: 0,
    };

    ctx
}

pub fn crypto_blake2b_init(ctx: &mut crypto_blake2b_ctx, hash_size: usize) {
    assert!(hash_size > 0 && hash_size <= 64);

    let ctx_ptr = ctx as *mut crypto_blake2b_ctx;

    unsafe {
        monocypher_sys::crypto_blake2b_init(ctx_ptr, hash_size);
    }
}

pub fn crypto_blake2b_update(ctx: &mut crypto_blake2b_ctx, message: &[u8]) {
    let ctx_ptr = ctx as *mut crypto_blake2b_ctx;
    let message_buf = message.as_ptr();

    unsafe {
        monocypher_sys::crypto_blake2b_update(ctx_ptr, message_buf, message.len());
    }
}

pub fn crypto_blake2b_final(ctx: &mut crypto_blake2b_ctx, hash: &mut [u8]) {
    assert!(hash.len() <= 64);
    let ctx_ptr = ctx as *mut crypto_blake2b_ctx;
    let hash_buf = hash.as_mut_ptr();

    unsafe {
        monocypher_sys::crypto_blake2b_final(ctx_ptr, hash_buf);
    }
}

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
        monocypher_sys::crypto_aead_lock(
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

pub fn crypto_aead_unlock(
    plain_text: &mut [u8],
    mac: &[u8],
    key: &[u8],
    nonce: &[u8],
    ad: Option<&[u8]>,
    cipher_text: &[u8],
) {
    assert!(mac.len() == 16);
    assert!(key.len() == 32);
    assert!(nonce.len() == 24);

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
        monocypher_sys::crypto_aead_unlock(
            plain_text_buf,
            mac_buf,
            key_buf,
            nonce_buf,
            ad_buf,
            ad_len,
            cipher_text_buf,
            cipher_text.len(),
        );
    }
}

pub fn crypto_x25519_public_key(
    public_key: &mut [u8],
    secret_key: &[u8],
) {
    assert!(public_key.len() == 32);
    assert!(secret_key.len() == 32);

    let pub_buf = public_key.as_mut_ptr();
    let secret_buf = secret_key.as_ptr();

    unsafe {
        monocypher_sys::crypto_x25519_public_key(
            pub_buf,
            secret_buf,
        )
    }
}

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

    unsafe {
        monocypher_sys::crypto_x25519(
            raw_buf,
            secret_buf,
            pub_buf,
        )
    }
}
