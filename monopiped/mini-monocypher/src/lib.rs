#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

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
