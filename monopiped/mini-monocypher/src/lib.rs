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
