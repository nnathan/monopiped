use std::fs::File;
use std::io::Read;

use std::path::PathBuf;

use mini_monocypher::{
    crypto_blake2b_ctx_new, crypto_blake2b_final, crypto_blake2b_init, crypto_blake2b_update,
};

pub fn crypto_hash_file(pathname: &PathBuf) -> Result<[u8; 32], std::io::Error> {
    const CHUNK_SIZE: usize = 4096;
    let mut buf = [0; CHUNK_SIZE];
    let mut f = File::open(pathname)?;
    let mut ctx = crypto_blake2b_ctx_new();
    let mut output: [u8; 32] = [0; 32];

    crypto_blake2b_init(&mut ctx, 32);

    loop {
        let n = f.read(&mut buf)?;
        if n < CHUNK_SIZE {
            crypto_blake2b_update(&mut ctx, &buf[..n]);
            crypto_blake2b_final(&mut ctx, &mut output);
            return Ok(output);
        }

        crypto_blake2b_update(&mut ctx, &buf[..n]);
    }
}

pub fn increment_nonce(nonce: &mut [u8; 24], incr: u8) {
    let mut acc: u16 = incr as u16;

    let mut i = 0;

    while i < nonce.len() {
        acc += nonce[i] as u16;
        nonce[i] = (acc & 0xFF) as u8;
        acc >>= 8;
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::increment_nonce;

    #[test]
    fn test_increment_nonce() {
        let mut x = [0u8; 24];
        increment_nonce(&mut x, 2);
        let mut expected = [0u8; 24];
        expected[0] = 2;
        assert_eq!(x[..], expected[..]);
    }

    #[test]
    fn test_increment_nonce_wrap() {
        let mut x = [0xffu8; CRYPTO_SECRETBOX_NONCEBYTES];
        increment_nonce(&mut x, 1);
        let expected = [0u8; CRYPTO_SECRETBOX_NONCEBYTES];
        assert_eq!(x[..], expected[..]);
    }
}
