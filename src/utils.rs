use std::fs::File;
use std::io::Read;

use std::path::PathBuf;

use rand_core::{OsRng, RngCore};

use zeroize::{Zeroize, ZeroizeOnDrop};

use mini_monocypher::{
    crypto_blake2b_ctx_new, crypto_blake2b_final, crypto_blake2b_init, crypto_blake2b_update,
    crypto_x25519_public_key,
};

pub fn is_websocket_url(url: &str) -> bool {
    let url = url.to_lowercase();
    if url.starts_with("ws:") || url.starts_with("wss:") {
        return true;
    }

    false
}

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

pub fn derive_x25519_keypair() -> ([u8; 32], [u8; 32]) {
    let mut pk = [0u8; 32];
    let mut sk = [0u8; 32];
    OsRng.fill_bytes(&mut sk);
    crypto_x25519_public_key(&mut pk, &sk);
    (pk, sk)
}

pub struct Key {
    pub key: [u8; 32],
    pub nonce: [u8; 24],
}

impl Key {
    pub fn increment_nonce(&mut self) {
        increment_nonce(&mut self.nonce, 1);
    }
}

impl Zeroize for Key {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl ZeroizeOnDrop for Key {}

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
        let mut x = [0xffu8; 24];
        increment_nonce(&mut x, 1);
        let expected = [0u8; 24];
        assert_eq!(x[..], expected[..]);
    }
}
