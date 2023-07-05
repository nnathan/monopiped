use std::fs::File;
use std::io::Read;

use std::path::PathBuf;

use dryoc::classic::crypto_generichash::*;

pub fn crypto_hash_file(pathname: &PathBuf) -> Result<[u8; 32], std::io::Error> {
    const CHUNK_SIZE: usize = 4096;
    let mut buf = [0; CHUNK_SIZE];
    let mut f = File::open(pathname)?;
    let mut state = crypto_generichash_init(None, 32).expect("create generichash state");
    let mut output: [u8; 32] = [0; 32];

    loop {
        let n = f.read(&mut buf)?;
        if n < CHUNK_SIZE {
            crypto_generichash_update(&mut state, &buf[..n]);
            crypto_generichash_final(state, &mut output).expect("final generichash failed");
            return Ok(output);
        }

        crypto_generichash_update(&mut state, &buf[..n]);
    }
}

pub fn increment_nonce(nonce: &mut [u8; 24], incr: u8) {
    let mut acc: u16 = incr as u16;

    let mut i = 0;

    while i < nonce.len() {
        acc = (nonce[i] as u16) + acc;
        nonce[i] = (acc & 0xFF) as u8;
        acc = acc >> 8;
        i += 1;
    }
}
