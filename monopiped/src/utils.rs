use std::fs::File;
use std::io::Read;

use std::path::PathBuf;

use dryoc::classic::crypto_generichash::*;
use dryoc::classic::crypto_kdf::*;

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

pub fn derive_keys(master_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let context: [u8; 8] = [0; 8];
    let mut client_key: [u8; 32] = [0; 32];
    let mut server_key: [u8; 32] = [0; 32];
    crypto_kdf_derive_from_key(&mut client_key, 0, &context, master_key)
        .expect("client key kdf failed");
    crypto_kdf_derive_from_key(&mut server_key, 1, &context, master_key)
        .expect("server key kdf failed");
    (client_key, server_key)
}
