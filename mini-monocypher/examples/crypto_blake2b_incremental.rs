use mini_monocypher::{
    crypto_blake2b_ctx_new, crypto_blake2b_final, crypto_blake2b_init, crypto_blake2b_update,
};

fn main() {
    let mut hash = [0u8; 32];
    let mut ctx = crypto_blake2b_ctx_new();

    crypto_blake2b_init(&mut ctx, hash.len());
    crypto_blake2b_update(&mut ctx, b"Lorem");
    crypto_blake2b_update(&mut ctx, b" ");
    crypto_blake2b_update(&mut ctx, b"ipsum");
    crypto_blake2b_final(&mut ctx, &mut hash);

    println!("{:02x?}", hash);
}
