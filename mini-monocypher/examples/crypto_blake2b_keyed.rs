use mini_monocypher::crypto_blake2b_keyed;

fn main() {
    use rand_core::{OsRng, RngCore};
    let mut input_key = [0u8; 32];

    let mut rx_key = [0u8; 32];
    let mut tx_key = [0u8; 32];

    // usually key material comes from somewhere
    // but for this example we will just fill
    // with cryptographic random bytes
    OsRng.fill_bytes(&mut input_key);

    crypto_blake2b_keyed(&mut rx_key, &input_key, b"receive");
    crypto_blake2b_keyed(&mut tx_key, &input_key, b"transmit");
    println!("rx_key: {:02x?}", rx_key);
    println!("tx_key: {:02x?}", tx_key);
}
