use mini_monocypher::crypto_blake2b;

fn main() {
    let mut hash = [0u8; 32];
    let message = b"Lorem ipsum";
    crypto_blake2b(&mut hash, message);
    println!("{:02x?}", hash);
}
