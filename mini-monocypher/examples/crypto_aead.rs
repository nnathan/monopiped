use mini_monocypher::{crypto_aead_lock, crypto_aead_unlock};

fn main() {
    use rand_core::{OsRng, RngCore};
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    let ad = b"authentication data";
    let plaintext = b"hello world";
    let mut aead_ciphertext = [0u8; 11 + 16]; // enc("hello world") + MAC

    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut nonce);

    // encrypt

    // note: the AEAD ciphertext is the ciphertext (size is plaintext.len())
    // concatenated with the MAC.
    let (ciphertext_detached, mac) = aead_ciphertext.split_at_mut(plaintext.len());

    crypto_aead_lock(ciphertext_detached, mac, &key, &nonce, Some(ad), plaintext);

    // decrypt
    let mut plaintext = [0u8; 11];

    crypto_aead_unlock(
        &mut plaintext,
        &aead_ciphertext[(aead_ciphertext.len() - 16)..],
        &key,
        &nonce,
        Some(ad),
        &aead_ciphertext[..aead_ciphertext.len() - 16],
    )
    .expect("decryption should succeed");

    println!("plaintext: {:02x?}", plaintext);
}
