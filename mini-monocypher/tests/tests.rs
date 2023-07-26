use hex_literal::hex;

#[test]
fn test_crypto_blake2b() {
    let mut hash = [0u8; 32];
    let message = b"Lorem ipsum";
    let expected = hex!("85 a6 d0 b4 bb 3f dc cf 60 e3 06 65 b7 69 49 7c 54 d9 42 2e 01 84 07 76 80 1e 09 4f 04 3f ff 41");

    mini_monocypher::crypto_blake2b(&mut hash, message);
    assert_eq!(hash, expected, "incorrect hash");
}

#[test]
fn test_crypto_blake2b_incremental() {
    let mut hash = [0u8; 32];
    let m1 = b"Lorem";
    let m2 = b" ";
    let m3 = b"ipsum";
    let expected = hex!("85 a6 d0 b4 bb 3f dc cf 60 e3 06 65 b7 69 49 7c 54 d9 42 2e 01 84 07 76 80 1e 09 4f 04 3f ff 41");

    let mut ctx = mini_monocypher::crypto_blake2b_ctx_new();
    mini_monocypher::crypto_blake2b_init(&mut ctx, 32);
    mini_monocypher::crypto_blake2b_update(&mut ctx, m1);
    mini_monocypher::crypto_blake2b_update(&mut ctx, m2);
    mini_monocypher::crypto_blake2b_update(&mut ctx, m3);
    mini_monocypher::crypto_blake2b_final(&mut ctx, &mut hash);
    assert_eq!(hash, expected, "incorrect hash");
}

#[test]
fn test_crypto_blake2b_keyed() {
    let mut hash = [0u8; 32];
    let message = b"Lorem ipsum";
    let key = hex!("aabbccdd");
    let expected = hex!("b7 6a de 2d 06 d3 e5 6a 1e e5 78 9d 25 1c c9 bb 75 b4 27 0f e5 9c 5e c0 76 8a 4f bb ca 59 ce 8a");

    mini_monocypher::crypto_blake2b_keyed(&mut hash, &key, message);
    assert_eq!(hash, expected, "incorrect hash");
}

#[test]
fn test_crypto_aead_lock() {
    let key = hex!("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");
    let nonce = [0u8; 24];
    let ad = b"authentication data";
    let plaintext = b"hello world";
    let mut ciphertext = [0u8; b"hello world".len()];
    let mut mac = [0u8; 16];
    let expected_ciphertext = hex!("bd ad ad b5 2a 7f fc 87 30 46 97");
    let expected_mac = hex!("15 06 e3 7d 59 18 cb 06 b9 d6 6e 66 fd 89 5d 12");

    mini_monocypher::crypto_aead_lock(
      &mut ciphertext,
      &mut mac,
      &key,
      &nonce,
      Some(ad),
      plaintext,
    );

    assert_eq!(ciphertext, expected_ciphertext, "incorrect ciphertext");
    assert_eq!(mac, expected_mac, "incorrect mac");
}

#[test]
fn test_crypto_aead_unlock() {
    let key = hex!("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");
    let nonce = [0u8; 24];
    let ad = b"authentication data";
    let ciphertext = hex!("bd ad ad b5 2a 7f fc 87 30 46 97");
    let mac = hex!("15 06 e3 7d 59 18 cb 06 b9 d6 6e 66 fd 89 5d 12");
    let mut plaintext = [0u8; b"hello world".len()];
    let expected_plaintext = b"hello world";

    mini_monocypher::crypto_aead_unlock(
      &mut plaintext,
      &mac,
      &key,
      &nonce,
      Some(ad),
      &ciphertext,
    );

    assert_eq!(&plaintext, expected_plaintext, "incorrect plaintext");
}

#[test]
fn test_crypto_x25519_pubkey() {
    let key = hex!("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");
    let mut pubkey = [0u8; 32];
    let expected = hex!("0d 67 bf 30 5a 47 b2 2d 47 e1 02 fd d0 0a 3b 9a e7 c1 94 8a 48 09 48 d6 b2 96 04 a6 13 65 4f 08");

    mini_monocypher::crypto_x25519_public_key(&mut pubkey, &key);

    assert_eq!(pubkey, expected, "incorrect public key");
}

#[test]
fn test_crypto_x25519() {
    let key = hex!("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    let their_pubkey = hex!("0d 67 bf 30 5a 47 b2 2d 47 e1 02 fd d0 0a 3b 9a e7 c1 94 8a 48 09 48 d6 b2 96 04 a6 13 65 4f 08");
    let mut shared = [0u8; 32];
    let expected = hex!("73 9f 58 e2 a4 6d de 60 19 ba 34 f3 c7 ec 5f 47 af 56 59 a7 52 32 59 74 1e 13 5a fa b5 a7 0c 32");

    mini_monocypher::crypto_x25519(&mut shared, &key, &their_pubkey);

    assert_eq!(shared, expected, "incorrect shared x25519 value");
}
