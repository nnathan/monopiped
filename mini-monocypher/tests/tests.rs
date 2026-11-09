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
fn test_crypto_blake2b_keyed_incremental() {
    let mut hash = [0u8; 32];
    let key = hex!("aabbccdd");
    let expected = hex!("b7 6a de 2d 06 d3 e5 6a 1e e5 78 9d 25 1c c9 bb 75 b4 27 0f e5 9c 5e c0 76 8a 4f bb ca 59 ce 8a");

    let mut ctx = mini_monocypher::crypto_blake2b_ctx_new();
    mini_monocypher::crypto_blake2b_keyed_init(&mut ctx, 32, &key);
    mini_monocypher::crypto_blake2b_update(&mut ctx, b"Lorem");
    mini_monocypher::crypto_blake2b_update(&mut ctx, b" ");
    mini_monocypher::crypto_blake2b_update(&mut ctx, b"ipsum");
    mini_monocypher::crypto_blake2b_final(&mut ctx, &mut hash);
    assert_eq!(hash, expected, "incorrect hash");
}

#[test]
#[should_panic]
fn test_crypto_blake2b_keyed_init_rejects_long_key() {
    let mut ctx = mini_monocypher::crypto_blake2b_ctx_new();
    mini_monocypher::crypto_blake2b_keyed_init(&mut ctx, 32, &[0u8; 65]);
}

#[test]
#[should_panic]
fn test_crypto_blake2b_keyed_init_rejects_bad_hash_size() {
    let mut ctx = mini_monocypher::crypto_blake2b_ctx_new();
    mini_monocypher::crypto_blake2b_keyed_init(&mut ctx, 65, b"key");
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

#[test]
#[should_panic]
fn test_crypto_blake2b_final_rejects_buffer_shorter_than_hash_size() {
    let mut hash = [0u8; 32];
    let mut ctx = mini_monocypher::crypto_blake2b_ctx_new();

    mini_monocypher::crypto_blake2b_init(&mut ctx, 64);
    mini_monocypher::crypto_blake2b_update(&mut ctx, b"Lorem ipsum");
    mini_monocypher::crypto_blake2b_final(&mut ctx, &mut hash);
}

#[test]
fn test_crypto_blake2b_final_larger_buffer_writes_hash_size_only() {
    let mut hash = [0u8; 64];
    let expected = hex!("85 a6 d0 b4 bb 3f dc cf 60 e3 06 65 b7 69 49 7c 54 d9 42 2e 01 84 07 76 80 1e 09 4f 04 3f ff 41");

    let mut ctx: mini_monocypher::crypto_blake2b_ctx = mini_monocypher::crypto_blake2b_ctx_new();
    mini_monocypher::crypto_blake2b_init(&mut ctx, 32);
    mini_monocypher::crypto_blake2b_update(&mut ctx, b"Lorem ipsum");
    mini_monocypher::crypto_blake2b_final(&mut ctx, &mut hash);

    assert_eq!(hash[..32], expected, "incorrect hash");
    assert_eq!(hash[32..], [0u8; 32], "wrote past hash_size");
}

macro_rules! test_crypto_verify {
    ($name:ident, $func:ident, $size:expr) => {
        #[test]
        fn $name() {
            let a = [0x5au8; $size];
            assert!(mini_monocypher::$func(&a, &a).is_ok());

            for i in 0..$size {
                let mut b = a;
                b[i] ^= 1;
                assert!(mini_monocypher::$func(&a, &b).is_err(), "byte {i}");
            }
        }
    };
}

test_crypto_verify!(test_crypto_verify16, crypto_verify16, 16);
test_crypto_verify!(test_crypto_verify32, crypto_verify32, 32);
test_crypto_verify!(test_crypto_verify64, crypto_verify64, 64);

#[test]
fn test_crypto_verify_returns_mismatch() {
    let result = mini_monocypher::crypto_verify16(&[0u8; 16], &[1u8; 16]);
    assert!(matches!(result, Err(mini_monocypher::ErrorKind::Mismatch)));
}

#[test]
fn test_authentication_failure_message_is_unchanged() {
    assert_eq!(
        mini_monocypher::ErrorKind::AuthenticationFailure.to_string(),
        "authentication failure trying to decrypt ciphertext"
    );
}

#[test]
fn test_crypto_wipe_erases_only_the_given_slice() {
    let mut buf = [0xffu8; 8];

    mini_monocypher::crypto_wipe(&mut buf[2..6]);

    assert_eq!(buf, [0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff]);
}

#[test]
fn test_crypto_wipe_accepts_empty_slice() {
    mini_monocypher::crypto_wipe(&mut []);
}

// RFC 8439 section 2.5.2
const POLY1305_KEY: [u8; 32] = hex!("85 d6 be 78 57 55 6d 33 7f 44 52 fe 42 d5 06 a8 01 03 80 8a fb 0d b2 fd 4a bf f6 af 41 49 f5 1b");
const POLY1305_MESSAGE: &[u8] = b"Cryptographic Forum Research Group";
const POLY1305_MAC: [u8; 16] = hex!("a8 06 1d c1 30 51 36 c6 c2 2b 8b af 0c 01 27 a9");

#[test]
fn test_crypto_poly1305() {
    let mut mac = [0u8; 16];

    mini_monocypher::crypto_poly1305(&mut mac, POLY1305_MESSAGE, &POLY1305_KEY);

    assert_eq!(mac, POLY1305_MAC, "incorrect mac");
}

#[test]
fn test_crypto_poly1305_incremental_at_every_split() {
    for i in 0..=POLY1305_MESSAGE.len() {
        let mut mac = [0u8; 16];
        let mut ctx = mini_monocypher::crypto_poly1305_ctx_new();

        mini_monocypher::crypto_poly1305_init(&mut ctx, &POLY1305_KEY);
        mini_monocypher::crypto_poly1305_update(&mut ctx, &POLY1305_MESSAGE[..i]);
        mini_monocypher::crypto_poly1305_update(&mut ctx, &POLY1305_MESSAGE[i..]);
        mini_monocypher::crypto_poly1305_final(&mut ctx, &mut mac);

        assert_eq!(mac, POLY1305_MAC, "incorrect mac splitting at {i}");
    }
}

#[test]
fn test_crypto_poly1305_empty_message() {
    let mut mac = [0u8; 16];
    let mut incremental_mac = [0u8; 16];
    let mut ctx = mini_monocypher::crypto_poly1305_ctx_new();

    mini_monocypher::crypto_poly1305(&mut mac, b"", &POLY1305_KEY);

    mini_monocypher::crypto_poly1305_init(&mut ctx, &POLY1305_KEY);
    mini_monocypher::crypto_poly1305_final(&mut ctx, &mut incremental_mac);

    assert_eq!(mac, incremental_mac, "interfaces disagree");
}

// RFC 8439 section 2.4.2
const CHACHA20_PLAIN_TEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

#[test]
fn test_crypto_chacha20_ietf() {
    let key = hex!("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f");
    let nonce = hex!("00 00 00 00 00 00 00 4a 00 00 00 00");
    let expected = hex!(
        "6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81 e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b"
        "f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57 16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8"
        "07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e 52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36"
        "5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42 87 4d"
    );
    let mut cipher_text = [0u8; 114];

    let ctr = mini_monocypher::crypto_chacha20_ietf(
        &mut cipher_text,
        Some(CHACHA20_PLAIN_TEXT),
        &key,
        &nonce,
        1,
    );

    assert_eq!(cipher_text, expected, "incorrect ciphertext");
    assert_eq!(ctr, 3, "incorrect counter");
}

#[test]
fn test_crypto_chacha20_h() {
    let key = hex!("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f");
    let input = hex!("00 00 00 09 00 00 00 4a 00 00 00 00 31 41 59 27");
    let expected = hex!("82 41 3b 42 27 b2 7b fe d3 0e 42 50 8a 87 7d 73 a0 f9 e4 d5 8a 74 a8 53 c1 2e c4 13 26 d3 ec dc");
    let mut out = [0u8; 32];

    mini_monocypher::crypto_chacha20_h(&mut out, &key, &input);

    assert_eq!(out, expected, "incorrect output");
}

macro_rules! test_crypto_chacha20 {
    ($module:ident, $func:ident, $nonce_size:expr) => {
        mod $module {
            use mini_monocypher::$func;

            const KEY: [u8; 32] = [1u8; 32];
            const NONCE: [u8; $nonce_size] = [2u8; $nonce_size];

            #[test]
            fn none_is_the_stream_for_all_of_cipher_text() {
                let mut stream = [0xffu8; 100];
                let mut encrypted_zeroes = [0xffu8; 100];

                let a = $func(&mut stream, None, &KEY, &NONCE, 0);
                let b = $func(&mut encrypted_zeroes, Some(&[0u8; 100]), &KEY, &NONCE, 0);

                assert_eq!(stream, encrypted_zeroes);
                assert_eq!(a, b);
            }

            #[test]
            fn empty_plain_text_writes_nothing() {
                let mut cipher_text = [0xffu8; 16];

                let ctr = $func(&mut cipher_text, Some(&[]), &KEY, &NONCE, 7);

                assert_eq!(cipher_text, [0xffu8; 16]);
                assert_eq!(ctr, 7);
            }

            #[test]
            fn round_trip() {
                let plain_text = b"Lorem ipsum";
                let mut cipher_text = [0u8; 11];
                let mut decrypted = [0u8; 11];

                $func(&mut cipher_text, Some(plain_text), &KEY, &NONCE, 0);
                $func(&mut decrypted, Some(&cipher_text), &KEY, &NONCE, 0);

                assert_ne!(&cipher_text, plain_text);
                assert_eq!(&decrypted, plain_text);
            }

            #[test]
            fn returned_counter_continues_the_stream() {
                let mut whole = [0u8; 128];
                let mut parts = [0u8; 128];

                $func(&mut whole, None, &KEY, &NONCE, 0);
                let (first, second) = parts.split_at_mut(64);
                let ctr = $func(first, None, &KEY, &NONCE, 0);
                assert_eq!(ctr, 1);
                $func(second, None, &KEY, &NONCE, ctr);

                assert_eq!(whole, parts);
            }

            #[test]
            fn longer_cipher_text_leaves_the_rest_untouched() {
                let mut exact = [0u8; 11];
                let mut longer = [0xffu8; 16];

                let a = $func(&mut exact, Some(b"Lorem ipsum"), &KEY, &NONCE, 0);
                let b = $func(&mut longer, Some(b"Lorem ipsum"), &KEY, &NONCE, 0);

                assert_eq!(longer[..11], exact);
                assert_eq!(longer[11..], [0xffu8; 5]);
                assert_eq!(a, b);
            }

            #[test]
            #[should_panic]
            fn rejects_short_cipher_text() {
                let mut cipher_text = [0u8; 10];

                $func(&mut cipher_text, Some(b"Lorem ipsum"), &KEY, &NONCE, 0);
            }
        }
    };
}

test_crypto_chacha20!(chacha20_djb, crypto_chacha20_djb, 8);
test_crypto_chacha20!(chacha20_ietf, crypto_chacha20_ietf, 12);
test_crypto_chacha20!(chacha20_x, crypto_chacha20_x, 24);

macro_rules! test_ctx_wiped_on_drop {
    ($name:ident, $ty:ident, $new:ident, |$ctx:ident| $init:block) => {
        #[test]
        fn $name() {
            let mut $ctx = std::mem::ManuallyDrop::new(mini_monocypher::$new());
            $init

            let bytes = |c: &mini_monocypher::$ty| unsafe {
                std::slice::from_raw_parts(
                    c as *const mini_monocypher::$ty as *const u8,
                    std::mem::size_of::<mini_monocypher::$ty>(),
                )
                .to_vec()
            };
            assert!(bytes(&$ctx).iter().any(|b| *b != 0), "context was not set up");

            unsafe { std::mem::ManuallyDrop::drop(&mut $ctx) };

            assert!(bytes(&$ctx).iter().all(|b| *b == 0), "context was not wiped");
        }
    };
}

test_ctx_wiped_on_drop!(
    test_crypto_blake2b_ctx_wiped_on_drop,
    crypto_blake2b_ctx,
    crypto_blake2b_ctx_new,
    |ctx| {
        mini_monocypher::crypto_blake2b_keyed_init(&mut ctx, 32, &[1u8; 32]);
    }
);

test_ctx_wiped_on_drop!(
    test_crypto_poly1305_ctx_wiped_on_drop,
    crypto_poly1305_ctx,
    crypto_poly1305_ctx_new,
    |ctx| {
        mini_monocypher::crypto_poly1305_init(&mut ctx, &[1u8; 32]);
    }
);

test_ctx_wiped_on_drop!(
    test_crypto_aead_ctx_wiped_on_drop,
    crypto_aead_ctx,
    crypto_aead_ctx_new,
    |ctx| {
        mini_monocypher::crypto_aead_init_x(&mut ctx, &[1u8; 32], &[2u8; 24]);
    }
);

mod aead_incremental {
    use mini_monocypher::{
        crypto_aead_ctx, crypto_aead_ctx_new, crypto_aead_init_djb, crypto_aead_init_ietf,
        crypto_aead_init_x, crypto_aead_lock, crypto_aead_read, crypto_aead_write, ErrorKind,
    };

    const KEY: [u8; 32] = [1u8; 32];
    const NONCE: [u8; 24] = [2u8; 24];
    const AD: &[u8] = b"authentication data";

    fn ctx() -> crypto_aead_ctx {
        let mut ctx = crypto_aead_ctx_new();
        crypto_aead_init_x(&mut ctx, &KEY, &NONCE);
        ctx
    }

    fn two_chunks() -> ([[u8; 5]; 2], [[u8; 16]; 2]) {
        let mut cipher_text = [[0u8; 5]; 2];
        let mut mac = [[0u8; 16]; 2];
        let mut w = ctx();

        crypto_aead_write(&mut w, &mut cipher_text[0], &mut mac[0], Some(AD), b"Lorem");
        crypto_aead_write(&mut w, &mut cipher_text[1], &mut mac[1], Some(AD), b"ipsum");

        (cipher_text, mac)
    }

    macro_rules! round_trip {
        ($name:ident, $init:ident, $nonce_size:expr) => {
            #[test]
            fn $name() {
                let nonce = [3u8; $nonce_size];
                let (mut w, mut r) = (crypto_aead_ctx_new(), crypto_aead_ctx_new());
                $init(&mut w, &KEY, &nonce);
                $init(&mut r, &KEY, &nonce);

                for chunk in [&b"Lorem"[..], b"ipsum dolor", b""] {
                    let mut cipher_text = vec![0u8; chunk.len()];
                    let mut plain_text = vec![0u8; chunk.len()];
                    let mut mac = [0u8; 16];

                    crypto_aead_write(&mut w, &mut cipher_text, &mut mac, Some(AD), chunk);
                    crypto_aead_read(&mut r, &mut plain_text, &mac, Some(AD), &cipher_text)
                        .expect("decryption should succeed");

                    assert_eq!(plain_text, chunk);
                }
            }
        };
    }

    round_trip!(round_trip_x, crypto_aead_init_x, 24);
    round_trip!(round_trip_djb, crypto_aead_init_djb, 8);
    round_trip!(round_trip_ietf, crypto_aead_init_ietf, 12);

    #[test]
    fn first_write_matches_crypto_aead_lock() {
        let (mut a, mut b) = ([0u8; 5], [0u8; 5]);
        let (mut a_mac, mut b_mac) = ([0u8; 16], [0u8; 16]);

        crypto_aead_write(&mut ctx(), &mut a, &mut a_mac, Some(AD), b"Lorem");
        crypto_aead_lock(&mut b, &mut b_mac, &KEY, &NONCE, Some(AD), b"Lorem");

        assert_eq!(a, b);
        assert_eq!(a_mac, b_mac);
    }

    #[test]
    fn rejects_reordered_chunks() {
        let (cipher_text, mac) = two_chunks();
        let mut plain_text = [0u8; 5];

        let result = crypto_aead_read(&mut ctx(), &mut plain_text, &mac[1], Some(AD), &cipher_text[1]);

        assert!(matches!(result, Err(ErrorKind::AuthenticationFailure)));
    }

    #[test]
    fn failed_read_writes_nothing_and_leaves_ctx_usable() {
        let (cipher_text, mac) = two_chunks();
        let mut bad_mac = mac[0];
        bad_mac[0] ^= 1;
        let mut plain_text = [0xffu8; 5];
        let mut r = ctx();

        assert!(crypto_aead_read(&mut r, &mut plain_text, &bad_mac, Some(AD), &cipher_text[0]).is_err());
        assert_eq!(plain_text, [0xffu8; 5]);

        assert!(crypto_aead_read(&mut r, &mut plain_text, &mac[0], Some(b"wrong"), &cipher_text[0]).is_err());

        crypto_aead_read(&mut r, &mut plain_text, &mac[0], Some(AD), &cipher_text[0])
            .expect("correct chunk should still succeed");
        assert_eq!(&plain_text, b"Lorem");
    }

    #[test]
    fn longer_output_leaves_the_rest_untouched() {
        let mut cipher_text = [0xffu8; 8];
        let mut plain_text = [0xffu8; 8];
        let mut mac = [0u8; 16];

        crypto_aead_write(&mut ctx(), &mut cipher_text, &mut mac, None, b"Lorem");
        assert_eq!(cipher_text[5..], [0xffu8; 3]);

        crypto_aead_read(&mut ctx(), &mut plain_text, &mac, None, &cipher_text[..5])
            .expect("decryption should succeed");
        assert_eq!(&plain_text[..5], b"Lorem");
        assert_eq!(plain_text[5..], [0xffu8; 3]);
    }

    #[test]
    #[should_panic]
    fn write_rejects_short_cipher_text() {
        crypto_aead_write(&mut ctx(), &mut [0u8; 4], &mut [0u8; 16], None, b"Lorem");
    }

    #[test]
    #[should_panic]
    fn read_rejects_short_plain_text() {
        let _ = crypto_aead_read(&mut ctx(), &mut [0u8; 4], &[0u8; 16], None, b"Lorem");
    }
}

fn x25519_test_key(i: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    mini_monocypher::crypto_blake2b(&mut key, &[i]);
    key
}

#[test]
fn test_crypto_x25519_inverse_undoes_crypto_x25519() {
    for i in 0..32 {
        let private_key = x25519_test_key(i);
        let mut base = [0u8; 32];
        let mut curve_point = [0u8; 32];
        let mut blind_salt = [0u8; 32];

        mini_monocypher::crypto_x25519_public_key(&mut base, &x25519_test_key(100 + i));
        mini_monocypher::crypto_x25519(&mut curve_point, &private_key, &base);
        mini_monocypher::crypto_x25519_inverse(&mut blind_salt, &private_key, &curve_point);

        assert_eq!(blind_salt, base, "key {i}");
    }
}

#[test]
fn test_crypto_x25519_inverse_low_order_points_give_zero() {
    let low_order = [
        [0u8; 32],
        hex!("01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"),
        hex!("5f 9c 95 bc a3 50 8c 24 b1 d0 b1 55 9c 83 ef 5b 04 44 5c c4 58 1c 8e 86 d8 22 4e dd d0 9f 11 57"),
        hex!("e0 eb 7a 7c 3b 41 b8 ae 16 56 e3 fa f1 9f c4 6a da 09 8d eb 9c 32 b1 fd 86 62 05 16 5f 49 b8 00"),
    ];

    for point in low_order {
        let mut blind_salt = [0xffu8; 32];

        mini_monocypher::crypto_x25519_inverse(&mut blind_salt, &x25519_test_key(1), &point);

        assert_eq!(blind_salt, [0u8; 32]);
    }
}

#[test]
fn test_crypto_x25519_dirty_functions_agree() {
    for i in 0..32 {
        let sk = x25519_test_key(i);
        let mut small = [0u8; 32];
        let mut fast = [0u8; 32];

        mini_monocypher::crypto_x25519_dirty_small(&mut small, &sk);
        mini_monocypher::crypto_x25519_dirty_fast(&mut fast, &sk);

        assert_eq!(small, fast, "key {i}");
    }
}

#[test]
fn test_crypto_x25519_dirty_matches_public_key_with_low_bits_cleared() {
    for i in 0..32 {
        let mut sk = x25519_test_key(i);
        sk[0] &= 248;
        let mut dirty = [0u8; 32];
        let mut clean = [0u8; 32];

        mini_monocypher::crypto_x25519_dirty_fast(&mut dirty, &sk);
        mini_monocypher::crypto_x25519_public_key(&mut clean, &sk);

        assert_eq!(dirty, clean, "key {i}");
    }
}

fn eddsa_test_key_pair(i: u8) -> ([u8; 64], [u8; 32]) {
    let mut seed = x25519_test_key(i);
    let mut secret_key = [0u8; 64];
    let mut public_key = [0u8; 32];

    mini_monocypher::crypto_eddsa_key_pair(&mut secret_key, &mut public_key, &mut seed);

    (secret_key, public_key)
}

#[test]
fn test_crypto_eddsa_key_pair_wipes_seed() {
    let original = x25519_test_key(1);
    let mut seed = original;
    let mut secret_key = [0u8; 64];
    let mut public_key = [0u8; 32];

    mini_monocypher::crypto_eddsa_key_pair(&mut secret_key, &mut public_key, &mut seed);

    assert_eq!(seed, [0u8; 32], "seed was not wiped");
    assert_eq!(secret_key[..32], original, "secret key should start with the seed");
    assert_eq!(secret_key[32..], public_key, "secret key should end with the public key");
}

#[test]
fn test_crypto_eddsa_sign_and_check() {
    let (secret_key, public_key) = eddsa_test_key_pair(1);
    let (_, other_public_key) = eddsa_test_key_pair(2);
    let mut signature = [0u8; 64];

    mini_monocypher::crypto_eddsa_sign(&mut signature, &secret_key, b"Lorem ipsum");

    assert!(mini_monocypher::crypto_eddsa_check(&signature, &public_key, b"Lorem ipsum").is_ok());

    let result = mini_monocypher::crypto_eddsa_check(&signature, &public_key, b"Lorem ipsuM");
    assert!(matches!(result, Err(mini_monocypher::ErrorKind::InvalidSignature)));

    assert!(mini_monocypher::crypto_eddsa_check(&signature, &other_public_key, b"Lorem ipsum").is_err());

    for i in [0, 31, 32, 63] {
        let mut bad_signature = signature;
        bad_signature[i] ^= 1;
        assert!(
            mini_monocypher::crypto_eddsa_check(&bad_signature, &public_key, b"Lorem ipsum").is_err(),
            "byte {i}"
        );
    }
}

#[test]
fn test_x25519_eddsa_conversions() {
    for i in 0..32 {
        let (secret_key, mut eddsa_public) = eddsa_test_key_pair(i);
        let mut x25519_private = [0u8; 64];
        let mut converted = [0u8; 32];
        let mut x25519_public = [0u8; 32];
        let mut converted_back = [0u8; 32];

        mini_monocypher::crypto_blake2b(&mut x25519_private, &secret_key[..32]);
        mini_monocypher::crypto_eddsa_to_x25519(&mut converted, &eddsa_public);
        mini_monocypher::crypto_x25519_public_key(
            &mut x25519_public,
            x25519_private[..32].try_into().unwrap(),
        );
        assert_eq!(converted, x25519_public, "key {i}");

        mini_monocypher::crypto_x25519_to_eddsa(&mut converted_back, &converted);
        assert_eq!(converted_back[31] & 0x80, 0, "key {i}");
        eddsa_public[31] &= 0x7f;
        assert_eq!(converted_back, eddsa_public, "key {i}");
    }
}

fn eddsa_hash_reduce(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = [0u8; 64];
    let mut reduced = [0u8; 32];
    let mut ctx = mini_monocypher::crypto_blake2b_ctx_new();

    mini_monocypher::crypto_blake2b_init(&mut ctx, 64);
    for part in parts {
        mini_monocypher::crypto_blake2b_update(&mut ctx, part);
    }
    mini_monocypher::crypto_blake2b_final(&mut ctx, &mut hash);
    mini_monocypher::hazmat::crypto_eddsa_reduce(&mut reduced, &hash);

    reduced
}

#[test]
fn test_crypto_eddsa_building_blocks_rebuild_a_signature() {
    let message = b"Lorem ipsum";

    for i in 0..32 {
        let (secret_key, public_key) = eddsa_test_key_pair(i);
        let mut expanded = [0u8; 64];
        let mut a = [0u8; 32];
        let mut derived_public_key = [0u8; 32];
        let mut big_r = [0u8; 32];
        let mut s = [0u8; 32];
        let mut expected = [0u8; 64];

        mini_monocypher::crypto_blake2b(&mut expanded, &secret_key[..32]);
        mini_monocypher::hazmat::crypto_eddsa_trim_scalar(&mut a, expanded[..32].try_into().unwrap());
        mini_monocypher::hazmat::crypto_eddsa_scalarbase(&mut derived_public_key, &a);
        assert_eq!(derived_public_key, public_key, "key {i}");

        let r = eddsa_hash_reduce(&[&expanded[32..], message]);
        mini_monocypher::hazmat::crypto_eddsa_scalarbase(&mut big_r, &r);
        let h = eddsa_hash_reduce(&[&big_r, &public_key, message]);
        mini_monocypher::hazmat::crypto_eddsa_mul_add(&mut s, &h, &a, &r);

        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&big_r);
        signature[32..].copy_from_slice(&s);

        mini_monocypher::crypto_eddsa_sign(&mut expected, &secret_key, message);
        assert_eq!(signature, expected, "key {i}");

        assert!(mini_monocypher::hazmat::crypto_eddsa_check_equation(&signature, &public_key, &h).is_ok());

        let wrong_h = eddsa_hash_reduce(&[b"wrong"]);
        let result = mini_monocypher::hazmat::crypto_eddsa_check_equation(&signature, &public_key, &wrong_h);
        assert!(matches!(result, Err(mini_monocypher::ErrorKind::InvalidSignature)));
    }
}

#[test]
fn test_crypto_elligator_key_pair() {
    for i in 0..32 {
        let mut seed = x25519_test_key(i);
        let mut hidden = [0u8; 32];
        let mut secret_key = [0u8; 32];
        let mut curve = [0u8; 32];
        let mut public_key = [0u8; 32];

        mini_monocypher::crypto_elligator_key_pair(&mut hidden, &mut secret_key, &mut seed);
        assert_eq!(seed, [0u8; 32], "seed was not wiped");

        mini_monocypher::crypto_elligator_map(&mut curve, &hidden);
        mini_monocypher::crypto_x25519_dirty_fast(&mut public_key, &secret_key);
        assert_eq!(curve, public_key, "key {i}");
    }
}

#[test]
fn test_crypto_elligator_rev() {
    let (mut hidden_count, mut unsuitable_count) = (0, 0);

    for i in 0..64 {
        let mut public_key = [0u8; 32];
        let mut hidden = [0u8; 32];
        let mut same_hidden = [0u8; 32];
        let mut other_tweak_hidden = [0u8; 32];

        mini_monocypher::crypto_x25519_dirty_fast(&mut public_key, &x25519_test_key(i));

        let result = mini_monocypher::crypto_elligator_rev(&mut hidden, &public_key, 1);
        let other_tweak = mini_monocypher::crypto_elligator_rev(&mut other_tweak_hidden, &public_key, 0xc2);
        assert_eq!(result.is_ok(), other_tweak.is_ok(), "the tweak must not matter, key {i}");

        match result {
            Err(mini_monocypher::ErrorKind::UnsuitableForHiding) => unsuitable_count += 1,
            Err(e) => panic!("unexpected error: {e}"),
            Ok(()) => {
                hidden_count += 1;
                let mut curve = [0u8; 32];
                mini_monocypher::crypto_elligator_map(&mut curve, &hidden);
                assert_eq!(curve, public_key, "key {i}");

                mini_monocypher::crypto_elligator_rev(&mut same_hidden, &public_key, 1)
                    .expect("a suitable key always succeeds");
                assert_eq!(hidden, same_hidden, "key {i}");
            }
        }
    }

    assert!(hidden_count > 0 && unsuitable_count > 0);
}

mod argon2 {
    use hex_literal::hex;
    use mini_monocypher::{
        crypto_argon2, crypto_argon2_config, crypto_argon2_extras, crypto_argon2_inputs,
        crypto_argon2_no_extras, CRYPTO_ARGON2_D, CRYPTO_ARGON2_I, CRYPTO_ARGON2_ID,
    };

    const PASS: [u8; 32] = [1u8; 32];
    const SALT: [u8; 16] = [2u8; 16];
    const KEY: [u8; 8] = [3u8; 8];
    const AD: [u8; 12] = [4u8; 12];

    fn config() -> crypto_argon2_config {
        crypto_argon2_config {
            algorithm: CRYPTO_ARGON2_I,
            nb_blocks: 8,
            nb_passes: 1,
            nb_lanes: 1,
        }
    }

    fn inputs() -> crypto_argon2_inputs<'static> {
        crypto_argon2_inputs {
            pass: &PASS,
            salt: &SALT,
        }
    }

    fn hash(extras: crypto_argon2_extras) -> [u8; 32] {
        let mut hash = [0u8; 32];
        crypto_argon2(&mut hash, &mut [0u64; 8 * 128], config(), inputs(), extras);
        hash
    }

    // RFC 9106 section 5
    macro_rules! rfc_vector {
        ($name:ident, $algorithm:expr, $expected:literal) => {
            #[test]
            fn $name() {
                let config = crypto_argon2_config {
                    algorithm: $algorithm,
                    nb_blocks: 32,
                    nb_passes: 3,
                    nb_lanes: 4,
                };
                let extras = crypto_argon2_extras {
                    key: Some(&KEY),
                    ad: Some(&AD),
                };
                let mut hash = [0u8; 32];
                let mut work_area = [0u64; 32 * 128];

                crypto_argon2(&mut hash, &mut work_area, config, inputs(), extras);

                assert_eq!(hash, hex!($expected), "incorrect hash");
            }
        };
    }

    rfc_vector!(rfc_9106_argon2d, CRYPTO_ARGON2_D, "51 2b 39 1b 6f 11 62 97 53 71 d3 09 19 73 42 94 f8 68 e3 be 39 84 f3 c1 a1 3a 4d b9 fa be 4a cb");
    rfc_vector!(rfc_9106_argon2i, CRYPTO_ARGON2_I, "c8 14 d9 d1 dc 7f 37 aa 13 f0 d7 7f 24 94 bd a1 c8 de 6b 01 6d d3 88 d2 99 52 a4 c4 67 2b 6c e8");
    rfc_vector!(rfc_9106_argon2id, CRYPTO_ARGON2_ID, "0d 64 0d f5 8d 78 76 6c 08 c0 37 a3 4a 8b 53 c9 d0 1e f0 45 2d 75 b6 5e b5 25 20 e9 6b 01 e6 59");

    #[test]
    fn extras_change_the_hash() {
        let with_key = crypto_argon2_extras {
            key: Some(&KEY),
            ad: None,
        };
        let with_ad = crypto_argon2_extras {
            key: None,
            ad: Some(&AD),
        };
        let none = hash(crypto_argon2_no_extras);

        assert_ne!(none, hash(with_key));
        assert_ne!(none, hash(with_ad));
        assert_ne!(hash(with_key), hash(with_ad));
    }

    #[test]
    fn empty_extras_are_the_same_as_none() {
        let empty = crypto_argon2_extras {
            key: Some(&[]),
            ad: Some(&[]),
        };

        assert_eq!(hash(empty), hash(crypto_argon2_no_extras));
    }

    #[test]
    fn work_area_is_wiped() {
        let mut hash = [0u8; 32];
        let mut work_area = [0xffu64; 8 * 128];

        crypto_argon2(&mut hash, &mut work_area, config(), inputs(), crypto_argon2_no_extras);

        assert!(work_area.iter().all(|x| *x == 0), "work area was not wiped");
    }

    #[test]
    fn larger_work_area_is_accepted() {
        let mut other = [0u8; 32];

        crypto_argon2(&mut other, &mut [0u64; 9 * 128], config(), inputs(), crypto_argon2_no_extras);

        assert_eq!(other, hash(crypto_argon2_no_extras));
    }

    macro_rules! rejects {
        ($name:ident, $work_blocks:expr, $inputs:expr, $($field:ident: $value:expr),*) => {
            #[test]
            #[should_panic]
            fn $name() {
                let mut hash = [0u8; 32];
                let mut work_area = vec![0u64; $work_blocks * 128];
                let config = crypto_argon2_config {
                    $($field: $value,)*
                    ..config()
                };

                crypto_argon2(&mut hash, &mut work_area, config, $inputs, crypto_argon2_no_extras);
            }
        };
    }

    rejects!(rejects_zero_lanes, 8, inputs(), nb_lanes: 0);
    rejects!(rejects_zero_passes, 8, inputs(), nb_passes: 0);
    rejects!(rejects_too_few_blocks_for_lanes, 16, inputs(), nb_blocks: 15, nb_lanes: 2);
    rejects!(rejects_small_work_area, 7, inputs(), nb_blocks: 8);
    rejects!(rejects_short_salt, 8, crypto_argon2_inputs { pass: &PASS, salt: &[0u8; 7] }, nb_blocks: 8);
}

mod sha512 {
    use hex_literal::hex;
    use mini_monocypher::{
        crypto_sha512, crypto_sha512_ctx_new, crypto_sha512_final, crypto_sha512_hkdf,
        crypto_sha512_hkdf_expand, crypto_sha512_hmac, crypto_sha512_hmac_ctx_new,
        crypto_sha512_hmac_final, crypto_sha512_hmac_init, crypto_sha512_hmac_update,
        crypto_sha512_init, crypto_sha512_update,
    };

    const SPLITS: [usize; 6] = [0, 1, 127, 128, 129, 300];

    fn long_message() -> Vec<u8> {
        (0..300).map(|i| i as u8).collect()
    }

    // FIPS 180 "abc"
    #[test]
    fn known_hash() {
        let mut hash = [0u8; 64];
        let expected = hex!(
            "dd af 35 a1 93 61 7a ba cc 41 73 49 ae 20 41 31 12 e6 fa 4e 89 a9 7e a2 0a 9e ee e6 4b 55 d3 9a"
            "21 92 99 2a 27 4f c1 a8 36 ba 3c 23 a3 fe eb bd 45 4d 44 23 64 3c e8 0e 2a 9a c9 4f a5 4c a4 9f"
        );

        crypto_sha512(&mut hash, b"abc");

        assert_eq!(hash, expected, "incorrect hash");
    }

    #[test]
    fn incremental_matches_one_shot() {
        let message = long_message();
        let mut expected = [0u8; 64];
        crypto_sha512(&mut expected, &message);

        for split in SPLITS {
            let mut hash = [0u8; 64];
            let mut ctx = crypto_sha512_ctx_new();

            crypto_sha512_init(&mut ctx);
            crypto_sha512_update(&mut ctx, &message[..split]);
            crypto_sha512_update(&mut ctx, &message[split..]);
            crypto_sha512_final(&mut ctx, &mut hash);

            assert_eq!(hash, expected, "split {split}");
        }
    }

    // RFC 4231 test case 1
    #[test]
    fn known_hmac() {
        let mut hmac = [0u8; 64];
        let expected = hex!(
            "87 aa 7c de a5 ef 61 9d 4f f0 b4 24 1a 1d 6c b0 23 79 f4 e2 ce 4e c2 78 7a d0 b3 05 45 e1 7c de"
            "da a8 33 b7 d6 b8 a7 02 03 8b 27 4e ae a3 f4 e4 be 9d 91 4e eb 61 f1 70 2e 69 6c 20 3a 12 68 54"
        );

        crypto_sha512_hmac(&mut hmac, &[0x0bu8; 20], b"Hi There");

        assert_eq!(hmac, expected, "incorrect hmac");
    }

    #[test]
    fn hmac_incremental_matches_one_shot() {
        let message = long_message();
        let key = [7u8; 32];
        let mut expected = [0u8; 64];
        crypto_sha512_hmac(&mut expected, &key, &message);

        for split in SPLITS {
            let mut hmac = [0u8; 64];
            let mut ctx = crypto_sha512_hmac_ctx_new();

            crypto_sha512_hmac_init(&mut ctx, &key);
            crypto_sha512_hmac_update(&mut ctx, &message[..split]);
            crypto_sha512_hmac_update(&mut ctx, &message[split..]);
            crypto_sha512_hmac_final(&mut ctx, &mut hmac);

            assert_eq!(hmac, expected, "split {split}");
        }
    }

    #[test]
    fn hkdf_is_extract_then_expand() {
        let (ikm, salt, info) = (b"input key", [2u8; 16], b"domain");
        let mut prk = [0u8; 64];
        let mut expanded = [0u8; 100];
        let mut okm = [0u8; 100];

        crypto_sha512_hmac(&mut prk, &salt, ikm);
        crypto_sha512_hkdf_expand(&mut expanded, &prk, Some(info));
        crypto_sha512_hkdf(&mut okm, ikm, Some(&salt), Some(info));

        assert_eq!(okm, expanded);
    }

    #[test]
    fn hkdf_expand_first_block_is_hmac_of_info_and_counter() {
        let prk = [3u8; 64];
        let mut okm = [0u8; 64];
        let mut expected = [0u8; 64];

        crypto_sha512_hkdf_expand(&mut okm, &prk, Some(b"domain"));
        crypto_sha512_hmac(&mut expected, &prk, b"domain\x01");

        assert_eq!(okm, expected);
    }

    #[test]
    fn hkdf_none_is_the_same_as_empty() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];

        crypto_sha512_hkdf(&mut a, b"ikm", None, None);
        crypto_sha512_hkdf(&mut b, b"ikm", Some(&[]), Some(&[]));

        assert_eq!(a, b);
    }

    #[test]
    fn hkdf_accepts_the_maximum_length() {
        let mut okm = vec![0u8; 16320];

        crypto_sha512_hkdf(&mut okm, b"ikm", None, None);
        crypto_sha512_hkdf_expand(&mut okm, &[1u8; 64], None);
    }

    #[test]
    #[should_panic]
    fn hkdf_rejects_too_much_output() {
        crypto_sha512_hkdf(&mut vec![0u8; 16321], b"ikm", None, None);
    }

    #[test]
    #[should_panic]
    fn hkdf_expand_rejects_too_much_output() {
        crypto_sha512_hkdf_expand(&mut vec![0u8; 16321], &[1u8; 64], None);
    }
}

test_ctx_wiped_on_drop!(
    test_crypto_sha512_ctx_wiped_on_drop,
    crypto_sha512_ctx,
    crypto_sha512_ctx_new,
    |ctx| {
        mini_monocypher::crypto_sha512_init(&mut ctx);
    }
);

test_ctx_wiped_on_drop!(
    test_crypto_sha512_hmac_ctx_wiped_on_drop,
    crypto_sha512_hmac_ctx,
    crypto_sha512_hmac_ctx_new,
    |ctx| {
        mini_monocypher::crypto_sha512_hmac_init(&mut ctx, &[1u8; 32]);
    }
);

mod ed25519 {
    use hex_literal::hex;
    use mini_monocypher::{
        crypto_ed25519_check, crypto_ed25519_key_pair, crypto_ed25519_ph_check,
        crypto_ed25519_ph_sign, crypto_ed25519_sign, crypto_sha512, ErrorKind,
    };

    fn key_pair(mut seed: [u8; 32]) -> ([u8; 64], [u8; 32]) {
        let mut secret_key = [0u8; 64];
        let mut public_key = [0u8; 32];

        crypto_ed25519_key_pair(&mut secret_key, &mut public_key, &mut seed);

        (secret_key, public_key)
    }

    // RFC 8032 section 7.1 test 1
    #[test]
    fn rfc_8032_ed25519() {
        let (secret_key, public_key) = key_pair(hex!(
            "9d 61 b1 9d ef fd 5a 60 ba 84 4a f4 92 ec 2c c4 44 49 c5 69 7b 32 69 19 70 3b ac 03 1c ae 7f 60"
        ));
        let expected = hex!(
            "e5 56 43 00 c3 60 ac 72 90 86 e2 cc 80 6e 82 8a 84 87 7f 1e b8 e5 d9 74 d8 73 e0 65 22 49 01 55"
            "5f b8 82 15 90 a3 3b ac c6 1e 39 70 1c f9 b4 6b d2 5b f5 f0 59 5b be 24 65 51 41 43 8e 7a 10 0b"
        );
        let mut signature = [0u8; 64];

        assert_eq!(public_key, hex!("d7 5a 98 01 82 b1 0a b7 d5 4b fe d3 c9 64 07 3a 0e e1 72 f3 da a6 23 25 af 02 1a 68 f7 07 51 1a"));

        crypto_ed25519_sign(&mut signature, &secret_key, b"");

        assert_eq!(signature, expected, "incorrect signature");
        assert!(crypto_ed25519_check(&signature, &public_key, b"").is_ok());
    }

    // RFC 8032 section 7.3 test abc
    #[test]
    fn rfc_8032_ed25519ph() {
        let (secret_key, public_key) = key_pair(hex!(
            "83 3f e6 24 09 23 7b 9d 62 ec 77 58 75 20 91 1e 9a 75 9c ec 1d 19 75 5b 7d a9 01 b9 6d ca 3d 42"
        ));
        let expected = hex!(
            "98 a7 02 22 f0 b8 12 1a a9 d3 0f 81 3d 68 3f 80 9e 46 2b 46 9c 7f f8 76 39 49 9b b9 4e 6d ae 41"
            "31 f8 50 42 46 3c 2a 35 5a 20 03 d0 62 ad f5 aa a1 0b 8c 61 e6 36 06 2a aa d1 1c 2a 26 08 34 06"
        );
        let mut message_hash = [0u8; 64];
        let mut signature = [0u8; 64];

        assert_eq!(public_key, hex!("ec 17 2b 93 ad 5e 56 3b f4 93 2c 70 e1 24 50 34 c3 54 67 ef 2e fd 4d 64 eb f8 19 68 34 67 e2 bf"));

        crypto_sha512(&mut message_hash, b"abc");
        crypto_ed25519_ph_sign(&mut signature, &secret_key, &message_hash);

        assert_eq!(signature, expected, "incorrect signature");
        assert!(crypto_ed25519_ph_check(&signature, &public_key, &message_hash).is_ok());
    }

    #[test]
    fn key_pair_wipes_seed() {
        let original = [5u8; 32];
        let mut seed = original;
        let mut secret_key = [0u8; 64];
        let mut public_key = [0u8; 32];

        crypto_ed25519_key_pair(&mut secret_key, &mut public_key, &mut seed);

        assert_eq!(seed, [0u8; 32], "seed was not wiped");
        assert_eq!(secret_key[..32], original);
        assert_eq!(secret_key[32..], public_key);
    }

    #[test]
    fn rejects_tampering() {
        let (secret_key, public_key) = key_pair([5u8; 32]);
        let (_, other_public_key) = key_pair([6u8; 32]);
        let mut signature = [0u8; 64];

        crypto_ed25519_sign(&mut signature, &secret_key, b"Lorem ipsum");

        let result = crypto_ed25519_check(&signature, &public_key, b"Lorem ipsuM");
        assert!(matches!(result, Err(ErrorKind::InvalidSignature)));
        assert!(crypto_ed25519_check(&signature, &other_public_key, b"Lorem ipsum").is_err());

        for i in [0, 31, 32, 63] {
            let mut bad_signature = signature;
            bad_signature[i] ^= 1;
            assert!(crypto_ed25519_check(&bad_signature, &public_key, b"Lorem ipsum").is_err(), "byte {i}");
        }
    }

    #[test]
    fn ph_rejects_tampering() {
        let (secret_key, public_key) = key_pair([5u8; 32]);
        let message_hash = [9u8; 64];
        let mut wrong_hash = message_hash;
        wrong_hash[0] ^= 1;
        let mut signature = [0u8; 64];

        crypto_ed25519_ph_sign(&mut signature, &secret_key, &message_hash);

        assert!(crypto_ed25519_ph_check(&signature, &public_key, &message_hash).is_ok());
        let result = crypto_ed25519_ph_check(&signature, &public_key, &wrong_hash);
        assert!(matches!(result, Err(ErrorKind::InvalidSignature)));
    }
}
