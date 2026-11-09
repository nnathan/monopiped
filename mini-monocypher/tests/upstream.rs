//! A port of Monocypher's `tests/test.c` (version 4.0.3), in the same order.
//!
//! The vectors are vendored, see `tests/upstream/PROVENANCE.md`.
//!
//! The following tests from `test.c` are intentionally not ported, as safe Rust
//! cannot express overlapping input and output buffers (see the README's known
//! limitations):
//!
//!   - Chacha20 (output == input)
//!   - HChacha20 (overlap)
//!   - Poly1305 (overlapping i/o)
//!   - BLAKE2b (overlapping i/o)
//!   - SHA-512 (overlapping i/o)
//!   - HMAC SHA-512 (overlapping i/o)
//!   - Argon2 (overlapping i/o)
//!   - x25519 (overlapping i/o)
//!   - x25519 inverse (overlapping i/o)
//!   - EdDSA (overlap)
//!   - elligator direct (overlapping i/o)
//!   - elligator inverse (overlapping i/o)
//!   - elligator key pair (overlapping i/o)
//!
//! BLAKE2b vectors with a zero-length hash are also skipped, as the manual
//! requires a hash size between 1 and 64 and the binding enforces that.

use hex_literal::hex;
use mini_monocypher::hazmat::*;
use mini_monocypher::*;

const VECTORS: &str = include_str!("upstream/vectors.h");
const VECTORS_SHA512: [u8; 64] = hex!("c6b83b5c6cbdbe16e6dae4b056940b7c3a561ce5bef3196e9961f05974b6f2d00fc37f517857e913044503beed72952b48ec6e48ce7f41ef255a449ac40d142a");

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Returns the named vectors, grouped into `arity` values per test case.
fn vectors(name: &str, arity: usize, expected_cases: usize) -> Vec<Vec<Vec<u8>>> {
    let start = format!("static const char *{name}_vectors[]={{");
    let body = &VECTORS[VECTORS.find(&start).unwrap() + start.len()..];
    let body = &body[..body.find("};").unwrap()];
    let strings: Vec<Vec<u8>> = body
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('"'))
        .map(|line| hex_decode(&line[1..line.rfind('"').unwrap()]))
        .collect();

    assert_eq!(strings.len(), expected_cases * arity, "{name}");

    strings.chunks(arity).map(<[_]>::to_vec).collect()
}

fn array<const N: usize>(v: &[u8]) -> [u8; N] {
    v.try_into().unwrap()
}

fn le32(v: &[u8]) -> u32 {
    u32::from_le_bytes(array(&v[..4]))
}

fn le64(v: &[u8]) -> u64 {
    u64::from_le_bytes(array(&v[..8]))
}

/// The xorshift* generator from Monocypher's `tests/utils.c`. `test.c` shares
/// one generator between all of its tests, here each test has its own.
struct Rng(u64);

impl Rng {
    fn new() -> Rng {
        Rng(12345)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        std::array::from_fn(|_| self.next() as u8)
    }
}

fn bytes_of<T>(value: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>()) }
}

fn fill<T>(value: &mut T, byte: u8) {
    unsafe { std::ptr::write_bytes(value as *mut T as *mut u8, byte, std::mem::size_of::<T>()) }
}

#[test]
fn vendored_vectors_are_unmodified() {
    let mut hash = [0u8; 64];
    crypto_sha512(&mut hash, VECTORS.as_bytes());
    assert_eq!(hash, VECTORS_SHA512);
}

// Wipe

#[test]
fn wipe() {
    let mut rng = Rng::new();

    for i in 0..50 {
        let mut buf: [u8; 50] = rng.bytes();
        crypto_wipe(&mut buf[..i]);
        assert_eq!(buf[..i], vec![0u8; i]);
    }
}

// Constant time comparison

macro_rules! verify {
    ($name:ident, $func:ident, $size:expr) => {
        #[test]
        fn $name() {
            for i in 0..2u8 {
                for j in 0..2u8 {
                    let (a, b) = ([i; $size], [j; $size]);
                    assert_eq!($func(&a, &b).is_ok(), i == j);

                    for k in 0..$size / 2 {
                        let (mut a, mut b) = ([0u8; $size], [0u8; $size]);
                        a[k] = i;
                        a[k + $size / 2 - 1] = i;
                        b[k] = j;
                        b[k + $size / 2 - 1] = j;
                        assert_eq!($func(&a, &b).is_ok(), i == j);
                    }
                }
            }
        }
    };
}

verify!(verify16, crypto_verify16, 16);
verify!(verify32, crypto_verify32, 32);
verify!(verify64, crypto_verify64, 64);

// Chacha20

macro_rules! chacha_vectors {
    ($name:ident, $vectors:literal, $count:expr, $func:ident, $nonce:expr, $ctr:ty, $load:ident) => {
        #[test]
        fn $name() {
            for t in vectors($vectors, 5, $count) {
                let (key, nonce, plain, out) = (array(&t[0]), array::<$nonce>(&t[1]), &t[2], &t[4]);
                let ctr = $load(&t[3]) as $ctr;
                let nb_blocks = (plain.len() / 64 + (plain.len() % 64 != 0) as usize) as $ctr;
                let mut output = vec![0u8; plain.len()];

                let new_ctr = $func(&mut output, Some(plain), &key, &nonce, ctr);

                assert_eq!(&output, out);
                assert_eq!(new_ctr.wrapping_sub(ctr), nb_blocks);
            }
        }
    };
}

macro_rules! chacha_ctr {
    ($name:ident, $func:ident, $nonce:expr) => {
        #[test]
        fn $name() {
            let mut rng = Rng::new();
            let key: [u8; 32] = rng.bytes();
            let nonce: [u8; $nonce] = rng.bytes();
            let plain: [u8; 128] = rng.bytes();
            let (mut full, mut out1, mut out2) = ([0u8; 128], [0u8; 64], [0u8; 64]);

            $func(&mut full, Some(&plain), &key, &nonce, 0);
            $func(&mut out1, Some(&plain[..64]), &key, &nonce, 0);
            $func(&mut out2, Some(&plain[64..]), &key, &nonce, 1);

            assert_eq!(full[..64], out1);
            assert_eq!(full[64..], out2);
        }
    };
}

chacha_vectors!(chacha20_vectors, "chacha20", 136, crypto_chacha20_djb, 8, u64, le64);
chacha_ctr!(chacha20_ctr, crypto_chacha20_djb, 8);

#[test]
fn chacha20_null_is_zeroes() {
    const INPUT_SIZE: usize = 64 * 2 + 1;
    let mut rng = Rng::new();

    for i in 0..INPUT_SIZE {
        let key: [u8; 32] = rng.bytes();
        let nonce: [u8; 8] = rng.bytes();
        let zeroes = [0u8; INPUT_SIZE];
        let (mut normal, mut stream) = ([0u8; INPUT_SIZE], [0u8; INPUT_SIZE]);

        crypto_chacha20_djb(&mut normal[..i], Some(&zeroes[..i]), &key, &nonce, 0);
        crypto_chacha20_djb(&mut stream[..i], None, &key, &nonce, 0);

        assert_eq!(normal[..i], stream[..i]);
    }
}

chacha_vectors!(ietf_chacha20_vectors, "ietf_chacha20", 128, crypto_chacha20_ietf, 12, u32, le32);
chacha_ctr!(ietf_chacha20_ctr, crypto_chacha20_ietf, 12);
chacha_vectors!(xchacha20_vectors, "xchacha20", 131, crypto_chacha20_x, 24, u64, le64);
chacha_ctr!(xchacha20_ctr, crypto_chacha20_x, 24);

#[test]
fn hchacha20_vectors() {
    for t in vectors("hchacha20", 3, 50) {
        let mut out = [0u8; 32];
        crypto_chacha20_h(&mut out, &array(&t[0]), &array(&t[1]));
        assert_eq!(out[..], t[2]);
    }
}

// Poly1305

#[test]
fn poly1305_vectors() {
    for t in vectors("poly1305", 3, 48) {
        let mut mac = [0u8; 16];
        crypto_poly1305(&mut mac, &t[1], &array(&t[0]));
        assert_eq!(mac[..], t[2]);
    }
}

#[test]
fn poly1305_incremental() {
    const INPUT_SIZE: usize = 16 * 4;
    let mut rng = Rng::new();

    for i in 0..INPUT_SIZE {
        let input: [u8; INPUT_SIZE] = rng.bytes();
        let key: [u8; 32] = rng.bytes();
        let (mut chunk, mut whole) = ([0u8; 16], [0u8; 16]);
        let mut ctx = crypto_poly1305_ctx_new();

        crypto_poly1305_init(&mut ctx, &key);
        crypto_poly1305_update(&mut ctx, &input[..i]);
        crypto_poly1305_update(&mut ctx, &input[i..]);
        crypto_poly1305_final(&mut ctx, &mut chunk);
        crypto_poly1305(&mut whole, &input, &key);

        assert_eq!(chunk, whole);
    }
}

// Authenticated encryption

#[test]
fn aead_ietf_vectors() {
    for t in vectors("aead_ietf", 5, 320) {
        let (mac, cipher_text) = t[4].split_at(16);
        let mut output = vec![0u8; t[3].len()];
        let mut output_mac = [0u8; 16];

        crypto_aead_lock(&mut output, &mut output_mac, &array(&t[0]), &array(&t[1]), Some(&t[2]), &t[3]);

        assert_eq!(output, cipher_text);
        assert_eq!(output_mac, mac);
    }
}

#[test]
fn aead_8439_vectors() {
    for t in vectors("aead_8439", 5, 320) {
        let (mac, cipher_text) = t[4].split_at(16);
        let mut output = vec![0u8; t[3].len()];
        let mut output_mac = [0u8; 16];
        let mut ctx = crypto_aead_ctx_new();

        crypto_aead_init_ietf(&mut ctx, &array(&t[0]), &array(&t[1]));
        crypto_aead_write(&mut ctx, &mut output, &mut output_mac, Some(&t[2]), &t[3]);

        assert_eq!(output, cipher_text);
        assert_eq!(output_mac, mac);
    }
}

#[test]
fn aead_roundtrip() {
    let mut rng = Rng::new();

    for _ in 0..1000 {
        let key: [u8; 32] = rng.bytes();
        let nonce: [u8; 24] = rng.bytes();
        let ad: [u8; 4] = rng.bytes();
        let plain_text: [u8; 8] = rng.bytes();
        let (mut cipher_text, mut mac, mut out) = ([0u8; 8], [0u8; 16], [0u8; 8]);

        crypto_aead_lock(&mut cipher_text, &mut mac, &key, &nonce, Some(&ad), &plain_text);
        crypto_aead_unlock(&mut out, &mac, &key, &nonce, Some(&ad), &cipher_text).unwrap();
        assert_eq!(plain_text, out);

        mac[0] = mac[0].wrapping_add(1);
        assert!(crypto_aead_unlock(&mut out, &mac, &key, &nonce, Some(&ad), &cipher_text).is_err());
    }
}

#[test]
fn aead_incremental_roundtrip() {
    let mut rng = Rng::new();

    fn step(a: &mut crypto_aead_ctx, b: &mut crypto_aead_ctx, ad: &[u8; 4], pt: &[u8; 8]) {
        let (mut mac, mut ct, mut pt2) = ([0u8; 16], [0u8; 8], [0u8; 8]);
        crypto_aead_write(a, &mut ct, &mut mac, Some(ad), pt);
        crypto_aead_read(b, &mut pt2, &mac, Some(ad), &ct).unwrap();
        assert_eq!(pt, &pt2);
    }

    for _ in 0..50 {
        let key: [u8; 32] = rng.bytes();
        let nonce: [u8; 24] = rng.bytes();
        let (mut xa, mut xb) = (crypto_aead_ctx_new(), crypto_aead_ctx_new());
        let (mut da, mut db) = (crypto_aead_ctx_new(), crypto_aead_ctx_new());
        let (mut ia, mut ib) = (crypto_aead_ctx_new(), crypto_aead_ctx_new());

        crypto_aead_init_x(&mut xa, &key, &nonce);
        crypto_aead_init_x(&mut xb, &key, &nonce);
        crypto_aead_init_djb(&mut da, &key, &array(&nonce[..8]));
        crypto_aead_init_djb(&mut db, &key, &array(&nonce[..8]));
        crypto_aead_init_ietf(&mut ia, &key, &array(&nonce[..12]));
        crypto_aead_init_ietf(&mut ib, &key, &array(&nonce[..12]));

        for _ in 0..10 {
            let ad: [u8; 4] = rng.bytes();
            let pt: [u8; 8] = rng.bytes();

            step(&mut xa, &mut xb, &ad, &pt);
            assert_eq!(bytes_of(&xa), bytes_of(&xb));
            step(&mut da, &mut db, &ad, &pt);
            step(&mut ia, &mut ib, &ad, &pt);
        }
    }
}

// BLAKE2b

#[test]
fn blake2b_vectors() {
    let mut skipped = 0;

    for t in vectors("blake2b", 3, 681) {
        let (msg, key, out) = (&t[0], &t[1], &t[2]);

        if out.is_empty() {
            skipped += 1;
            continue;
        }

        let mut hash = vec![0u8; out.len()];
        crypto_blake2b_keyed(&mut hash, key, msg);
        assert_eq!(&hash, out);
    }

    assert_eq!(skipped, 85);
}

#[test]
fn blake2b_zero_input() {
    let mut rng = Rng::new();
    let key: [u8; 32] = rng.bytes();
    let (mut chunk, mut whole) = ([0u8; 64], [0u8; 64]);
    let mut ctx = crypto_blake2b_ctx_new();

    fill(&mut ctx, 0x5c);
    crypto_blake2b_keyed_init(&mut ctx, 64, &key);
    crypto_blake2b_final(&mut ctx, &mut chunk);
    crypto_blake2b_keyed(&mut whole, &key, &[]);
    assert_eq!(chunk, whole);

    fill(&mut ctx, 0x5c);
    crypto_blake2b_init(&mut ctx, 64);
    crypto_blake2b_final(&mut ctx, &mut chunk);
    crypto_blake2b(&mut whole, &[]);
    assert_eq!(chunk, whole);
}

#[test]
fn blake2b_incremental() {
    const INPUT_SIZE: usize = 128 * 3;
    let input: [u8; INPUT_SIZE] = Rng::new().bytes();
    let mut whole = [0u8; 64];
    crypto_blake2b(&mut whole, &input);

    for j in 0..INPUT_SIZE {
        for i in 0..j + 1 {
            let mut chunk = [0u8; 64];
            let mut ctx = crypto_blake2b_ctx_new();

            crypto_blake2b_init(&mut ctx, 64);
            crypto_blake2b_update(&mut ctx, &input[..i]);
            crypto_blake2b_update(&mut ctx, &input[i..j]);
            crypto_blake2b_update(&mut ctx, &input[j..]);
            crypto_blake2b_final(&mut ctx, &mut chunk);

            assert_eq!(chunk, whole);
        }
    }
}

// SHA-512

#[test]
fn sha512_vectors() {
    for t in vectors("sha512", 2, 256) {
        let mut hash = [0u8; 64];
        crypto_sha512(&mut hash, &t[0]);
        assert_eq!(hash[..], t[1]);
    }
}

#[test]
fn sha512_hmac_vectors() {
    for t in vectors("sha512_hmac", 3, 343) {
        let mut hmac = [0u8; 64];
        crypto_sha512_hmac(&mut hmac, &t[0], &t[1]);
        assert_eq!(hmac[..], t[2]);
    }
}

#[test]
fn sha512_hkdf_vectors() {
    for t in vectors("sha512_hkdf", 4, 20) {
        let mut okm = vec![0u8; t[3].len()];
        crypto_sha512_hkdf(&mut okm, &t[0], Some(&t[1]), Some(&t[2]));
        assert_eq!(okm, t[3]);
    }
}

#[test]
fn sha512_incremental() {
    const INPUT_SIZE: usize = 128 * 4 - 32;
    let input: [u8; INPUT_SIZE] = Rng::new().bytes();
    let mut whole = [0u8; 64];
    crypto_sha512(&mut whole, &input);

    for j in 0..INPUT_SIZE {
        for i in 0..j + 1 {
            let mut chunk = [0u8; 64];
            let mut ctx = crypto_sha512_ctx_new();

            crypto_sha512_init(&mut ctx);
            crypto_sha512_update(&mut ctx, &input[..i]);
            crypto_sha512_update(&mut ctx, &input[i..j]);
            crypto_sha512_update(&mut ctx, &input[j..]);
            crypto_sha512_final(&mut ctx, &mut chunk);

            assert_eq!(chunk, whole);
        }
    }
}

#[test]
fn sha512_hmac_incremental() {
    const INPUT_SIZE: usize = 128 * 4 - 32;
    let mut rng = Rng::new();

    for i in 0..INPUT_SIZE {
        let key: [u8; 32] = rng.bytes();
        let input: [u8; INPUT_SIZE] = rng.bytes();
        let (mut chunk, mut whole) = ([0u8; 64], [0u8; 64]);
        let mut ctx = crypto_sha512_hmac_ctx_new();

        crypto_sha512_hmac_init(&mut ctx, &key);
        crypto_sha512_hmac_update(&mut ctx, &input[..i]);
        crypto_sha512_hmac_update(&mut ctx, &input[i..]);
        crypto_sha512_hmac_final(&mut ctx, &mut chunk);
        crypto_sha512_hmac(&mut whole, &key, &input);

        assert_eq!(chunk, whole);
    }
}

// Argon2

#[test]
fn argon2_vectors() {
    for t in vectors("argon2", 9, 28) {
        let config = crypto_argon2_config {
            algorithm: match le32(&t[0]) {
                0 => CRYPTO_ARGON2_D,
                1 => CRYPTO_ARGON2_I,
                2 => CRYPTO_ARGON2_ID,
                other => panic!("unknown algorithm {other}"),
            },
            nb_blocks: le32(&t[1]),
            nb_passes: le32(&t[2]),
            nb_lanes: le32(&t[3]),
        };
        let inputs = crypto_argon2_inputs {
            pass: &t[4],
            salt: &t[5],
        };
        let extras = crypto_argon2_extras {
            key: Some(&t[6]),
            ad: Some(&t[7]),
        };
        let mut hash = vec![0u8; t[8].len()];
        let mut work_area = vec![0u64; config.nb_blocks as usize * 128];

        crypto_argon2(&mut hash, &mut work_area, config, inputs, extras);

        assert_eq!(hash, t[8]);
    }
}

// X25519

#[test]
fn x25519_vectors() {
    for t in vectors("x25519", 3, 623) {
        let mut out = [0u8; 32];
        crypto_x25519(&mut out, &array(&t[0]), &array(&t[1]));
        assert_eq!(out[..], t[2]);
    }
}

#[test]
fn x25519_pk_vectors() {
    for t in vectors("x25519_pk", 2, 51) {
        let mut out = [0u8; 32];
        crypto_x25519_public_key(&mut out, &array(&t[0]));
        assert_eq!(out[..], t[1]);
    }
}

#[test]
fn x25519_1_and_1k() {
    let mut u = [0u8; 32];
    u[0] = 9;
    let mut k = [0u8; 32];

    crypto_x25519_public_key(&mut k, &u);
    assert_eq!(k, hex!("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"));

    for _ in 1..1000 {
        let mut tmp = [0u8; 32];
        crypto_x25519(&mut tmp, &k, &u);
        u = k;
        k = tmp;
    }
    assert_eq!(k, hex!("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"));
}

#[test]
fn x25519_inverse() {
    let mut rng = Rng::new();
    let b: [u8; 32] = rng.bytes();
    let mut base = [0u8; 32];
    crypto_x25519_public_key(&mut base, &b);

    for _ in 0..50 {
        let sk: [u8; 32] = rng.bytes();
        let (mut pk, mut blind) = ([0u8; 32], [0u8; 32]);

        crypto_x25519(&mut pk, &sk, &base);
        crypto_x25519_inverse(&mut blind, &sk, &pk);

        assert_eq!(blind, base);
    }

    let mut one = [0u8; 32];
    one[0] = 1;
    let low_order = [
        [0u8; 32],
        one,
        hex!("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        hex!("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    ];

    for i in 0..32 {
        let sk: [u8; 32] = rng.bytes();
        let mut blind = [0u8; 32];

        crypto_x25519_inverse(&mut blind, &sk, &low_order[i % 4]);

        assert_eq!(blind, [0u8; 32]);
    }
}

// EdDSA utils

fn add_xl(input: &[u8; 32], factor: u32) -> [u8; 32] {
    const L: [u8; 32] = hex!("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    let mut out = [0u8; 32];
    let mut acc = 0u32;

    assert!(factor <= 8);
    for i in 0..32 {
        acc += input[i] as u32 + L[i] as u32 * factor;
        out[i] = acc as u8;
        acc >>= 8;
    }
    assert_eq!(acc, 0);

    out
}

#[test]
fn eddsa_scalarbase() {
    let mut rng = Rng::new();

    for _ in 0..50 {
        let mut scalar: [u8; 32] = rng.bytes();
        scalar[31] &= 0xf;
        let scalar_plus = add_xl(&scalar, 8);
        assert_ne!(scalar, scalar_plus);

        let (mut point, mut point_plus) = ([0u8; 32], [0u8; 32]);
        crypto_eddsa_scalarbase(&mut point, &scalar);
        crypto_eddsa_scalarbase(&mut point_plus, &scalar_plus);

        assert_eq!(point, point_plus);
    }
}

// EdDSA

fn fat_secret_key(secret: &[u8], public: &[u8]) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(secret);
    key[32..].copy_from_slice(public);
    key
}

macro_rules! sign_vectors {
    ($name:ident, $vectors:literal, $sign:ident) => {
        #[test]
        fn $name() {
            for t in vectors($vectors, 4, 256) {
                let mut signature = [0u8; 64];
                $sign(&mut signature, &fat_secret_key(&t[0], &t[1]), &t[2]);
                assert_eq!(signature[..], t[3]);
            }
        }
    };
}

macro_rules! key_pair_vectors {
    ($name:ident, $vectors:literal, $key_pair:ident) => {
        #[test]
        fn $name() {
            for t in vectors($vectors, 2, 257) {
                let mut seed: [u8; 32] = array(&t[0]);
                let (mut secret_key, mut public_key) = ([0u8; 64], [0u8; 32]);

                $key_pair(&mut secret_key, &mut public_key, &mut seed);

                assert_eq!(public_key[..], t[1]);
                assert_eq!(seed, [0u8; 32]);
                assert_eq!(secret_key[..32], t[0]);
                assert_eq!(secret_key[32..], public_key);
            }
        }
    };
}

sign_vectors!(eddsa_vectors, "edDSA", crypto_eddsa_sign);
key_pair_vectors!(eddsa_pk_vectors, "edDSA_pk", crypto_eddsa_key_pair);

#[test]
fn eddsa_roundtrip() {
    const MESSAGE_SIZE: usize = 30;
    let mut rng = Rng::new();

    for i in 0..MESSAGE_SIZE {
        let message: [u8; MESSAGE_SIZE] = rng.bytes();
        let mut seed: [u8; 32] = rng.bytes();
        let (mut sk, mut pk, mut signature) = ([0u8; 64], [0u8; 32], [0u8; 64]);

        crypto_eddsa_key_pair(&mut sk, &mut pk, &mut seed);
        crypto_eddsa_sign(&mut signature, &sk, &message[..i]);
        crypto_eddsa_check(&signature, &pk, &message[..i]).unwrap();

        assert!(crypto_eddsa_check(&[0u8; 64], &pk, &message[..i]).is_err());
        for j in 0..64 {
            let mut forgery = signature;
            forgery[j] = signature[j].wrapping_add(1);
            assert!(crypto_eddsa_check(&forgery, &pk, &message[..i]).is_err());
        }
    }
}

#[test]
fn eddsa_random() {
    const MESSAGE_SIZE: usize = 30;
    let mut rng = Rng::new();

    for _ in 0..100 {
        let message: [u8; MESSAGE_SIZE] = rng.bytes();
        let pk: [u8; 32] = rng.bytes();
        let signature: [u8; 64] = rng.bytes();

        assert!(crypto_eddsa_check(&signature, &pk, &message).is_err());
    }

    // S == L
    let message: [u8; MESSAGE_SIZE] = rng.bytes();
    let pk: [u8; 32] = rng.bytes();
    let mut signature = [0u8; 64];
    signature[32..].copy_from_slice(&hex!(
        "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
    ));

    assert!(crypto_eddsa_check(&signature, &pk, &message).is_err());
}

// Ed25519

sign_vectors!(ed25519_vectors, "ed_25519", crypto_ed25519_sign);
key_pair_vectors!(ed25519_pk_vectors, "ed_25519_pk", crypto_ed25519_key_pair);

#[test]
fn ed25519_check_vectors() {
    for t in vectors("ed_25519_check", 4, 330) {
        let result = crypto_ed25519_check(&array(&t[2]), &array(&t[0]), &t[1]);
        assert_eq!(result.is_ok(), t[3][0] == 0);
    }
}

#[test]
fn ed25519ph_vectors() {
    for t in vectors("ed_25519ph", 4, 2) {
        let mut seed: [u8; 32] = array(&t[0]);
        let (mut secret_key, mut public_key) = ([0u8; 64], [0u8; 32]);
        let (mut digest, mut signature) = ([0u8; 64], [0u8; 64]);

        crypto_ed25519_key_pair(&mut secret_key, &mut public_key, &mut seed);
        assert_eq!(public_key[..], t[1]);
        assert_eq!(public_key[..], secret_key[32..]);

        crypto_sha512(&mut digest, &t[2]);
        crypto_ed25519_ph_sign(&mut signature, &secret_key, &digest);
        assert_eq!(signature[..], t[3]);

        crypto_ed25519_ph_check(&signature, &public_key, &digest).unwrap();
        for i in 0..64 {
            let mut corrupt = signature;
            corrupt[i] ^= 1;
            assert!(crypto_ed25519_ph_check(&corrupt, &public_key, &digest).is_err());
        }
    }
}

// Elligator

#[test]
fn elligator_dir_vectors() {
    for t in vectors("elligator_dir", 2, 92) {
        let mut curve = [0u8; 32];
        crypto_elligator_map(&mut curve, &array(&t[0]));
        assert_eq!(curve[..], t[1]);
    }
}

#[test]
fn elligator_direct_msb() {
    let mut rng = Rng::new();

    for _ in 0..20 {
        let r: [u8; 32] = rng.bytes();
        let mut u = [0u8; 32];
        crypto_elligator_map(&mut u, &r);

        for msb in [0x00, 0x40, 0x80, 0xc0] {
            let mut other = r;
            other[31] = (r[31] & 0x3f) | msb;
            let mut other_u = [0u8; 32];

            crypto_elligator_map(&mut other_u, &other);

            assert_eq!(u, other_u);
        }
    }
}

#[test]
fn elligator_inv_vectors() {
    for t in vectors("elligator_inv", 4, 77) {
        let mut hidden = [0u8; 32];
        let result = crypto_elligator_rev(&mut hidden, &array(&t[0]), t[1][0]);

        assert_eq!(result.is_ok(), t[2][0] == 0);
        if result.is_ok() {
            assert_eq!(hidden[..], t[3]);
        }
    }
}

#[test]
fn elligator_x25519() {
    let mut rng = Rng::new();
    let mut i: u32 = 0;

    while i < 64 {
        let sk1: [u8; 32] = rng.bytes();
        let sk2: [u8; 32] = rng.bytes();
        let mut skc = sk1;
        skc[0] &= 248;
        let (mut pks, mut pksc, mut pkf, mut pkfc, mut pk1) =
            ([0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]);

        crypto_x25519_dirty_small(&mut pks, &sk1);
        crypto_x25519_dirty_small(&mut pksc, &skc);
        crypto_x25519_dirty_fast(&mut pkf, &sk1);
        crypto_x25519_dirty_fast(&mut pkfc, &skc);
        crypto_x25519_public_key(&mut pk1, &sk1);

        assert_eq!(pks, pkf);
        assert_eq!(pksc, pk1);
        assert_eq!(pkfc, pk1);
        if sk1[0] & 7 == 0 {
            assert_eq!(pk1, pkf);
        } else {
            assert_ne!(pk1, pkf);
        }

        let tweak = ((i & 1) + (i << 5)) as u8;
        let mut r = [0u8; 32];
        if crypto_elligator_rev(&mut r, &pkf, tweak).is_err() {
            continue;
        }
        assert_eq!(tweak >> 6, r[31] >> 6);

        let mut pkr = [0u8; 32];
        crypto_elligator_map(&mut pkr, &r);
        assert_eq!(pkr, pkf);

        let (mut e1, mut e2) = ([0u8; 32], [0u8; 32]);
        crypto_x25519(&mut e1, &sk2, &pk1);
        crypto_x25519(&mut e2, &sk2, &pkr);
        assert_eq!(e1, e2);

        i += 1;
    }
}

#[test]
fn elligator_key_pair() {
    let mut rng = Rng::new();

    for _ in 0..32 {
        let mut seed: [u8; 32] = rng.bytes();
        let sk2: [u8; 32] = rng.bytes();
        let (mut r, mut sk1, mut pkr, mut pk1) = ([0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]);
        let (mut e1, mut e2) = ([0u8; 32], [0u8; 32]);

        crypto_elligator_key_pair(&mut r, &mut sk1, &mut seed);
        crypto_elligator_map(&mut pkr, &r);
        crypto_x25519_public_key(&mut pk1, &sk1);
        crypto_x25519(&mut e1, &sk2, &pk1);
        crypto_x25519(&mut e2, &sk2, &pkr);

        assert_eq!(e1, e2);
    }
}

// X25519 <-> EdDSA

#[test]
fn x25519_eddsa_conversions() {
    let mut rng = Rng::new();

    for _ in 0..32 {
        let mut seed: [u8; 32] = rng.bytes();
        let (mut secret, mut e_public1) = ([0u8; 64], [0u8; 32]);
        crypto_eddsa_key_pair(&mut secret, &mut e_public1, &mut seed);

        let mut x_private = [0u8; 64];
        crypto_blake2b(&mut x_private, &secret[..32]);

        let (mut x_public1, mut x_public2, mut e_public2) = ([0u8; 32], [0u8; 32], [0u8; 32]);
        crypto_eddsa_to_x25519(&mut x_public1, &e_public1);
        crypto_x25519_public_key(&mut x_public2, &array(&x_private[..32]));
        assert_eq!(x_public1, x_public2);

        crypto_x25519_to_eddsa(&mut e_public2, &x_public1);
        assert_eq!(e_public2[31] & 0x80, 0);

        e_public1[31] &= 0x7f;
        assert_eq!(e_public1, e_public2);
    }
}
