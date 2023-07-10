use std::io::{Error, ErrorKind};
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;

use tracing::instrument;
use tracing::{error, info};

use rand_core::{OsRng, RngCore};

use zeroize::{Zeroize, ZeroizeOnDrop};

use mini_monocypher::{
    crypto_aead_lock, crypto_aead_unlock, crypto_blake2b, crypto_blake2b_keyed, crypto_x25519,
    crypto_x25519_public_key,
};

use crate::utils::increment_nonce;

const ENCRYPTED_HANDSHAKE_BYTES: usize = 32 /* key */ + 16 /* tag */;

const CIPHERTEXT_FRAME_BYTES: usize = 1060;
const PLAINTEXT_FRAME_BYTES: usize = CIPHERTEXT_FRAME_BYTES - 16 /* tag */;
const PLAINTEXT_FRAME_LEN_BYTES: usize = 4;

struct Key {
    key: [u8; 32],
    nonce: [u8; 24],
}

impl Key {
    fn increment_nonce(&mut self) {
        increment_nonce(&mut self.nonce, 1);
    }
}

impl Zeroize for Key {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl ZeroizeOnDrop for Key {}

#[instrument(skip(client_stream, target, is_client, client_key, server_key))]
pub async fn proxy_connection(
    client_addr: SocketAddr,
    mut client_stream: TcpStream,
    target: &str,
    is_client: bool,
    client_key: &[u8; 32],
    server_key: &[u8; 32],
) {
    // client/server:
    //   - connect to backend
    //   - initiate/complete handshake with backend/client
    //   - proxy data

    let mut backend_stream = match TcpStream::connect(target).await {
        Ok(backend_stream) => {
            info!("Connected to backend: {}", target);
            backend_stream
        }
        Err(e) => {
            error!("Failed to connect to backend (aborting): {}", e);
            return;
        }
    };

    let mut write_key = Key {
        key: [0u8; 32],
        nonce: [0u8; 24],
    };

    let mut read_key = Key {
        key: [0u8; 32],
        nonce: [0u8; 24],
    };

    write_key.key[..].clone_from_slice(server_key);
    read_key.key[..].clone_from_slice(client_key);

    if is_client {
        write_key.key[..].clone_from_slice(client_key);
        read_key.key[..].clone_from_slice(server_key);
    }

    let derive_x25519_keypair = || {
        let mut pk = [0u8; 32];
        let mut sk = [0u8; 32];
        OsRng.fill_bytes(&mut sk);
        crypto_x25519_public_key(&mut pk, &sk);
        (pk, sk)
    };

    let (pk, mut sk) = derive_x25519_keypair();

    let mut encrypted_pk = [0u8; ENCRYPTED_HANDSHAKE_BYTES];

    let (encrypted_pk_detached, mac) = encrypted_pk.split_at_mut(ENCRYPTED_HANDSHAKE_BYTES - 16);

    crypto_aead_lock(
        encrypted_pk_detached,
        mac,
        &write_key.key,
        &write_key.nonce,
        None,
        &pk,
    );

    let mut handshake_stream = &mut client_stream;

    if is_client {
        handshake_stream = &mut backend_stream;
    }

    if let Err(e) = handshake_stream.write_all(&encrypted_pk[..]).await {
        error!("Failed to send encrypted public key: {}", e);
        return;
    }

    if let Err(e) = handshake_stream.read_exact(&mut encrypted_pk).await {
        error!("Error receiving encrypted public key: {}", e);
        return;
    }

    let mut received_pk = [0u8; 32];

    if let Err(e) = crypto_aead_unlock(
        &mut received_pk,
        &encrypted_pk[(ENCRYPTED_HANDSHAKE_BYTES - 16)..],
        &read_key.key,
        &read_key.nonce,
        None,
        &encrypted_pk[..(ENCRYPTED_HANDSHAKE_BYTES - 16)],
    ) {
        error!("Failed to decrypt encrypted public key: {}", e);
        received_pk.zeroize();
        return;
    }

    let mut shared = [0u8; 32];
    crypto_x25519(&mut shared, &sk, &received_pk);
    sk.zeroize();

    let mut shared_hash = [0u8; 32];
    crypto_blake2b(&mut shared_hash, &shared);

    if is_client {
        crypto_blake2b_keyed(&mut read_key.key, &shared_hash, b"server");
        crypto_blake2b_keyed(&mut write_key.key, &shared_hash, b"client");
    } else {
        crypto_blake2b_keyed(&mut read_key.key, &shared_hash, b"client");
        crypto_blake2b_keyed(&mut write_key.key, &shared_hash, b"server");
    }

    shared_hash.zeroize();

    let (mut backend_read, mut backend_write) = backend_stream.split();
    let (mut client_read, mut client_write) = client_stream.split();

    let (encrypt, decrypt) = match is_client {
        false => {
            let encrypt = shovel_encrypted(&mut backend_read, &mut client_write, &mut write_key);
            let decrypt = shovel_decrypted(&mut client_read, &mut backend_write, &mut read_key);
            (encrypt, decrypt)
        }
        true => {
            let encrypt = shovel_encrypted(&mut client_read, &mut backend_write, &mut write_key);
            let decrypt = shovel_decrypted(&mut backend_read, &mut client_write, &mut read_key);
            (encrypt, decrypt)
        }
    };

    if let Err(e) = tokio::try_join!(encrypt, decrypt) {
        error!("Error with shovelling data: {}", e);
    }
}

async fn shovel_decrypted<'a>(
    source: &mut ReadHalf<'a>,
    sink: &mut WriteHalf<'a>,
    key: &mut Key,
) -> Result<(), std::io::Error> {
    let mut buffer = [0u8; CIPHERTEXT_FRAME_BYTES];

    loop {
        match source.read_exact(&mut buffer[..]).await {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                sink.shutdown().await?;
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        let mut plaintext = [0u8; PLAINTEXT_FRAME_BYTES];

        if let Err(e) = crypto_aead_unlock(
            &mut plaintext,
            &buffer[PLAINTEXT_FRAME_BYTES..],
            &key.key,
            &key.nonce,
            None,
            &buffer[..PLAINTEXT_FRAME_BYTES],
        ) {
            plaintext.zeroize();
            sink.shutdown().await?;
            return Err(Error::new(ErrorKind::InvalidData, e));
        }

        key.increment_nonce();

        let len = u32::from_le_bytes(
            plaintext[(PLAINTEXT_FRAME_BYTES - PLAINTEXT_FRAME_LEN_BYTES)..PLAINTEXT_FRAME_BYTES]
                .try_into()
                .unwrap(),
        );

        sink.write_all(&plaintext[..len as usize]).await?;

        plaintext.zeroize();
    }
}

async fn shovel_encrypted<'a>(
    source: &mut ReadHalf<'a>,
    sink: &mut WriteHalf<'a>,
    key: &mut Key,
) -> Result<(), std::io::Error> {
    let mut buffer = [0u8; PLAINTEXT_FRAME_BYTES];

    loop {
        let n = source
            .read(&mut buffer[..(PLAINTEXT_FRAME_BYTES - PLAINTEXT_FRAME_LEN_BYTES)])
            .await?;

        // when read() returns 0 it means EOF / closed connection
        if n == 0 {
            sink.shutdown().await?;
            return Ok(());
        }

        let len: u32 = n.try_into().unwrap();
        buffer[(PLAINTEXT_FRAME_BYTES - PLAINTEXT_FRAME_LEN_BYTES)..PLAINTEXT_FRAME_BYTES]
            .copy_from_slice(&len.to_le_bytes());

        let mut ciphertext = [0u8; CIPHERTEXT_FRAME_BYTES];
        let (ciphertext_detached, mac) = ciphertext.split_at_mut(PLAINTEXT_FRAME_BYTES);

        crypto_aead_lock(
            ciphertext_detached,
            mac,
            &key.key,
            &key.nonce,
            None,
            &buffer[..PLAINTEXT_FRAME_BYTES],
        );

        key.increment_nonce();

        sink.write_all(&ciphertext).await?;

        // clean buffer for if we write again
        buffer.zeroize();
    }
}
