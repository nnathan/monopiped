use std::io::{Error as IOError, ErrorKind as IOErrorKind};
use std::net::SocketAddr;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::error::Error;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{accept_async, connect_async, MaybeTlsStream, WebSocketStream};

use tracing::instrument;
use tracing::{error, info};

use zeroize::Zeroize;

use mini_monocypher::{
    crypto_aead_lock, crypto_aead_unlock, crypto_blake2b, crypto_blake2b_keyed, crypto_x25519,
};

use crate::utils::{derive_x25519_keypair, Key};

const ENCRYPTED_HANDSHAKE_BYTES: usize = 32 /* key */ + 16 /* tag */;

const CIPHERTEXT_FRAME_BYTES: usize = 1060;
const PLAINTEXT_FRAME_BYTES: usize = CIPHERTEXT_FRAME_BYTES - 16 /* tag */;
const PLAINTEXT_FRAME_LEN_BYTES: usize = 4;

#[instrument(skip(stream, target, is_client, client_key, server_key))]
pub async fn proxy_ws_connection(
    peer_addr: SocketAddr,
    stream: TcpStream,
    target: &str,
    is_client: bool,
    client_key: &[u8; 32],
    server_key: &[u8; 32],
) {
    let ws_stream;
    let mut tcp_stream;

    if is_client {
        ws_stream = match connect_async(target).await {
            Ok((ws_stream, _)) => ws_stream,
            Err(e) => {
                error!("Failed to connect to backend (aborting): {}", e);
                return;
            }
        };

        tcp_stream = stream;
    } else {
        ws_stream = match accept_async(MaybeTlsStream::Plain(stream)).await {
            Ok(ws_stream) => ws_stream,
            Err(e) => {
                error!("Error during the websocket handshake occurred: {}", e);
                return;
            }
        };

        tcp_stream = match TcpStream::connect(target).await {
            Ok(tcp_stream) => {
                info!("Connected to backend: {}", target);
                tcp_stream
            }
            Err(e) => {
                error!("Failed to connect to backend (aborting): {}", e);
                return;
            }
        };
    }

    info!("WebSocket connection established");

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

    let (pk, mut sk) = derive_x25519_keypair();

    let mut encrypted_pk = vec![0u8; ENCRYPTED_HANDSHAKE_BYTES];

    let (encrypted_pk_detached, mac) = encrypted_pk.split_at_mut(ENCRYPTED_HANDSHAKE_BYTES - 16);

    crypto_aead_lock(
        encrypted_pk_detached,
        mac,
        &write_key.key,
        &write_key.nonce,
        None,
        &pk,
    );

    let (mut ws_write, mut ws_read) = ws_stream.split();

    if let Err(e) = ws_write.send(Message::binary(encrypted_pk)).await {
        error!("Failed to send encrypted public key: {}", e);
        return;
    }

    let mut received_pk = [0u8; 32];

    match ws_read.next().await {
        None => {
            error!("Error receiving encrypted public key: websocket stream closed");
            return;
        }
        Some(msg) => match msg {
            Ok(msg) => {
                if msg.is_close() {
                    error!("Error receiving encrypted public key: peer closed connection");
                    return;
                }

                if !msg.is_binary() {
                    error!("Error receiving encrypted public key: not a binary message");
                    return;
                }

                if msg.len() != ENCRYPTED_HANDSHAKE_BYTES {
                    error!("Error receiving encrypted public key: invalid message size");
                    return;
                }

                let msg = msg.into_data();

                if let Err(e) = crypto_aead_unlock(
                    &mut received_pk,
                    &msg[(ENCRYPTED_HANDSHAKE_BYTES - 16)..],
                    &read_key.key,
                    &read_key.nonce,
                    None,
                    &msg[..(ENCRYPTED_HANDSHAKE_BYTES - 16)],
                ) {
                    error!("Failed to decrypt encrypted public key: {}", e);
                    received_pk.zeroize();
                    return;
                }
            }
            Err(e) => {
                error!("Error receiving encrypted public key: {:?}", e);
                return;
            }
        },
    };

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

    let (mut tcp_read, mut tcp_write) = tcp_stream.split();

    let encrypt = shovel_encrypted(&mut tcp_read, &mut ws_write, &mut write_key);
    let decrypt = shovel_decrypted(&mut ws_read, &mut tcp_write, &mut read_key);

    if let Err(e) = tokio::try_join!(encrypt, decrypt) {
        error!("Error with shovelling data: {}", e);
    }
}

#[instrument(skip(source, sink, key))]
async fn shovel_encrypted<'a>(
    source: &mut ReadHalf<'a>,
    sink: &mut SplitSink<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>, Message>,
    key: &mut Key,
) -> Result<(), Error> {
    let mut buffer = [0u8; PLAINTEXT_FRAME_BYTES];

    loop {
        let n = source
            .read(&mut buffer[..(PLAINTEXT_FRAME_BYTES - PLAINTEXT_FRAME_LEN_BYTES)])
            .await?;

        // when read() returns 0 it means EOF / closed connection
        if n == 0 {
            sink.close().await?;
            return Ok(());
        }

        let len: u32 = n.try_into().unwrap();
        buffer[(PLAINTEXT_FRAME_BYTES - PLAINTEXT_FRAME_LEN_BYTES)..PLAINTEXT_FRAME_BYTES]
            .copy_from_slice(&len.to_le_bytes());

        let mut ciphertext = vec![0u8; CIPHERTEXT_FRAME_BYTES];
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

        sink.send(Message::binary(ciphertext)).await?;

        // clean buffer for if we write again
        buffer.zeroize();
    }
}

#[instrument(skip(source, sink, key))]
async fn shovel_decrypted<'a>(
    source: &mut SplitStream<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>>,
    sink: &mut WriteHalf<'a>,
    key: &mut Key,
) -> Result<(), Error> {
    loop {
        match source.next().await {
            None => {
                sink.shutdown().await?;
                return Ok(());
            }
            Some(msg) => match msg {
                Ok(msg) => {
                    if msg.is_close() {
                        return Ok(());
                    }

                    if !msg.is_binary() {
                        return Err(Error::Io(IOError::new(
                            IOErrorKind::InvalidInput,
                            "received text data when expecting binary",
                        )));
                    }

                    if msg.len() != CIPHERTEXT_FRAME_BYTES {
                        return Err(Error::Io(IOError::new(
                            IOErrorKind::InvalidInput,
                            format!("message length != {CIPHERTEXT_FRAME_BYTES}"),
                        )));
                    }

                    let msg = msg.into_data();

                    let mut plaintext = [0u8; PLAINTEXT_FRAME_BYTES];

                    if let Err(e) = crypto_aead_unlock(
                        &mut plaintext,
                        &msg[PLAINTEXT_FRAME_BYTES..],
                        &key.key,
                        &key.nonce,
                        None,
                        &msg[..PLAINTEXT_FRAME_BYTES],
                    ) {
                        plaintext.zeroize();
                        sink.shutdown().await?;
                        return Err(Error::Io(IOError::new(IOErrorKind::InvalidData, e)));
                    }

                    key.increment_nonce();

                    let len = u32::from_le_bytes(
                        plaintext[(PLAINTEXT_FRAME_BYTES - PLAINTEXT_FRAME_LEN_BYTES)
                            ..PLAINTEXT_FRAME_BYTES]
                            .try_into()
                            .unwrap(),
                    );

                    sink.write_all(&plaintext[..len as usize]).await?;

                    plaintext.zeroize();
                }
                Err(Error::ConnectionClosed) => {
                    sink.shutdown().await?;
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
            },
        }
    }
}
