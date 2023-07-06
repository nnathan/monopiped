use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;

use tracing::{debug, error, info};

use rand_core::{OsRng, RngCore};

use mini_monocypher::{
    crypto_aead_lock, crypto_aead_unlock, crypto_blake2b, crypto_blake2b_keyed, crypto_x25519,
    crypto_x25519_public_key,
};

use crate::utils::increment_nonce;

const ENCRYPTED_HANDSHAKE_BYTES: usize = 32 /* key */ + 16 /* tag */;

const CIPHERTEXT_FRAME_BYTES: usize = 1060;
const PLAINTEXT_FRAME_BYTES: usize = CIPHERTEXT_FRAME_BYTES - 16 /* tag */;
const PLAINTEXT_FRAME_LEN_BYTES: usize = 4;

struct ConnectionContext {
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    tx_nonce: [u8; 24],
    rx_nonce: [u8; 24],
    rx_buf: [u8; CIPHERTEXT_FRAME_BYTES],
    rx_buf_len: usize,
}

impl ConnectionContext {
    fn increment_tx_nonce(&mut self) {
        increment_nonce(&mut self.tx_nonce, 1);
    }

    fn increment_rx_nonce(&mut self) {
        increment_nonce(&mut self.rx_nonce, 1);
    }

    fn reset_rx_buf(&mut self) {
        self.rx_buf[..].fill(0);
        self.rx_buf_len = 0;
    }
}

pub fn proxy_connection(
    client_stream: TcpStream,
    target: &str,
    is_client: bool,
    client_key: &[u8; 32],
    server_key: &[u8; 32],
) {
    if let Err(e) = client_stream.set_nonblocking(true) {
        error!(
            "Error setting client connection to non-blocking (aborting): {:?}",
            e
        );
        return;
    }

    // client/server:
    //   - connect to backend
    //   - initiate/complete handshake with backend/client
    //   - proxy data

    let backend_stream = match TcpStream::connect(target) {
        Ok(backend_stream) => {
            info!("Connected to backend: {}", target);
            backend_stream
        }
        Err(e) => {
            error!("Failed to connect to backend (aborting): {}", e);
            return;
        }
    };

    if let Err(e) = backend_stream.set_nonblocking(true) {
        error!(
            "Error setting backend connection to non-blocking (aborting): {:?}",
            e
        );
        return;
    }

    let mut conn_ctx = ConnectionContext {
        tx_key: [0u8; 32],
        rx_key: [0u8; 32],
        rx_nonce: [0u8; 24],
        tx_nonce: [0u8; 24],
        rx_buf: [0u8; CIPHERTEXT_FRAME_BYTES],
        rx_buf_len: 0,
    };

    conn_ctx.tx_key[..].clone_from_slice(server_key);
    conn_ctx.rx_key[..].clone_from_slice(client_key);

    if is_client {
        conn_ctx.tx_key[..].clone_from_slice(client_key);
        conn_ctx.rx_key[..].clone_from_slice(server_key);
    }

    let derive_x25519_keypair = || {
        let mut pk = [0u8; 32];
        let mut sk = [0u8; 32];
        OsRng.fill_bytes(&mut sk);
        crypto_x25519_public_key(&mut pk, &sk);
        (pk, sk)
    };

    let (pk, sk) = derive_x25519_keypair();

    let nonce = [0u8; 24];

    let mut encrypted_pk = [0u8; ENCRYPTED_HANDSHAKE_BYTES];

    let (encrypted_pk_detached, mac) = encrypted_pk.split_at_mut(ENCRYPTED_HANDSHAKE_BYTES - 16);

    crypto_aead_lock(
        encrypted_pk_detached,
        mac,
        &conn_ctx.tx_key,
        &nonce,
        None,
        &pk,
    );

    let mut handshake_stream = &client_stream;

    if is_client {
        handshake_stream = &backend_stream;
    }

    if let Err(e) = handshake_stream.write_all(&encrypted_pk[..]) {
        error!("Failed to send encrypted public key: {}", e);
        return;
    }

    encrypted_pk = match receive_pubkey(handshake_stream) {
        Ok((pk, eof)) => {
            if eof {
                error!("Connection closed during handshake");
                return;
            }

            pk
        }
        Err(e) if e.kind() == ErrorKind::TimedOut => {
            error!("Poll timeout waiting for handshake to complete (aborting)");
            return;
        }
        Err(e) => {
            error!("Error receiving encrypted public key: {:?}", e);
            return;
        }
    };

    let mut received_pk = [0u8; 32];

    crypto_aead_unlock(
        &mut received_pk,
        &encrypted_pk[(ENCRYPTED_HANDSHAKE_BYTES - 16)..],
        &conn_ctx.rx_key,
        &nonce,
        None,
        &encrypted_pk[..(ENCRYPTED_HANDSHAKE_BYTES - 16)],
    );

    let mut shared = [0u8; 32];
    crypto_x25519(&mut shared, &sk, &received_pk);

    let mut shared_hash = [0u8; 32];
    crypto_blake2b(&mut shared_hash, &shared);

    if is_client {
        crypto_blake2b_keyed(&mut conn_ctx.rx_key, &shared_hash, b"server");
        crypto_blake2b_keyed(&mut conn_ctx.tx_key, &shared_hash, b"client");
    } else {
        crypto_blake2b_keyed(&mut conn_ctx.rx_key, &shared_hash, b"client");
        crypto_blake2b_keyed(&mut conn_ctx.tx_key, &shared_hash, b"server");
    }

    let mut sources = popol::Sources::with_capacity(2);
    let mut events = Vec::with_capacity(2);

    sources.register((), &client_stream, popol::interest::READ);
    sources.register((), &backend_stream, popol::interest::READ);

    loop {
        debug!("before poll");

        events.clear();

        if let Err(e) = sources.poll(&mut events, popol::Timeout::from_secs(1)) {
            if e.kind() == ErrorKind::TimedOut {
                debug!("poll timeout");
                continue;
            }

            error!("poll error: {:?}", e);
            break;
        }

        debug!("draining {} events", events.len());

        for event in events.drain(..) {
            debug!("received event {:?}", event);

            if event.is_invalid() {
                // fd was probably not opened first
                error!("received invalid event (aborting): {:?}", event);
                return;
            }

            if event.is_error() {
                error!("received error in event (aborting): {:?}", event);
                return;
            }

            if event.is_hangup() {
                error!("received hangup in event (aborting): {:?}", event);
                return;
            }

            if !event.is_readable() {
                debug!("received event but not readable: {:?}", event);
                continue;
            }

            let source: &TcpStream;
            let sink: &TcpStream;
            let source_is_backend: bool;

            if event.as_raw_fd() == backend_stream.as_raw_fd() {
                source = &backend_stream;
                sink = &client_stream;
                source_is_backend = true;
                debug!("source is backend, sink is client");
            } else {
                source = &client_stream;
                sink = &backend_stream;
                source_is_backend = false;
                debug!("source is client, sink is backend");
            }

            // backend -> client
            //   - client decrypts from backend and sends to client
            //   - server reads from backend and encrypts to client
            // client -> backend
            //   - client reaads from client and encrypts to backend
            //   - server decrypts from client and sends to backend
            match shovel(source, sink, source_is_backend, is_client, &mut conn_ctx) {
                Ok(eof) => {
                    if eof {
                        let mut source_kind = "client";
                        if source_is_backend {
                            source_kind = "backend";
                        }
                        info!("{} connection closed", source_kind);
                        return;
                    }
                }
                Err(e) => {
                    error!("Error shovelling data: {:?}", e);
                    return;
                }
            }
        }
    }
}

fn receive_pubkey(
    mut source: &TcpStream,
) -> Result<([u8; ENCRYPTED_HANDSHAKE_BYTES], bool), std::io::Error> {
    let mut encrypted_pk = [0u8; ENCRYPTED_HANDSHAKE_BYTES];
    let mut received = 0;

    let mut sources = popol::Sources::with_capacity(1);
    let mut events = Vec::with_capacity(1);

    sources.register((), source, popol::interest::READ);

    loop {
        events.clear();

        sources.poll(&mut events, popol::Timeout::from_secs(60))?;

        assert!(events.len() == 1, "expecting 1 event for handshake");

        let event = &events[0];

        if event.is_invalid() {
            // fd was probably not opened first
            error!("received invalid event (aborting): {:?}", event);
            return Ok((encrypted_pk, true));
        }

        if event.is_error() {
            error!("received error in event (aborting): {:?}", event);
            return Ok((encrypted_pk, true));
        }

        if event.is_hangup() {
            error!("received hangup in event (aborting): {:?}", event);
            return Ok((encrypted_pk, true));
        }

        if !event.is_readable() {
            error!("received event but not readable: {:?}", event);
            return Ok((encrypted_pk, true));
        }

        let n = match source.read(&mut encrypted_pk[received..]) {
            Ok(n) => {
                debug!("receive_pubkey read {} bytes", n);
                n
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        };

        // when read() returns 0 it means EOF / closed connection
        if n == 0 {
            return Ok((encrypted_pk, true));
        }

        received += n;

        if received == ENCRYPTED_HANDSHAKE_BYTES {
            return Ok((encrypted_pk, false));
        }
    }
}

fn shovel(
    source: &TcpStream,
    sink: &TcpStream,
    source_is_backend: bool,
    is_client: bool,
    conn_ctx: &mut ConnectionContext,
) -> Result<bool, std::io::Error> {
    match (source_is_backend, is_client) {
        (false, false) => shovel_decrypted(source, sink, conn_ctx),
        (false, true) => shovel_encrypted(source, sink, conn_ctx),
        (true, false) => shovel_encrypted(source, sink, conn_ctx),
        (true, true) => shovel_decrypted(source, sink, conn_ctx),
    }
}

fn shovel_decrypted(
    mut source: &TcpStream,
    mut sink: &TcpStream,
    conn_ctx: &mut ConnectionContext,
) -> Result<bool, std::io::Error> {
    loop {
        debug!("before read");

        assert!(conn_ctx.rx_buf_len < CIPHERTEXT_FRAME_BYTES);

        let n = match source.read(&mut conn_ctx.rx_buf[conn_ctx.rx_buf_len..CIPHERTEXT_FRAME_BYTES])
        {
            Ok(n) => {
                debug!("read {} bytes", n);
                n
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(e) => return Err(e),
        };

        // when read() returns 0 it means EOF / closed connection
        if n == 0 {
            return Ok(true);
        }

        conn_ctx.rx_buf_len += n;

        // try to see if there's more to read, otherwise exit on WouldBlock
        if conn_ctx.rx_buf_len < CIPHERTEXT_FRAME_BYTES {
            continue;
        }

        assert!(conn_ctx.rx_buf_len == CIPHERTEXT_FRAME_BYTES);

        let mut plaintext = [0u8; PLAINTEXT_FRAME_BYTES];

        crypto_aead_unlock(
            &mut plaintext,
            &conn_ctx.rx_buf[PLAINTEXT_FRAME_BYTES..],
            &conn_ctx.rx_key,
            &conn_ctx.rx_nonce,
            None,
            &conn_ctx.rx_buf[..PLAINTEXT_FRAME_BYTES],
        );

        conn_ctx.increment_rx_nonce();

        let len = u32::from_le_bytes(
            plaintext[(PLAINTEXT_FRAME_BYTES - PLAINTEXT_FRAME_LEN_BYTES)..PLAINTEXT_FRAME_BYTES]
                .try_into()
                .unwrap(),
        );

        sink.write_all(&plaintext[..len as usize])?;
        debug!("wrote {} bytes", len);

        // clean buffer for if we write again
        conn_ctx.reset_rx_buf();
    }
}

fn shovel_encrypted(
    mut source: &TcpStream,
    mut sink: &TcpStream,
    conn_ctx: &mut ConnectionContext,
) -> Result<bool, std::io::Error> {
    let mut buffer = [0u8; PLAINTEXT_FRAME_BYTES];

    loop {
        debug!("before read");
        let n =
            match source.read(&mut buffer[..(PLAINTEXT_FRAME_BYTES - PLAINTEXT_FRAME_LEN_BYTES)]) {
                Ok(n) => {
                    debug!("read {} bytes", n);
                    n
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(false),
                Err(e) => return Err(e),
            };

        // when read() returns 0 it means EOF / closed connection
        if n == 0 {
            return Ok(true);
        }

        assert!(n <= (PLAINTEXT_FRAME_BYTES - PLAINTEXT_FRAME_LEN_BYTES));

        let len: u32 = n.try_into().unwrap();
        buffer[(PLAINTEXT_FRAME_BYTES - PLAINTEXT_FRAME_LEN_BYTES)..PLAINTEXT_FRAME_BYTES]
            .copy_from_slice(&len.to_le_bytes());

        let mut ciphertext = [0u8; CIPHERTEXT_FRAME_BYTES];
        let (ciphertext_detached, mac) = ciphertext.split_at_mut(PLAINTEXT_FRAME_BYTES);

        crypto_aead_lock(
            ciphertext_detached,
            mac,
            &conn_ctx.tx_key,
            &conn_ctx.tx_nonce,
            None,
            &buffer[..PLAINTEXT_FRAME_BYTES],
        );

        conn_ctx.increment_tx_nonce();

        sink.write_all(&ciphertext)?;
        debug!("wrote {} bytes", ciphertext.len());

        // clean buffer for if we write again
        buffer[..].fill(0);
    }
}
