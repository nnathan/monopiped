use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::process;
use std::thread;

use tracing::{debug, error, info, warn};

use clap::{ArgGroup, Parser};

use dryoc::classic::crypto_kdf::*;
use dryoc::classic::crypto_kx::*;
use dryoc::classic::crypto_secretbox::*;
use dryoc::constants::CRYPTO_SECRETBOX_MACBYTES;

use crate::utils::crypto_hash_file;
mod utils;

const CIPHERTEXT_FRAME_BYTES: usize = 1060;
const PLAINTEXT_BYTES: usize = CIPHERTEXT_FRAME_BYTES - CRYPTO_SECRETBOX_MACBYTES;
const PLAINTEXT_OVERHEAD: usize = 4;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[clap(group(
            ArgGroup::new("mode")
                .required(true)
                .args(&["encrypt", "decrypt"]),
        ))]
struct Args {
    /// Take unencrypted connections from listener and send encryption connections to target
    #[arg(short, long)]
    encrypt: bool,

    /// Take encrypted connections from listener and send unencrypted connections to target
    #[arg(short, long)]
    decrypt: bool,

    /// Listen address
    #[arg(short, long, value_name = "ADDR:PORT")]
    listener: String,

    /// Target backend address
    #[arg(short, long, value_name = "ADDR:PORT")]
    target: String,

    /// Key material
    #[arg(short, long, value_name = "FILE")]
    key: PathBuf,
}

use tracing_subscriber::filter::{EnvFilter, LevelFilter};

fn default_env() -> EnvFilter {
    EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy()
}

fn main() {
    tracing_subscriber::fmt()
        .compact()
        .with_target(false)
        .with_thread_ids(true)
        .with_env_filter(default_env())
        .init();

    let args = Args::parse();

    let master_key = match crypto_hash_file(&args.key) {
        Ok(k) => k,
        Err(e) => {
            let p = args.key.into_os_string().into_string().unwrap();
            error!("Failed to derive key from key file {}: {:?}", p, e);
            process::exit(1);
        }
    };

    let derive_keys = |k: &[u8; 32]| {
        let context: [u8; 8] = [0; 8];
        let mut client_key: [u8; 32] = [0; 32];
        let mut server_key: [u8; 32] = [0; 32];
        crypto_kdf_derive_from_key(&mut client_key, 0, &context, k).expect("client key kdf failed");
        crypto_kdf_derive_from_key(&mut server_key, 1, &context, k).expect("server key kdf failed");
        (client_key, server_key)
    };

    let (client_key, server_key) = derive_keys(&master_key);

    let listener_addr = args.listener.as_str();

    let listener = match TcpListener::bind(listener_addr) {
        Ok(listener) => listener,
        Err(e) => {
            error!("Failed to listen on {} {:?}", listener_addr, e);
            process::exit(1);
        }
    };

    info!("Listening on {}", listener_addr);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                match stream.peer_addr() {
                    Ok(peer_addr) => {
                        info!("New connection: {}", peer_addr);
                    }
                    Err(e) => {
                        warn!("New connection: <error getting peer address>: {:?}", e);
                    }
                };

                let target = args.target.clone();

                thread::spawn(move || {
                    proxy_connection(
                        stream,
                        target.as_str(),
                        args.encrypt,
                        &client_key,
                        &server_key,
                    );
                });
            }
            Err(e) => {
                error!("Error accepting connection: {}", e);
            }
        }
    }
}

const ENCRYPTED_HANDSHAKE_BYTES: usize = 32 + CRYPTO_SECRETBOX_MACBYTES;

fn proxy_connection(
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

    let (pk, sk) = crypto_kx_keypair();
    let nonce = [0u8; 24];

    let mut encrypted_pk = [0u8; ENCRYPTED_HANDSHAKE_BYTES];

    if crypto_secretbox_easy(&mut encrypted_pk, &pk, &nonce, &conn_ctx.tx_key).is_err() {
        error!("Error encrypting public key");
        return;
    }

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

    if crypto_secretbox_open_easy(&mut received_pk, &encrypted_pk, &nonce, &conn_ctx.rx_key)
        .is_err()
    {
        error!("Failed to decrypted encrypted public key (aborting): authentication failure");
        return;
    }

    if is_client {
        if crypto_kx_client_session_keys(
            &mut conn_ctx.rx_key,
            &mut conn_ctx.tx_key,
            &pk,
            &sk,
            &received_pk,
        )
        .is_err()
        {
            error!("Failed to perform key exchange (aborting)");
            return;
        }
    } else if crypto_kx_server_session_keys(
        &mut conn_ctx.rx_key,
        &mut conn_ctx.tx_key,
        &pk,
        &sk,
        &received_pk,
    )
    .is_err()
    {
        error!("Failed to perform key exchange (aborting)");
        return;
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

fn increment_nonce(nonce: &mut [u8; 24], incr: u8) {
    let mut acc: u16 = incr as u16;

    let mut i = 0;

    while i < nonce.len() {
        acc = (nonce[i] as u16) + acc;
        nonce[i] = (acc & 0xFF) as u8;
        acc = acc >> 8;
        i += 1;
    }
}

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

        let _ = crypto_secretbox_open_easy_inplace(
            &mut conn_ctx.rx_buf,
            &conn_ctx.rx_nonce,
            &conn_ctx.rx_key,
        );
        conn_ctx.increment_rx_nonce();

        let len = u32::from_le_bytes(
            conn_ctx.rx_buf[(PLAINTEXT_BYTES - PLAINTEXT_OVERHEAD)..PLAINTEXT_BYTES]
                .try_into()
                .unwrap(),
        );

        let len: usize = len as usize;
        sink.write_all(&conn_ctx.rx_buf[..len])?;
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
    let mut buffer = [0u8; CIPHERTEXT_FRAME_BYTES];

    loop {
        debug!("before read");
        let n = match source.read(&mut buffer[..(PLAINTEXT_BYTES - PLAINTEXT_OVERHEAD)]) {
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

        assert!(n <= (PLAINTEXT_BYTES - PLAINTEXT_OVERHEAD));

        let len: u32 = n.try_into().unwrap();
        buffer[(PLAINTEXT_BYTES - PLAINTEXT_OVERHEAD)..PLAINTEXT_BYTES]
            .copy_from_slice(&len.to_le_bytes());

        let _ = crypto_secretbox_easy_inplace(&mut buffer, &conn_ctx.tx_nonce, &conn_ctx.tx_key);
        conn_ctx.increment_tx_nonce();

        sink.write_all(&buffer)?;
        debug!("wrote {} bytes", buffer.len());

        // clean buffer for if we write again
        buffer[..].fill(0);
    }
}
