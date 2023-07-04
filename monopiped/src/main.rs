use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::process;
use std::thread;

use tracing::{debug, error, info, warn};

use clap::{ArgGroup, Parser};

use dryoc::classic::crypto_kx::*;
use dryoc::classic::crypto_secretbox::{crypto_secretbox_easy, crypto_secretbox_open_easy};
use dryoc::constants::CRYPTO_SECRETBOX_MACBYTES;

use crate::utils::{crypto_hash_file, derive_keys};
mod utils;

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
    client: bool,
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

    let mut tx_key = [0u8; 32];
    let mut rx_key = [0u8; 32];

    tx_key[..].clone_from_slice(server_key);
    rx_key[..].clone_from_slice(client_key);

    if client {
        tx_key[..].clone_from_slice(client_key);
        rx_key[..].clone_from_slice(server_key);
    }

    let (pk, sk) = crypto_kx_keypair();
    let nonce = [0u8; 24];

    let mut encrypted_pk = [0u8; ENCRYPTED_HANDSHAKE_BYTES];

    if crypto_secretbox_easy(&mut encrypted_pk, &pk, &nonce, &tx_key).is_err() {
        error!("Error encrypting public key");
        return;
    }

    let mut handshake_stream = &client_stream;

    if client {
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

    if crypto_secretbox_open_easy(&mut received_pk, &encrypted_pk, &nonce, &rx_key).is_err() {
        error!("Failed to decrypted encrypted public key (aborting): authentication failure");
        return;
    }

    if client {
        if crypto_kx_client_session_keys(&mut rx_key, &mut tx_key, &pk, &sk, &received_pk).is_err()
        {
            error!("Failed to perform key exchange (aborting)");
            return;
        }
    } else if crypto_kx_server_session_keys(&mut rx_key, &mut tx_key, &pk, &sk, &received_pk)
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

        match sources.poll(&mut events, popol::Timeout::from_secs(1)) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::TimedOut => {
                debug!("poll timeout");
                continue;
            }
            Err(e) => {
                error!("poll error: {:?}", e);
                break;
            }
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
            let source_kind: &str;
            let sink_kind: &str;

            if event.as_raw_fd() == backend_stream.as_raw_fd() {
                source = &backend_stream;
                sink = &client_stream;
                source_kind = "backend";
                sink_kind = "client";
            } else {
                source = &client_stream;
                sink = &backend_stream;
                source_kind = "client";
                sink_kind = "backend";
            }

            debug!("source is {}, sink is {}", source_kind, sink_kind);

            match shovel(source, sink) {
                Ok(eof) => {
                    if eof {
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

fn shovel(mut source: &TcpStream, mut sink: &TcpStream) -> Result<bool, std::io::Error> {
    let mut buffer = [0; 4096];

    loop {
        debug!("before read");
        let n = match source.read(&mut buffer) {
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

        sink.write_all(&buffer[..n])?;

        debug!("wrote {} bytes", n);
    }
}
