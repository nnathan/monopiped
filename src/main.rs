use std::path::PathBuf;
use std::process;

use tracing::{error, info, warn};

use clap::error::ErrorKind;
use clap::{ArgGroup, CommandFactory, Parser};

use tokio::net::TcpListener;

use zeroize::Zeroize;

use crate::conn::proxy_connection;
use crate::utils::{crypto_hash_file, is_websocket_url};
use crate::ws::proxy_ws_connection;

use mini_monocypher::crypto_blake2b_keyed;

mod conn;
mod utils;
mod ws;

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
    #[arg(short, long, value_name = "WS_URL|ADDR:PORT")]
    target: String,

    /// Key material
    #[arg(short, long, value_name = "FILE")]
    key: PathBuf,

    /// Configure listener to receive websocket connections (only in decrypt mode)
    #[arg(short, long)]
    ws: bool,
}

use tracing_subscriber::filter::{EnvFilter, LevelFilter};

#[tokio::main]
async fn main() -> Result<(), tokio::io::Error> {
    let mut args = Args::parse();

    if is_websocket_url(&args.target) {
        if args.decrypt {
            let mut cmd = Args::command();
            cmd.error(
                ErrorKind::ArgumentConflict,
                "Specifying target as a websocket URL is not supported in server (decrypt) mode",
            )
            .exit();
        }

        args.ws = true;
    }

    let default_env = || {
        EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy()
    };

    tracing_subscriber::fmt()
        .compact()
        .with_target(false)
        .with_thread_ids(false)
        .with_env_filter(default_env())
        .init();

    let mut master_key = match crypto_hash_file(&args.key) {
        Ok(k) => k,
        Err(e) => {
            let p = args.key.into_os_string().into_string().unwrap();
            error!("Failed to derive key from key file {}: {:?}", p, e);
            process::exit(1);
        }
    };

    let derive_keys = |k: &[u8; 32]| {
        let mut client_key = [0u8; 32];
        let mut server_key = [0u8; 32];
        crypto_blake2b_keyed(&mut client_key, k, b"client");
        crypto_blake2b_keyed(&mut server_key, k, b"server");
        (client_key, server_key)
    };

    let (client_key, server_key) = derive_keys(&master_key);
    master_key.zeroize();

    let listener_addr = args.listener.as_str();

    let listener = match TcpListener::bind(listener_addr).await {
        Ok(listener) => listener,
        Err(e) => {
            error!("Failed to listen on {} {:?}", listener_addr, e);
            process::exit(1);
        }
    };

    info!("Listening on {}", listener_addr);

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok((stream, peer_addr)) => {
                info!("New connection: {}", peer_addr);
                (stream, peer_addr)
            }

            Err(e) => {
                warn!("New connection: <error getting peer address>: {:?}", e);
                tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
                continue;
            }
        };

        let target = args.target.clone();

        if args.ws {
            tokio::spawn(async move {
                proxy_ws_connection(
                    peer_addr,
                    stream,
                    target.as_str(),
                    args.encrypt,
                    &client_key,
                    &server_key,
                )
                .await;
            });

            continue;
        }

        tokio::spawn(async move {
            proxy_connection(
                peer_addr,
                stream,
                target.as_str(),
                args.encrypt,
                &client_key,
                &server_key,
            )
            .await;
        });
    }
}
