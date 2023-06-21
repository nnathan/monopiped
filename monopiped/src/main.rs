use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::process;
use std::thread;

use tracing::{debug, error, info, warn};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Listen address
    #[arg(short, long)]
    listener: String,

    /// Target backend address
    #[arg(short, long)]
    target: String,
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
                    proxy_connection(stream, target.as_str());
                });
            }
            Err(e) => {
                error!("Error accepting connection: {}", e);
            }
        }
    }
}

fn proxy_connection(client_stream: TcpStream, target: &str) {
    if let Err(e) = client_stream.set_nonblocking(true) {
        error!(
            "Error setting client connection to non-blocking (not proceeding): {:?}",
            e
        );
        return;
    }

    let backend_stream = match TcpStream::connect(target) {
        Ok(backend_stream) => {
            info!("Connected to backend: {}", target);
            backend_stream
        }
        Err(e) => {
            error!("Failed to connect to backend (not proceeding): {}", e);
            return;
        }
    };

    if let Err(e) = backend_stream.set_nonblocking(true) {
        error!(
            "Error setting backend connection to non-blocking (not proceeding): {:?}",
            e
        );
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
                /* fd was probably not opened first */
                error!("received invalid event (not proceeding): {:?}", event);
                return;
            }

            if event.is_error() {
                error!("received error in event (not proceeding): {:?}", event);
                return;
            }

            if event.is_hangup() {
                error!("received hangup in event (not proceeding): {:?}", event);
                return;
            }

            if event.is_readable() {
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

        /* when read() returns 0 it means EOF / closed connection */
        if n == 0 {
            return Ok(true);
        }

        sink.write_all(&buffer[..n])?;

        debug!("wrote {} bytes", n);
    }
}
