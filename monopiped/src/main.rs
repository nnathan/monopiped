use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::process;

use tracing::{info, error, debug};

fn main() {
    tracing_subscriber::fmt::init();

    let listener = match TcpListener::bind("0.0.0.0:31337") {
        Ok(listener) => listener,
        Err(e) => {
            error!("Failed to bind to port 31337: {:?}", e);
            process::exit(1);
        }
    };

    info!("Server listening on port 31337");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                info!("New connection: {:?}", stream.peer_addr().unwrap());

                proxy_connection(stream);
            }
            Err(e) => {
                error!("Error accepting connection: {}", e);
            }
        }
    }
}

const BACKEND_HOST: &str = "localhost";
const BACKEND_PORT: u16 = 22;

fn proxy_connection(client_stream: TcpStream) {
    match client_stream.set_nonblocking(true) {
        Ok(_) => {},
        Err(e) => {
            error!("Error setting client connection to non-blocking (not proceeding): {:?}", e);
            return;
        }
    }

    let backend_stream = match TcpStream::connect((BACKEND_HOST, BACKEND_PORT)) {
        Ok(backend_stream) => {
            info!("Connected to backend: {}:{}", BACKEND_HOST, BACKEND_PORT);
            backend_stream
        }
        Err(e) => {
            error!("Failed to connect to backend (not proceeding): {}", e);
            return;
        }
    };

    match backend_stream.set_nonblocking(true) {
        Ok(_) => {},
        Err(e) => {
            error!("Error setting backend connection to non-blocking (not proceeding): {:?}", e);
            return;
        }
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

        debug!("draining {:?} events", events.len());

        for event in events.drain(..) {
            debug!("received event {:?}", event);

            if event.is_invalid() {
                /* fd was probably not opened first */
                error!(
                    "received invalid event (not proceeding): {:?}",
                    event
                );
                return;
            }

            if event.is_error() {
                eprintln!(
                    "received error in event (not proceeding): {:?}",
                    event
                );
                return;
            }

            if event.is_hangup() {
                eprintln!(
                    "received hangup in event (not proceeding): {:?}",
                    event
                );
                return;
            }

            if event.is_readable() {
                let source: &TcpStream;
                let sink: &TcpStream;
                let kind: &str;

                if event.as_raw_fd() == backend_stream.as_raw_fd() {
                    debug!("source is backend, sink is client");
                    source = &backend_stream;
                    sink = &client_stream;
                    kind = "backend";
                } else {
                    debug!("source is client, sink is backend");
                    source = &client_stream;
                    sink = &backend_stream;
                    kind = "client";
                }

                match shovel(source, sink) {
                    Ok(eof) => {
                        info!("{} connection closed", kind);
                        if eof {
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
                debug!("read {:?} bytes", n);
                n
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(e) => return Err(e),
        };

        /* when read() returns 0 it means EOF / closed connection */
        if n == 0 {
            return Ok(true);
        }

        match sink.write_all(&buffer[..n]) {
            Ok(_) => {}
            Err(e) => return Err(e),
        };

        debug!("wrote {:?} bytes", n);
    }
}
