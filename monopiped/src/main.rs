use std::io;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;

fn main() {
    let listener = TcpListener::bind("0.0.0.0:31337").expect("Failed to bind to port 31337");
    println!("Server listening on port 31337");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {:?}", stream.peer_addr().unwrap());
                proxy_connection(stream);
            }
            Err(e) => {
                eprintln!("Error accepting connection: {}", e);
            }
        }
    }
}

const BACKEND_HOST: &str = "localhost";
const BACKEND_PORT: u16 = 22;

fn proxy_connection(client_stream: TcpStream) {
    client_stream
        .set_nonblocking(true)
        .expect("set_nonblocking call on client_stream failed");
    match TcpStream::connect((BACKEND_HOST, BACKEND_PORT)) {
        Ok(backend_stream) => {
            println!("Connected to backend: {}:{}", BACKEND_HOST, BACKEND_PORT);

            backend_stream
                .set_nonblocking(true)
                .expect("set_nonblocking call on backend_stream failed");
            let mut sources = popol::Sources::with_capacity(2);
            let mut events = Vec::with_capacity(2);

            sources.register((), &client_stream, popol::interest::READ);
            sources.register((), &backend_stream, popol::interest::READ);

            let mut buffer = [0; 4096];

            'outer: loop {
                println!("entering poll");

                events.clear();

                match sources.poll(&mut events, popol::Timeout::from_secs(1)) {
                    Ok(_) => {}
                    Err(err) if err.kind() == io::ErrorKind::TimedOut => {
                        eprintln!("poll 1 sec timeout");
                        continue;
                    }
                    Err(err) => {
                        eprintln!("poll error: {:?}", err);
                        break;
                    }
                }

                println!("draining {:?} events", events.len());

                for event in events.drain(..) {
                    println!("received event {:?}", event);

                    if event.is_invalid() {
                        /* fd was probably not opened first */
                        eprintln!(
                            "received invalid event - shutting down socketpair: {:?}",
                            event
                        );
                        break 'outer;
                    }

                    if event.is_error() {
                        eprintln!(
                            "received error in event - shutting down socketpair: {:?}",
                            event
                        );
                        break 'outer;
                    }

                    if event.is_hangup() {
                        eprintln!(
                            "received hangup in event - shutting down socketpair: {:?}",
                            event
                        );
                        break 'outer;
                    }

                    if event.is_readable() {
                        let mut source = &client_stream;
                        let mut sink = &backend_stream;

                        if event.as_raw_fd() == backend_stream.as_raw_fd() {
                            println!("source is backend_stream");
                            source = &backend_stream;
                            sink = &client_stream;
                        }

                        loop {
                            println!("read loop");
                            let n = match source.read(&mut buffer) {
                                Ok(n) => {
                                    println!("read {:?} bytes", n);
                                    n
                                }
                                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                                    break;
                                }
                                Err(err) => {
                                    eprintln!(
                                        "error reading from socket - shutting down socketpair: {:?}",
                                        err
                                    );
                                    break 'outer;
                                }
                            };

                            if n == 0 {
                                /* when read() returns 0 it means EOF / closed connection */
                                break 'outer;
                            }

                            match sink.write_all(&buffer[..n]) {
                                Ok(_) => {}
                                Err(err) => {
                                    eprintln!(
                                        "error writing to socket - shutting down socketpair: {:?}",
                                        err
                                    );

                                    break 'outer;
                                }
                            };

                            println!("wrote {:?} bytes", n);
                        }
                    }
                }
            }

            println!("Connection closed");
        }
        Err(e) => {
            eprintln!("Failed to connect to backend: {}", e);
        }
    }
}
