# Monopiped

Monopiped is a pastiche of Colin Percival's [spiped](https://www.tarsnap.com/spiped.html).

## Motivation

Originally Monopiped was intended to modify spiped and replace crypto primitives by those available in [Monocypher](https://monocypher.org/) (e.g. X25519 instead of finite field Diffie-Hellman, ChaCha20Poly1305 instead of AES-CTR+HMAC, etc.).

However since inception there was no progress on this front.

The idea pivoted from being a modification of spiped to instead a reinterpretation in Rust, primarily as a technical exercise for the author to learn Rust and dabble in cryptography and sockets.

## Build

Install Rust and run `cargo build -r`. (You want `-r` for release version which is at least an order of magnitude faster than debug build.)

## Operation

There are two "modes" that monopiped can be run as:

  - *client* or *encrypt* mode: this is when monopiped listens for unencrypted connections on a socket, and sends encrypted connections to the *server*
  - *server* or *decrypt* mode: this is when monopiped listens for encrypted connections, and sends/proxy unencrypted connections to a target socket

### Tunneling over TCP

The usual way to run monopiped is by tunneling a TCP application like `ssh` encrypted over TCP.

This is a depiction of how a client and server would run:

```
┌────────────────────────────────────────────────────┐                                   ┌──────────────────────────────────────────────────┐
│ client                                             │                                   │  server                                          │
│                                                    │                                   │                                                  │
│ ┌────────────────────────┐        ┌───────────┐    │        (encrypted over tcp)       │   ┌───────────┐       ┌────────────────────────┐ │
│ │ application (e.g. ssh) │◀──────▶│ monopiped │◀───┼───────────────────────────────────┼──▶│ monopiped │◀─────▶│   target (e.g. sshd)   │ │
│ └────────────────────────┘        └───────────┘    │                                   │   └───────────┘       └────────────────────────┘ │
│                                                    │                                   │                                                  │
└────────────────────────────────────────────────────┘                                   └──────────────────────────────────────────────────┘
```

As an example of tunneling SSH, you would:

  - generate a shared key: `dd if=/dev/urandom bs=32 count=1 of=key.bin`
  - run on the *client*: `monopiped -l 127.0.0.1:3000 -t server.example.com:2222 -e -k key.bin`
  - run on the *server*: `monopiped -l 0.0.0.0:2222 -t 127.0.0.1:22 -d -k key.bin`

Then on the client you can connect to the SSH server by running: `ssh -p3000 127.0.0.1`.

### Tunneling over Websockets

monopiped also supports tunneling TCP application encrypted over WebSockets.

This is a depiction of how a client and server would run:

```
┌────────────────────────────────────────────────────┐                                   ┌────────────────────────────────────────────────────────────────────────────────────────┐
│ client                                             │                                   │  server                                                                                │
│                                                    │           [encrypted over         │                                                                                        │
│ ┌────────────────────────┐        ┌───────────┐    │       WebSockets via HTTP(S)]     │   ┌────────────────────────────┐       ┌───────────┐        ┌────────────────────────┐ │
│ │ application (e.g. ssh) │◀──────▶│ monopiped │◀───┼───────────────────────────────────┼──▶│nginx/caddy/websocket proxy │◀─────▶│ monopiped │◀──────▶│   target (e.g. sshd)   │ │
│ └────────────────────────┘        └───────────┘    │                                   │   └────────────────────────────┘       └───────────┘        └────────────────────────┘ │
│                                                    │                                   │                                                                                        │
└────────────────────────────────────────────────────┘                                   └────────────────────────────────────────────────────────────────────────────────────────┘
```

What's different to TCP is the inclusion of a webserver that will front the monopiped on the server side.

As an example of tunneling SSH, you would:

  - generate a shared key: `dd if=/dev/urandom bs=32 count=1 of=key.bin`
  - run on the *client*: `monopiped -l 127.0.0.1:3000 -t wss://server.example.com/ssh -e -k key.bin`
  - run a websocket proxy server on the *server*: (see below for an example Caddy v2 example)
  - run on the *server*: `monopiped -l 127.0.0.1:3000 -t 127.0.0.1:22 -d -k key.bin -w`

Then on the client you can connect to the SSH server by running: `ssh -p3000 127.0.0.1`.

Here is a sample `Caddyfile` to use with the [Caddy v2 webserver](https://caddyserver.com/) to setup a route to a websocket backend, where the backend will be monopiped listening in websocket mode on port 3000:

```
server.example.com:80 server.example.com:443 {
        root * /var/www/html
        file_server
        reverse_proxy /ssh 127.0.0.1:3000
}
```

The above Caddyfile listens on both HTTP and HTTPS. Since the transport is end-to-end encrypted between client and server over WebSockets or TCP, it is perfectly fine to use HTTP and still maintain confidentiality and integrity. Packet captures of traffic over HTTP would just show WebSocket binary payloads and little else.

## Aspirations

~Currently the program implements a one thread per connection model. To minimise resources and improve scalability (as if it's needed) maybe the model will be switched to asynchronous network I/O using Tokio.~

~It would also be nice to support proxying over WebSockets.~
