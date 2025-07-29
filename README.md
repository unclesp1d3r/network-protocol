<div align="center">
        <img width="120px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <h1>network-protocol</h1>
    <br>
    <div>
        <a href="https://crates.io/crates/network-protocol" alt="Network-Protocol on Crates.io"><img alt="Crates.io" src="https://img.shields.io/crates/v/network-protocol"></a>
        <span>&nbsp;</span>
        <a href="https://crates.io/crates/network-protocol" alt="Download Network-Protocol"><img alt="Crates.io Downloads" src="https://img.shields.io/crates/d/network-protocol?color=%230099ff"></a>
        <span>&nbsp;</span>
        <a href="https://docs.rs/network-protocol" title="Network-Protocol Documentation"><img alt="docs.rs" src="https://img.shields.io/docsrs/network-protocol"></a>
        <span>&nbsp;</span>
        <img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/jamesgober/network-protocol?color=%23347d39" alt="last commit badge">
        <span>&nbsp;</span>
        <a href="https://github.com/jamesgober/network-protocol/actions"><img alt="GitHub CI" src="https://github.com/jamesgober/network-protocol/actions/workflows/ci.yml/badge.svg"></a>
    </div>
</div>
<br>
<p>
    A secure, high-performance network protocol core for Rust applications and services. Built for speed, encryption, and pluggable transport modes (local, remote, cluster).
</p>
<br>

## Features
- Secure handshake + post-handshake encryption
- Custom binary packet format with compression
- Plugin-friendly dispatcher for message routing
- Modular: remote TCP, local Unix socket, cluster sync (planned)
- Ready for microservices, databases, daemons, and system protocols

<br>

## Installation
Add the library to your `Cargo.toml`:
```toml
[dependencies]
network-protocol = "0.8.0"
```

<br>

## Example Usage

### Server (daemon)
```rust
#[tokio::main]
async fn main() -> Result<()> {
    network_protocol::service::daemon::start("127.0.0.1:9000").await?;
    Ok(())
}
```

### Client
```rust
#[tokio::main]
async fn main() -> Result<()> {
    let mut conn = network_protocol::service::client::connect("127.0.0.1:9000").await?;
    conn.secure_send(Message::Echo("hello".into())).await?;
    let reply = conn.secure_recv().await?;
    println!("Received: {:?}", reply);
    Ok(())
}
```

<br>

### Message Types
Built-in messages include:
- `HandshakeInit` / `HandshakeAck`
- `Ping` / `Pong`
- `Echo(String)`
- `Unknown`

You can extend this list with your own enums or handlers.

<br>

### Custom Handlers
Register your own handlers:
```rust
let mut dispatcher = Dispatcher::new();

dispatcher.register("PING", |_| Ok(Message::Pong));
dispatcher.register("ECHO", |msg| Ok(msg.clone()));
```

The dispatcher will auto-route incoming messages based on their `message_type()`.

<br>

### Running Tests
```bash
cargo test
```

Runs full unit + integration + performance benchmarks:
- Secure handshake
- Message roundtrip
- Throughput (unoptimized dev profile)

<br>

### Project Structure
```
src/
├── core/        # Codec, packet structure
├── protocol/    # Handshake, heartbeat, message types
├── transport/   # TCP, Unix socket, Cluster (WIP)
├── service/     # Daemon + client APIs
├── utils/       # Compression, crypto, timers
```




