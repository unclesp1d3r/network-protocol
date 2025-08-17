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
        <a href="https://github.com/jamesgober/network-protocol/actions"><img alt="GitHub CI" src="https://github.com/jamesgober/network-protocol/actions/workflows/ci.yml/badge.svg"></a>
    </div>
</div>
<br>
<p>
    A secure, high-performance network protocol core for Rust applications and services with TLS support and graceful shutdown capabilities. Built for speed, encryption, and pluggable transport modes (local, remote, TLS, cluster).
</p>
<br>

## Features
- Secure handshake + post-handshake encryption using Elliptic Curve Diffie-Hellman (ECDH) key exchange
- TLS transport with client/server implementations and mutual authentication (mTLS)
- Self-signed certificate generation capability for development environments
- Certificate pinning for enhanced security in TLS connections
- Custom binary packet format with optional compression (LZ4, Zstd)
- Plugin-friendly dispatcher for message routing with zero-copy serialization
- Graceful shutdown support for all server implementations with configurable timeouts
- Modular transport: TCP, Unix socket, TLS, cluster sync
- Ready for microservices, databases, daemons, and system protocols
<br>

## Installation
Add the library to your `Cargo.toml`:
```toml
[dependencies]
network-protocol = "0.9.3"
```

<br>

## Example Usage

### TCP Server with Graceful Shutdown
```rust
#[tokio::main]
async fn main() -> Result<()> {
    // Create a dispatcher
    let dispatcher = Arc::new(Dispatcher::default());
    
    // Register message handlers
    dispatcher.register("ECHO", |msg| Ok(msg.clone()));
    
    // Start server with graceful shutdown support
    let server = network_protocol::service::daemon::new("127.0.0.1:9000", dispatcher);
    
    // Handle Ctrl+C for graceful shutdown
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl+c");
        println!("Initiating graceful shutdown...");
        server.shutdown(Some(Duration::from_secs(10))).await;
    });
    
    // Run server until stopped
    server.run().await?;
    Ok(())
}
```

### TLS Server
```rust
#[tokio::main]
async fn main() -> Result<()> {
    // Generate or load certificates
    let cert_config = TlsConfig {
        cert_path: "server_cert.pem",
        key_path: "server_key.pem",
        ca_path: Some("ca_cert.pem"), // For mTLS
        verify_client: true, // Enable mTLS
    };
    
    // Start TLS server
    network_protocol::service::tls_daemon::start("127.0.0.1:9443", cert_config).await?;
    Ok(())
}
```

### Standard Client
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

### TLS Client
```rust
#[tokio::main]
async fn main() -> Result<()> {
    // Configure TLS client
    let tls_config = TlsClientConfig {
        cert_path: Some("client_cert.pem"), // For mTLS
        key_path: Some("client_key.pem"),  // For mTLS
        ca_path: Some("ca_cert.pem"),      // Server verification
        server_name: "example.com",         // SNI
    };
    
    // Connect with TLS
    let mut conn = network_protocol::service::client::connect_tls(
        "127.0.0.1:9443", 
        tls_config
    ).await?;
    
    // Communicate securely
    conn.send(Message::Echo("secure message".into())).await?;
    let reply = conn.receive().await?;
    
    // Close connection properly
    conn.close().await?;
    Ok()
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


[Docs Root](./docs/README.md) | 
[API Reference](./docs/API.md)

