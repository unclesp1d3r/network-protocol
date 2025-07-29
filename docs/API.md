<div align="center">
    <img width="120px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <h1>
        <strong>network-protocol</strong>
        <sup>
            <br>
            <sub>API REFERENCE</sub>
            <br>
        </sup>
    </h1>
</div>


[Home](../README.md) | 
[Docs Root](./README.md)

<br>


## Table of Contents

- [Installation](#installation)
- [Core Modules](#core-modules)
  - [Packet](#packet)
  - [PacketCodec](#packetcodec)
- [Transport](#transport)
  - [Remote Transport](#remote-transport)
  - [Local Transport](#local-transport)
  - [Cluster Transport](#cluster-transport)
- [Protocol](#protocol)
  - [Message](#message)
  - [Handshake](#handshake)
  - [Dispatcher](#dispatcher)
  - [Heartbeat](#heartbeat)
- [Service](#service)
  - [Client](#client)
  - [Daemon](#daemon)
  - [Secure Connection](#secure-connection)
- [Utilities](#utilities)
  - [Cryptography](#cryptography)
  - [Compression](#compression)
  - [Time](#time)
- [Error Handling](#error-handling)
- [Configuration](#configuration)

## Installation

### Install Manually
```toml
[dependencies]
network-protocol = "0.8.0"
```

### Install Using Cargo
```bash
cargo install network-protocol
```

## Core Modules

The core modules provide the fundamental structures and functionality for packet handling and serialization/deserialization.

### Packet

The `Packet` struct represents a fully decoded protocol packet, including the protocol version and binary payload.

#### Constants

```rust
pub const HEADER_SIZE: usize = 9; // 4 magic + 1 version + 4 length
```

#### Struct Definition

```rust
pub struct Packet {
    pub version: u8,
    pub payload: Vec<u8>,
}
```

#### Methods

##### `from_bytes`

Parses a packet from a raw buffer containing a header and body.

```rust
pub fn from_bytes(buf: &[u8]) -> Result<Self>
```

**Parameters:**
- `buf`: A byte slice containing the raw packet data

**Returns:**
- `Result<Packet>`: A result containing either the parsed packet or an error

**Errors:**
- `ProtocolError::InvalidHeader`: If the buffer is too short or has invalid magic bytes
- `ProtocolError::UnsupportedVersion`: If the protocol version is not supported
- `ProtocolError::OversizedPacket`: If the packet exceeds the maximum allowed size

**Example:**
```rust
use network_protocol::core::packet::Packet;

let raw_data = vec![0x4E, 0x50, 0x52, 0x4F, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
match Packet::from_bytes(&raw_data) {
    Ok(packet) => println!("Parsed packet with version {} and payload of {} bytes", packet.version, packet.payload.len()),
    Err(e) => eprintln!("Failed to parse packet: {}", e),
}
```

##### `to_bytes`

Serializes a packet to a byte vector containing a header and body.

```rust
pub fn to_bytes(&self) -> Vec<u8>
```

**Returns:**
- `Vec<u8>`: The serialized packet as bytes

**Example:**
```rust
use network_protocol::core::packet::Packet;

let packet = Packet {
    version: 1,
    payload: vec![1, 2, 3, 4, 5],
};

let bytes = packet.to_bytes();
println!("Serialized packet: {:?}", bytes);
```

### PacketCodec

The `PacketCodec` struct implements the Tokio `Decoder` and `Encoder` traits for packet-based communication.

#### Struct Definition

```rust
pub struct PacketCodec;
```

#### Implementations

##### Decoder Implementation

```rust
impl Decoder for PacketCodec {
    type Item = Packet;
    type Error = ProtocolError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Packet>>
}
```

**Parameters:**
- `src`: A mutable reference to a `BytesMut` buffer containing incoming data

**Returns:**
- `Result<Option<Packet>>`: A result containing either:
  - `Some(Packet)` if a complete packet was successfully decoded
  - `None` if more data is needed to decode a complete packet
  - `Err(ProtocolError)` if an error occurred during decoding

##### Encoder Implementation

```rust
impl Encoder<Packet> for PacketCodec {
    type Error = ProtocolError;

    fn encode(&mut self, packet: Packet, dst: &mut BytesMut) -> Result<()>
}
```

**Parameters:**
- `packet`: The `Packet` to encode
- `dst`: A mutable reference to a `BytesMut` buffer to write the encoded packet to

**Returns:**
- `Result<()>`: A result indicating success or an encoding error

**Example:**
```rust
use network_protocol::core::codec::PacketCodec;
use network_protocol::core::packet::Packet;
use tokio_util::codec::{Decoder, Encoder};
use bytes::BytesMut;

let mut codec = PacketCodec;
let mut buffer = BytesMut::new();

// Encode a packet
let packet = Packet {
    version: 1,
    payload: vec![1, 2, 3, 4, 5],
};
codec.encode(packet, &mut buffer).unwrap();

// Decode a packet
if let Some(decoded_packet) = codec.decode(&mut buffer).unwrap() {
    println!("Decoded packet: version={}, payload length={}", 
             decoded_packet.version, decoded_packet.payload.len());
}
```

## Transport

### Remote Transport

The remote transport module provides functions for TCP-based network communication.

#### Functions

##### `start_server`

Starts a TCP server at the given address.

```rust
pub async fn start_server(addr: &str) -> Result<()>
```

**Parameters:**
- `addr`: The address to bind the server to (e.g., "127.0.0.1:8080")

**Returns:**
- `Result<()>`: A result indicating success or an error

**Example:**
```rust
use network_protocol::transport::remote;

#[tokio::main]
async fn main() -> network_protocol::error::Result<()> {
    remote::start_server("127.0.0.1:8080").await
}
```

##### `connect`

Connects to a remote server and returns a framed transport.

```rust
pub async fn connect(addr: &str) -> Result<Framed<TcpStream, PacketCodec>>
```

**Parameters:**
- `addr`: The address to connect to (e.g., "127.0.0.1:8080")

**Returns:**
- `Result<Framed<TcpStream, PacketCodec>>`: A result containing either the framed connection or an error

**Example:**
```rust
use network_protocol::transport::remote;

#[tokio::main]
async fn main() -> network_protocol::error::Result<()> {
    let framed = remote::connect("127.0.0.1:8080").await?;
    println!("Connected to server!");
    Ok(())
}
```

### Local Transport

The local transport module provides functions for Unix Domain Socket (UDS) communication.

#### Functions

##### `start_server`

Starts a UDS server at the given socket path.

```rust
pub async fn start_server<P: AsRef<Path>>(path: P) -> Result<()>
```

**Parameters:**
- `path`: The path to the Unix domain socket

**Returns:**
- `Result<()>`: A result indicating success or an error

**Example:**
```rust
use network_protocol::transport::local;

#[tokio::main]
async fn main() -> network_protocol::error::Result<()> {
    local::start_server("/tmp/my_socket").await
}
```

##### `connect`

Connects to a local UDS socket.

```rust
pub async fn connect<P: AsRef<Path>>(path: P) -> Result<Framed<UnixStream, PacketCodec>>
```

**Parameters:**
- `path`: The path to the Unix domain socket

**Returns:**
- `Result<Framed<UnixStream, PacketCodec>>`: A result containing either the framed connection or an error

**Example:**
```rust
use network_protocol::transport::local;

#[tokio::main]
async fn main() -> network_protocol::error::Result<()> {
    let framed = local::connect("/tmp/my_socket").await?;
    println!("Connected to local socket!");
    Ok(())
}
```

### Cluster Transport

The cluster module provides functionality for managing a cluster of network nodes.

#### Structs

##### `ClusterNode`

```rust
pub struct ClusterNode {
    pub id: String,
    pub addr: String,
    pub last_seen: Option<Instant>,
}
```

##### `Cluster`

```rust
pub struct Cluster {
    peers: HashMap<String, ClusterNode>,
}
```

#### Methods

##### `Cluster::new`

Creates a new cluster with the given peers.

```rust
pub fn new(peers: Vec<(String, String)>) -> Self
```

**Parameters:**
- `peers`: A vector of (id, address) tuples representing the cluster peers

**Returns:**
- `Cluster`: A new cluster instance

##### `Cluster::start_heartbeat`

Starts the heartbeat process to monitor cluster nodes.

```rust
pub async fn start_heartbeat(&mut self, interval: Duration)
```

**Parameters:**
- `interval`: The interval between heartbeats

##### `Cluster::get_peers`

Gets a list of all peers in the cluster.

```rust
pub fn get_peers(&self) -> Vec<&ClusterNode>
```

**Returns:**
- `Vec<&ClusterNode>`: A vector of references to cluster nodes

**Example:**
```rust
use network_protocol::transport::cluster::Cluster;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let peers = vec![
        ("node1".to_string(), "127.0.0.1:8081".to_string()),
        ("node2".to_string(), "127.0.0.1:8082".to_string()),
    ];
    
    let mut cluster = Cluster::new(peers);
    
    // Print all peers
    for node in cluster.get_peers() {
        println!("Cluster node: {} at {}", node.id, node.addr);
    }
    
    // Start heartbeat in a separate task
    tokio::spawn(async move {
        cluster.start_heartbeat(Duration::from_secs(5)).await;
    });
}
```

## Protocol

### Message

The `Message` enum defines the types of messages that can be exchanged.

#### Enum Definition

```rust
pub enum Message {
    Ping,
    Pong,
    HandshakeInit { client_nonce: u64 },
    HandshakeAck { server_nonce: u64 },
    Echo(String),
    Disconnect,
    Unknown,
}
```

### Handshake

The handshake module provides functions for performing secure handshakes between client and server.

#### Functions

##### `client_handshake_init`

Initiates a handshake from the client side.

```rust
pub fn client_handshake_init() -> Message
```

**Returns:**
- `Message`: A `HandshakeInit` message containing a randomly generated nonce

##### `server_handshake_response`

Handles a server-side handshake response.

```rust
pub fn server_handshake_response(client_nonce: u64) -> Message
```

**Parameters:**
- `client_nonce`: The nonce received from the client

**Returns:**
- `Message`: A `HandshakeAck` message containing the server's response nonce

##### `verify_server_ack`

Verifies the server's handshake response.

```rust
pub fn verify_server_ack(server_nonce: u64, client_nonce: u64) -> bool
```

**Parameters:**
- `server_nonce`: The nonce received from the server
- `client_nonce`: The original client nonce

**Returns:**
- `bool`: `true` if the server's response is valid, `false` otherwise

##### `derive_shared_key`

Generates a 32-byte symmetric key from the client nonce.

```rust
pub fn derive_shared_key(client_nonce: u64) -> [u8; 32]
```

**Parameters:**
- `client_nonce`: The client nonce

**Returns:**
- `[u8; 32]`: A 32-byte symmetric key

**Example:**
```rust
use network_protocol::protocol::handshake;
use network_protocol::protocol::message::Message;

// Client side
let init_msg = handshake::client_handshake_init();
let client_nonce = match init_msg {
    Message::HandshakeInit { client_nonce } => client_nonce,
    _ => panic!("Unexpected message type"),
};

// Server side (after receiving client_nonce)
let response_msg = handshake::server_handshake_response(client_nonce);
let server_nonce = match response_msg {
    Message::HandshakeAck { server_nonce } => server_nonce,
    _ => panic!("Unexpected message type"),
};

// Client side (after receiving server_nonce)
let is_valid = handshake::verify_server_ack(server_nonce, client_nonce);
assert!(is_valid, "Invalid server handshake response");

// Both sides can now derive the same key
let key = handshake::derive_shared_key(client_nonce);
println!("Derived shared key: {:?}", key);
```

### Dispatcher

The dispatcher module provides a mechanism for routing and handling messages.

#### Struct Definition

```rust
pub struct Dispatcher {
    handlers: Arc<RwLock<HashMap<String, Box<HandlerFn>>>>,
}
```

#### Methods

##### `new`

Creates a new dispatcher.

```rust
pub fn new() -> Self
```

**Returns:**
- `Dispatcher`: A new dispatcher instance

##### `register`

Registers a handler for a specific operation code.

```rust
pub fn register<F>(&self, opcode: &str, handler: F)
where
    F: Fn(&Message) -> Result<Message> + Send + Sync + 'static,
```

**Parameters:**
- `opcode`: The operation code to register the handler for
- `handler`: The function to handle messages with the given opcode

##### `dispatch`

Dispatches a message to the appropriate handler.

```rust
pub fn dispatch(&self, msg: &Message) -> Result<Message>
```

**Parameters:**
- `msg`: The message to dispatch

**Returns:**
- `Result<Message>`: A result containing either the handler's response or an error

**Example:**
```rust
use network_protocol::protocol::dispatcher::Dispatcher;
use network_protocol::protocol::message::Message;
use network_protocol::error::Result;

let dispatcher = Dispatcher::new();

// Register handlers
dispatcher.register("PING", |_| Ok(Message::Pong));
dispatcher.register("ECHO", |msg| {
    match msg {
        Message::Echo(s) => Ok(Message::Echo(s.clone())),
        _ => Ok(Message::Unknown),
    }
});

// Dispatch a ping message
let response = dispatcher.dispatch(&Message::Ping).unwrap();
match response {
    Message::Pong => println!("Received pong response"),
    _ => println!("Unexpected response type"),
}
```

### Heartbeat

The heartbeat module provides functions for implementing heartbeat mechanisms.

#### Functions

##### `build_ping`

Builds a heartbeat ping message.

```rust
pub fn build_ping() -> Message
```

**Returns:**
- `Message`: A `Ping` message

##### `is_pong`

Returns true if a received message is a valid pong.

```rust
pub fn is_pong(msg: &Message) -> bool
```

**Parameters:**
- `msg`: The message to check

**Returns:**
- `bool`: `true` if the message is a `Pong`, `false` otherwise

**Example:**
```rust
use network_protocol::protocol::heartbeat;
use network_protocol::protocol::message::Message;

// Send a ping
let ping_msg = heartbeat::build_ping();

// Receive a response (in a real scenario, this would come from the network)
let response_msg = Message::Pong;

// Check if the response is a valid pong
if heartbeat::is_pong(&response_msg) {
    println!("Received valid pong response");
} else {
    println!("Response is not a pong");
}
```

## Service

### Client

The client module provides functionality for establishing secure connections to servers.

#### Struct Definition

```rust
pub struct Client {
    framed: FramedConnection,
    secure: SecureConnection,
}
```

#### Methods

##### `connect_tcp`

Connects to a remote TCP server with secure communication.

```rust
pub async fn connect_tcp(addr: &str) -> Result<Self>
```

**Parameters:**
- `addr`: The address to connect to (e.g., "127.0.0.1:8080")

**Returns:**
- `Result<Client>`: A result containing either a connected client or an error

##### `connect_uds`

Connects to a Unix domain socket server with secure communication.

```rust
pub async fn connect_uds<P: AsRef<Path>>(path: P) -> Result<Self>
```

**Parameters:**
- `path`: The path to the Unix domain socket

**Returns:**
- `Result<Client>`: A result containing either a connected client or an error

##### `send`

Sends a message to the server.

```rust
pub async fn send(&mut self, msg: Message) -> Result<()>
```

**Parameters:**
- `msg`: The message to send

**Returns:**
- `Result<()>`: A result indicating success or an error

##### `receive`

Receives a message from the server.

```rust
pub async fn receive(&mut self) -> Result<Message>
```

**Returns:**
- `Result<Message>`: A result containing either the received message or an error

##### `close`

Closes the connection to the server.

```rust
pub async fn close(&mut self) -> Result<()>
```

**Returns:**
- `Result<()>`: A result indicating success or an error

**Example:**
```rust
use network_protocol::service::client::Client;
use network_protocol::protocol::message::Message;

#[tokio::main]
async fn main() -> network_protocol::error::Result<()> {
    // Connect to a TCP server
    let mut client = Client::connect_tcp("127.0.0.1:8080").await?;
    println!("Connected to server");
    
    // Send an echo message
    let message = Message::Echo("Hello, server!".to_string());
    client.send(message).await?;
    
    // Receive the response
    let response = client.receive().await?;
    match response {
        Message::Echo(text) => println!("Received echo response: {}", text),
        _ => println!("Unexpected response type")
    }
    
    // Close the connection
    client.close().await?
}
```

### Daemon

The daemon module provides functionality for running a server that accepts client connections.

#### Functions

##### `run_tcp_server`

Runs a TCP server with the provided dispatcher.

```rust
pub async fn run_tcp_server(addr: &str, dispatcher: Arc<Dispatcher>) -> Result<()>
```

**Parameters:**
- `addr`: The address to bind the server to (e.g., "127.0.0.1:8080")
- `dispatcher`: An Arc-wrapped dispatcher for handling incoming messages

**Returns:**
- `Result<()>`: A result indicating success or an error

##### `run_uds_server`

Runs a Unix domain socket server with the provided dispatcher.

```rust
pub async fn run_uds_server<P: AsRef<Path>>(path: P, dispatcher: Arc<Dispatcher>) -> Result<()>
```

**Parameters:**
- `path`: The path to the Unix domain socket
- `dispatcher`: An Arc-wrapped dispatcher for handling incoming messages

**Returns:**
- `Result<()>`: A result indicating success or an error

**Example:**
```rust
use network_protocol::service::daemon;
use network_protocol::protocol::dispatcher::Dispatcher;
use network_protocol::protocol::message::Message;
use std::sync::Arc;

#[tokio::main]
async fn main() -> network_protocol::error::Result<()> {
    // Create a dispatcher
    let dispatcher = Arc::new(Dispatcher::new());
    
    // Register handlers
    let dispatcher_clone = Arc::clone(&dispatcher);
    dispatcher_clone.register("PING", |_| Ok(Message::Pong));
    dispatcher_clone.register("ECHO", |msg| {
        match msg {
            Message::Echo(s) => Ok(Message::Echo(s.clone())),
            _ => Ok(Message::Unknown),
        }
    });
    
    // Run the server
    println!("Starting server on 127.0.0.1:8080");
    daemon::run_tcp_server("127.0.0.1:8080", dispatcher).await
}
```

### Secure Connection

The secure connection module provides encryption and decryption capabilities for network communications.

#### Struct Definition

```rust
pub struct SecureConnection {
    key: [u8; 32],
    cipher: XChaCha20Poly1305,
    compress: bool,
}
```

#### Methods

##### `new`

Creates a new secure connection with the given key.

```rust
pub fn new(key: [u8; 32], compress: bool) -> Result<Self>
```

**Parameters:**
- `key`: The 32-byte encryption key
- `compress`: Whether to enable compression

**Returns:**
- `Result<SecureConnection>`: A result containing either the secure connection or an error

##### `encrypt`

Encrypts a message using the established key.

```rust
pub fn encrypt(&self, msg: &Message) -> Result<Vec<u8>>
```

**Parameters:**
- `msg`: The message to encrypt

**Returns:**
- `Result<Vec<u8>>`: A result containing either the encrypted message as bytes or an error

##### `decrypt`

Decrypts a message using the established key.

```rust
pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Message>
```

**Parameters:**
- `ciphertext`: The encrypted message bytes to decrypt

**Returns:**
- `Result<Message>`: A result containing either the decrypted message or an error

**Example:**
```rust
use network_protocol::service::secure::SecureConnection;
use network_protocol::protocol::message::Message;
use network_protocol::protocol::handshake;

// Establish a shared key (in a real scenario, this would be via handshake)
let client_nonce = 12345678;
let key = handshake::derive_shared_key(client_nonce);

// Create a secure connection
let secure_conn = SecureConnection::new(key, true).unwrap();

// Encrypt a message
let message = Message::Echo("Secret message".to_string());
let encrypted = secure_conn.encrypt(&message).unwrap();

// Decrypt the message
let decrypted = secure_conn.decrypt(&encrypted).unwrap();
if let Message::Echo(text) = decrypted {
    println!("Decrypted message: {}", text);
}
```

## Utilities

### Cryptography

The crypto module provides cryptographic functions for secure communication.

#### Functions

##### `generate_random_bytes`

Generates a vector of random bytes of the specified length.

```rust
pub fn generate_random_bytes(len: usize) -> Vec<u8>
```

**Parameters:**
- `len`: The length of the random byte vector to generate

**Returns:**
- `Vec<u8>`: A vector containing the random bytes

##### `encrypt`

Encrypts data using XChaCha20Poly1305.

```rust
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>
```

**Parameters:**
- `key`: The 32-byte encryption key
- `plaintext`: The data to encrypt

**Returns:**
- `Result<(Vec<u8>, Vec<u8>)>`: A result containing either a tuple of (ciphertext, nonce) or an error

##### `decrypt`

Decrypts data using XChaCha20Poly1305.

```rust
pub fn decrypt(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>>
```

**Parameters:**
- `key`: The 32-byte encryption key
- `ciphertext`: The encrypted data
- `nonce`: The nonce used during encryption

**Returns:**
- `Result<Vec<u8>>`: A result containing either the decrypted data or an error

**Example:**
```rust
use network_protocol::utils::crypto;

// Generate a random encryption key
let key: [u8; 32] = crypto::generate_random_bytes(32).try_into().unwrap();

// Data to encrypt
let data = b"This is a secret message";

// Encrypt the data
let (ciphertext, nonce) = crypto::encrypt(&key, data).unwrap();
println!("Encrypted data length: {}", ciphertext.len());

// Decrypt the data
let plaintext = crypto::decrypt(&key, &ciphertext, &nonce).unwrap();
let decrypted_text = String::from_utf8(plaintext).unwrap();
println!("Decrypted text: {}", decrypted_text);
```

### Compression

The compression module provides functions for compressing and decompressing data.

#### Functions

##### `compress_lz4`

Compresses data using the LZ4 algorithm.

```rust
pub fn compress_lz4(data: &[u8]) -> Vec<u8>
```

**Parameters:**
- `data`: The data to compress

**Returns:**
- `Vec<u8>`: The compressed data

##### `decompress_lz4`

Decompresses data compressed with the LZ4 algorithm.

```rust
pub fn decompress_lz4(compressed: &[u8], expected_size: usize) -> Result<Vec<u8>>
```

**Parameters:**
- `compressed`: The compressed data
- `expected_size`: The expected size of the decompressed data

**Returns:**
- `Result<Vec<u8>>`: A result containing either the decompressed data or an error

##### `compress_zstd`

Compresses data using the Zstd algorithm.

```rust
pub fn compress_zstd(data: &[u8]) -> Result<Vec<u8>>
```

**Parameters:**
- `data`: The data to compress

**Returns:**
- `Result<Vec<u8>>`: A result containing either the compressed data or an error

##### `decompress_zstd`

Decompresses data compressed with the Zstd algorithm.

```rust
pub fn decompress_zstd(compressed: &[u8]) -> Result<Vec<u8>>
```

**Parameters:**
- `compressed`: The compressed data

**Returns:**
- `Result<Vec<u8>>`: A result containing either the decompressed data or an error

**Example:**
```rust
use network_protocol::utils::compression;

// Original data
let data = b"This is some test data that will be compressed and then decompressed";

// Compress with LZ4
let compressed = compression::compress_lz4(data);
println!("Original size: {}, Compressed size: {}", data.len(), compressed.len());

// Decompress with LZ4
let decompressed = compression::decompress_lz4(&compressed, data.len()).unwrap();
let decompressed_text = String::from_utf8(decompressed).unwrap();
println!("Decompressed text: {}", decompressed_text);

// Compress with Zstd
let zstd_compressed = compression::compress_zstd(data).unwrap();
println!("Zstd compressed size: {}", zstd_compressed.len());

// Decompress with Zstd
let zstd_decompressed = compression::decompress_zstd(&zstd_compressed).unwrap();
let zstd_text = String::from_utf8(zstd_decompressed).unwrap();
println!("Zstd decompressed text: {}", zstd_text);
```

### Time

The time module provides time-related utilities.

#### Functions

##### `get_current_time_ms`

Returns the current system time in milliseconds.

```rust
pub fn get_current_time_ms() -> u64
```

**Returns:**
- `u64`: The current system time in milliseconds since the Unix epoch

##### `duration_since`

Calculates the duration in milliseconds between the current time and a past timestamp.

```rust
pub fn duration_since(past_time_ms: u64) -> u64
```

**Parameters:**
- `past_time_ms`: A timestamp in milliseconds since the Unix epoch

**Returns:**
- `u64`: The duration in milliseconds between the current time and the past timestamp

**Example:**
```rust
use network_protocol::utils::time;
use std::thread::sleep;
use std::time::Duration;

// Get current time
let now = time::get_current_time_ms();
println!("Current time (ms): {}", now);

// Sleep for a short time
sleep(Duration::from_millis(500));

// Calculate duration since the recorded time
let elapsed = time::duration_since(now);
println!("Elapsed time (ms): {}", elapsed);
```

## Error Handling

The error module defines various error types that can occur during network protocol operations.

#### Enum Definition

```rust
pub enum ProtocolError {
    IoError(io::Error),
    SerializationError(bincode::Error),
    InvalidHeader,
    OversizedPacket,
    UnsupportedVersion,
    HandshakeError,
    EncryptionError,
    DecryptionError,
    CompressionError,
    InvalidMessage,
    Timeout,
    Other(String),
}
```

#### Type Aliases

```rust
pub type Result<T> = std::result::Result<T, ProtocolError>;
```

## Configuration

The config module defines constants for protocol configuration.

#### Constants

```rust
// Protocol version - bump this when making breaking changes
pub const PROTOCOL_VERSION: u8 = 1;

// Magic bytes for identifying protocol packets ("NPRO")
pub const MAGIC_BYTES: [u8; 4] = [0x4E, 0x50, 0x52, 0x4F];

// Maximum size of a packet payload in bytes
pub const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024; // 16MB

// Default settings
pub const DEFAULT_COMPRESSION_ENABLED: bool = true;
pub const DEFAULT_ENCRYPTION_ENABLED: bool = true;
```
