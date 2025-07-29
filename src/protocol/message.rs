use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[repr(u8)]
pub enum Message {
    Ping,
    Pong,

    /// Optional handshake request/response types
    HandshakeInit { client_nonce: u64 },
    HandshakeAck { server_nonce: u64 },

    // Placeholder for custom commands:
    Echo(String),
    Disconnect,

    #[serde(other)]
    Unknown,
}
