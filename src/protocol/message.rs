use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[repr(u8)]
pub enum Message {
    Ping,
    Pong,

    /// Legacy handshake types (deprecated)
    #[deprecated(note = "Use SecureHandshakeInit instead")]
    HandshakeInit { client_nonce: u64 },
    #[deprecated(note = "Use SecureHandshakeResponse instead")]
    HandshakeAck { server_nonce: u64 },

    /// Secure handshake using ECDH key exchange
    /// Client initiates with its public key and a timestamp to prevent replay attacks
    SecureHandshakeInit {
        /// Client's public key for ECDH exchange
        pub_key: [u8; 32],
        /// Timestamp to prevent replay attacks
        timestamp: u64,
        /// Random nonce for additional security
        nonce: [u8; 16],
    },
    
    /// Server responds with its public key and a signature
    SecureHandshakeResponse {
        /// Server's public key for ECDH exchange
        pub_key: [u8; 32],
        /// Server's nonce (different from client nonce)
        nonce: [u8; 16],
        /// Hash of the client's nonce to prove receipt
        nonce_verification: [u8; 32],
    },
    
    /// Final handshake confirmation from client
    SecureHandshakeConfirm {
        /// Hash of server's nonce to prove receipt
        nonce_verification: [u8; 32],
    },

    // Placeholder for custom commands:
    Echo(String),
    Disconnect,

    #[serde(other)]
    Unknown,
}
