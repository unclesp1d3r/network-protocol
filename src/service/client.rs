//use tokio_util::codec::Framed;
//use tokio::net::TcpStream;
use futures::{SinkExt, StreamExt};

use crate::core::packet::Packet;
//use crate::core::codec::PacketCodec;
use crate::protocol::message::Message;
// Import secure handshake functions
use crate::protocol::handshake::{client_secure_handshake_init, client_secure_handshake_verify, client_derive_session_key};
// Keep deprecated imports for reference but commented out
// use crate::protocol::handshake::{client_handshake_init, verify_server_ack, derive_shared_key};
use crate::service::secure::SecureConnection;
use crate::transport::remote;
use crate::error::{Result, ProtocolError};

/// High-level protocol client with post-handshake encryption
pub struct Client {
    conn: SecureConnection,
}

impl Client {
    /// Connect and perform secure handshake
    pub async fn connect(addr: &str) -> Result<Self> {
        let mut framed = remote::connect(addr).await?;
        
        // --- Legacy Handshake Support ---
        // Commented out legacy code for reference
        // #[allow(deprecated)]
        // async fn legacy_handshake(framed: &mut remote::RemoteFramed) -> Result<[u8; 32]> {
        //     // Legacy handshake process
        //     let (client_nonce, handshake) = client_handshake_init();
        //     
        //     let handshake_bytes = bincode::serialize(&handshake)?;
        //     framed.send(Packet {
        //         version: 1,
        //         payload: handshake_bytes,
        //     }).await?;
        //     
        //     let packet = framed.next().await.ok_or(ProtocolError::Timeout)??;
        //     let ack: Message = bincode::deserialize(&packet.payload)?;
        //     match ack {
        //         Message::HandshakeAck { server_nonce } => {
        //             if !verify_server_ack(server_nonce, client_nonce) {
        //                 return Err(ProtocolError::HandshakeError("Invalid handshake ack".into()));
        //             }
        //         }
        //         _ => return Err(ProtocolError::UnexpectedMessage),
        //     }
        //     
        //     Ok(derive_shared_key(client_nonce))
        // }
        
        // --- Secure Handshake Process ---
        // Step 1: Send client init with public key, nonce, and timestamp
        let init_msg = client_secure_handshake_init();
        let init_bytes = bincode::serialize(&init_msg)?;
        framed.send(Packet {
            version: 1,
            payload: init_bytes,
        }).await?;
        
        // Step 2: Receive server response
        let packet = framed.next().await.ok_or(ProtocolError::Timeout)??;
        let response: Message = bincode::deserialize(&packet.payload)?;
        
        // Step 3: Verify server response and send confirmation
        // Extract data from server response
        let (server_pub_key, server_nonce, nonce_verification) = match response {
            Message::SecureHandshakeResponse { pub_key, nonce, nonce_verification } => {
                (pub_key, nonce, nonce_verification)
            },
            _ => return Err(ProtocolError::HandshakeError("Invalid server response message type".into())),
        };
        
        // Verify the server's response and prepare confirmation message
        let verify_msg = client_secure_handshake_verify(server_pub_key, server_nonce, nonce_verification)?;
        
        let verify_bytes = bincode::serialize(&verify_msg)?;
        framed.send(Packet {
            version: 1,
            payload: verify_bytes,
        }).await?;
        
        // Step 4: Derive shared session key
        let key = client_derive_session_key()?;
        let conn = SecureConnection::new(framed, key);
        
        Ok(Self { conn })
    }

    /// Securely send a message
    pub async fn send(&mut self, msg: Message) -> Result<()> {
        self.conn.secure_send(msg).await
    }

    /// Securely receive a message
    pub async fn recv(&mut self) -> Result<Message> {
        self.conn.secure_recv().await
    }

    /// Send a message and wait for a response
    pub async fn send_and_wait(&mut self, msg: Message) -> Result<Message> {
        self.send(msg).await?;
        self.recv().await
    }
}
