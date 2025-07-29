//use tokio_util::codec::Framed;
//use tokio::net::TcpStream;
use futures::{SinkExt, StreamExt};

use crate::core::packet::Packet;
//use crate::core::codec::PacketCodec;
use crate::protocol::message::Message;
use crate::protocol::handshake::{client_handshake_init, verify_server_ack, derive_shared_key};
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

        // --- Unencrypted Handshake Init ---
        let handshake = client_handshake_init();
        let client_nonce = match handshake {
            Message::HandshakeInit { client_nonce } => client_nonce,
            _ => unreachable!(),
        };

        let handshake_bytes = bincode::serialize(&handshake)?;
        framed.send(Packet {
            version: 1,
            payload: handshake_bytes,
        }).await?;

        // --- Expect Handshake Ack ---
        let packet = framed.next().await.ok_or(ProtocolError::Timeout)??;
        let ack: Message = bincode::deserialize(&packet.payload)?;
        match ack {
            Message::HandshakeAck { server_nonce } => {
                if !verify_server_ack(server_nonce, client_nonce) {
                    return Err(ProtocolError::HandshakeError("Invalid handshake ack".into()));
                }
            }
            _ => return Err(ProtocolError::UnexpectedMessage),
        }

        // --- Derive shared key, wrap connection ---
        let key = derive_shared_key(client_nonce);
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
