use crate::core::packet::Packet;
use crate::utils::crypto::Crypto;
use crate::error::{Result, ProtocolError};

use tokio_util::codec::Framed;
use tokio::net::TcpStream;
use futures::{SinkExt, StreamExt};

pub struct SecureConnection {
    framed: Framed<TcpStream, crate::core::codec::PacketCodec>,
    crypto: Crypto,
}

impl SecureConnection {
    pub fn new(framed: Framed<TcpStream, crate::core::codec::PacketCodec>, key: [u8; 32]) -> Self {
        Self {
            framed,
            crypto: Crypto::new(&key),
        }
    }

    pub async fn secure_send(&mut self, msg: impl serde::Serialize) -> Result<()> {
        let data = bincode::serialize(&msg)?;
        let nonce = Crypto::generate_nonce();
        let ciphertext = self.crypto.encrypt(&data, &nonce)?;

        let mut final_payload = nonce.to_vec();
        final_payload.extend(ciphertext);

        self.framed.send(Packet {
            version: 1,
            payload: final_payload,
        }).await?;

        Ok(())
    }

    pub async fn secure_recv<T: serde::de::DeserializeOwned>(&mut self) -> Result<T> {
        let pkt = self.framed.next().await.ok_or(ProtocolError::Timeout)??;

        if pkt.payload.len() < 24 {
            return Err(ProtocolError::DecryptionFailure);
        }

        let (nonce_bytes, ciphertext) = pkt.payload.split_at(24);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(nonce_bytes);

        let plaintext = self.crypto.decrypt(ciphertext, &nonce)?;
        let msg = bincode::deserialize(&plaintext)?;
        Ok(msg)
    }
}
