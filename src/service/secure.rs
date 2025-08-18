use crate::core::packet::Packet;
use crate::utils::crypto::Crypto;
use crate::error::{Result, ProtocolError};
use crate::utils::timeout::{with_timeout_error, DEFAULT_TIMEOUT};

use tokio_util::codec::Framed;
use tokio::net::TcpStream;
use futures::{SinkExt, StreamExt};
use std::time::Duration;
use tracing::{debug, instrument};

pub struct SecureConnection {
    framed: Framed<TcpStream, crate::core::codec::PacketCodec>,
    crypto: Crypto,
    send_timeout: Duration,
    recv_timeout: Duration,
    last_activity: std::time::Instant,
}

impl SecureConnection {
    pub fn new(framed: Framed<TcpStream, crate::core::codec::PacketCodec>, key: [u8; 32]) -> Self {
        Self {
            framed,
            crypto: Crypto::new(&key),
            send_timeout: DEFAULT_TIMEOUT,
            recv_timeout: DEFAULT_TIMEOUT,
            last_activity: std::time::Instant::now(),
        }
    }
    
    /// Set custom timeout durations
    pub fn with_timeouts(mut self, send_timeout: Duration, recv_timeout: Duration) -> Self {
        self.send_timeout = send_timeout;
        self.recv_timeout = recv_timeout;
        self
    }
    
    /// Get the time since the last activity (send or receive)
    pub fn time_since_last_activity(&self) -> Duration {
        self.last_activity.elapsed()
    }
    
    /// Update the last activity timestamp
    fn update_activity(&mut self) {
        self.last_activity = std::time::Instant::now();
    }

    #[instrument(skip(self, msg), level = "debug")]
    pub async fn secure_send(&mut self, msg: impl serde::Serialize) -> Result<()> {
        let data = bincode::serialize(&msg)?;
        let nonce = Crypto::generate_nonce();
        let ciphertext = self.crypto.encrypt(&data, &nonce)?;

        let mut final_payload = nonce.to_vec();
        final_payload.extend(ciphertext);

        let packet = Packet {
            version: 1,
            payload: final_payload,
        };
        
        debug!(timeout_ms = ?self.send_timeout.as_millis(), "Sending packet with timeout");
        
        with_timeout_error(
            async {
                self.framed.send(packet).await?;
                Ok(())
            },
            self.send_timeout
        ).await?;
        
        self.update_activity();
        Ok(())
    }

    #[instrument(skip(self), level = "debug")]
    pub async fn secure_recv<T: serde::de::DeserializeOwned>(&mut self) -> Result<T> {
        debug!(timeout_ms = ?self.recv_timeout.as_millis(), "Receiving packet with timeout");
        
        let pkt = with_timeout_error(
            async {
                let pkt = self.framed.next().await
                    .ok_or(ProtocolError::ConnectionClosed)??;
                Ok(pkt)
            },
            self.recv_timeout
        ).await?;

        if pkt.payload.len() < 24 {
            return Err(ProtocolError::DecryptionFailure);
        }

        let (nonce_bytes, ciphertext) = pkt.payload.split_at(24);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(nonce_bytes);

        let plaintext = self.crypto.decrypt(ciphertext, &nonce)?;
        let msg = bincode::deserialize(&plaintext)?;
        
        self.update_activity();
        Ok(msg)
    }
}
