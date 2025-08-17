use tokio::net::TcpListener;
use tokio_util::codec::Framed;
use futures::{StreamExt, SinkExt};
use std::sync::Arc;

use crate::core::codec::PacketCodec;
use crate::core::packet::Packet;
use crate::protocol::message::Message;
// Import secure handshake functions
use crate::protocol::handshake::{server_secure_handshake_response, server_secure_handshake_finalize, clear_handshake_data};
// Legacy imports (commented out for reference)
// use crate::protocol::handshake::{server_handshake_response, derive_shared_key};
use crate::protocol::dispatcher::Dispatcher;
use crate::service::secure::SecureConnection;
use crate::error::Result;

/// Start a secure server and listen for connections
pub async fn start(addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("[daemon] listening on {addr}");

    // 🔁 Shared dispatcher
    let dispatcher = Arc::new({
        let d = Dispatcher::new();
        d.register("PING", |_| Ok(Message::Pong));
        d.register("ECHO", |msg| Ok(msg.clone()));
        d
    });

    loop {
        let (stream, peer) = listener.accept().await?;
        println!("[daemon] connection from {peer}");
        let dispatcher = dispatcher.clone();

        tokio::spawn(async move {
            let mut framed = Framed::new(stream, PacketCodec);

            // --- Expect Secure Handshake Init ---
            let init = match framed.next().await {
                Some(Ok(pkt)) => bincode::deserialize::<Message>(&pkt.payload),
                _ => return,
            };

            // Extract the client's handshake init data
            let (client_pub_key, client_timestamp, client_nonce) = match &init {
                Ok(Message::SecureHandshakeInit { pub_key, timestamp, nonce }) => {
                    (*pub_key, *timestamp, *nonce)
                },
                _ => {
                    eprintln!("[daemon] Received unsupported handshake message type");
                    return;
                },
            };

            // --- Send Secure Handshake Response ---
            let response = match server_secure_handshake_response(client_pub_key, client_nonce, client_timestamp) {
                Ok(msg) => msg,
                Err(e) => {
                    eprintln!("[daemon] handshake error: {e}");
                    return;
                }
            };
            
            let response_bytes = bincode::serialize(&response).unwrap();
            let _ = framed.send(Packet { version: 1, payload: response_bytes }).await;
            
            // --- Expect Handshake Confirmation ---
            let confirm = match framed.next().await {
                Some(Ok(pkt)) => bincode::deserialize::<Message>(&pkt.payload),
                _ => return,
            };
            
            let nonce_verification = match &confirm {
                Ok(Message::SecureHandshakeConfirm { nonce_verification }) => {
                    *nonce_verification
                },
                _ => {
                    eprintln!("[daemon] expected handshake confirmation but got something else");
                    return;
                }
            };
            
            // --- Finalize Handshake and Derive Session Key ---
            let session_key = match server_secure_handshake_finalize(nonce_verification) {
                Ok(key) => key,
                Err(e) => {
                    eprintln!("[daemon] handshake finalization failed: {e}");
                    return;
                }
            };
            
            // Clear sensitive handshake data from memory
            clear_handshake_data();
            
            // Create secure connection with derived key
            let conn = SecureConnection::new(framed, session_key);
            
            // Handle the secure message loop
            handle_secure_connection(conn, dispatcher, peer).await;
        });
    }
}

/// Handle a secure connection after handshake
async fn handle_secure_connection(
    mut conn: SecureConnection,
    dispatcher: Arc<Dispatcher>,
    peer: std::net::SocketAddr
) {
    // --- Secure Message Loop ---
    loop {
        let msg: Message = match conn.secure_recv().await {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[daemon] recv error from {peer}: {e}");
                break;
            }
        };

        println!("[daemon] received from {peer}: {msg:?}");

        match dispatcher.dispatch(&msg) {
            Ok(reply) => {
                if let Err(e) = conn.secure_send(reply).await {
                    eprintln!("[daemon] send error: {e}");
                    break;
                }
            }
            Err(e) => {
                eprintln!("[daemon] dispatch error: {e}");
                break;
            }
        }
    }

    println!("[daemon] disconnected: {peer}");
}
