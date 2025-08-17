use tokio::net::TcpListener;
use tokio_util::codec::Framed;
use futures::{StreamExt, SinkExt};
use std::sync::Arc;

use crate::core::codec::PacketCodec;
use crate::core::packet::Packet;
use crate::protocol::message::Message;
use crate::protocol::handshake::{server_handshake_response, derive_shared_key};
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

            // --- Expect Handshake Init ---
            let init = match framed.next().await {
                Some(Ok(pkt)) => bincode::deserialize::<Message>(&pkt.payload),
                _ => return,
            };

            let client_nonce = match init {
                Ok(Message::HandshakeInit { client_nonce }) => client_nonce,
                _ => return,
            };

            // --- Send Handshake Ack ---
            let ack = server_handshake_response(client_nonce);
            let ack_bytes = bincode::serialize(&ack).unwrap();
            let ack_packet = Packet { version: 1, payload: ack_bytes };
            let _ = framed.send(ack_packet).await;

            // --- Derive Key + Wrap as SecureConnection ---
            let key = derive_shared_key(client_nonce);
            let mut conn = SecureConnection::new(framed, key);

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
        });
    }
}
