use tokio_rustls::server::TlsStream;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;
use futures::{StreamExt, SinkExt};
use std::sync::Arc;

use crate::core::codec::PacketCodec;
use crate::core::packet::Packet;
use crate::protocol::message::Message;
use crate::protocol::dispatcher::Dispatcher;
// Secure connection not needed since TLS handles encryption
use crate::transport::tls::TlsServerConfig;
use crate::error::Result;

/// Start a secure TLS server and listen for connections
pub async fn start(addr: &str, tls_config: TlsServerConfig) -> Result<()> {
    let config = tls_config.load_server_config()?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    
    let listener = TcpListener::bind(addr).await?;
    println!("[tls_daemon] listening on {addr}");

    // 🔁 Shared dispatcher
    let dispatcher = Arc::new({
        let d = Dispatcher::new();
        let _ = d.register("PING", |_| Ok(Message::Pong));
        let _ = d.register("ECHO", |msg| Ok(msg.clone()));
        d
    });

    loop {
        let (stream, peer) = listener.accept().await?;
        println!("[tls_daemon] connection from {peer}");
        let dispatcher = dispatcher.clone();
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(e) = handle_tls_connection(tls_stream, dispatcher, peer).await {
                        eprintln!("[tls_daemon] connection error: {e}");
                    }
                },
                Err(e) => {
                    eprintln!("[tls_daemon] TLS handshake failed: {e}");
                }
            }
        });
    }
}

/// Handle a TLS connection
async fn handle_tls_connection(
    tls_stream: TlsStream<TcpStream>,
    dispatcher: Arc<Dispatcher>,
    peer: std::net::SocketAddr
) -> Result<()> {
    let mut framed = Framed::new(tls_stream, PacketCodec);
    
    println!("[tls_daemon] TLS connected: {peer}");
    
    // Unlike regular daemon, we don't need a separate handshake
    // TLS already provides the encryption layer
    
    // Message loop
    loop {
        let packet = match framed.next().await {
            Some(Ok(pkt)) => pkt,
            Some(Err(e)) => {
                eprintln!("[tls_daemon] protocol error: {e}");
                break;
            },
            None => break,
        };
        
        // Deserialize the message
        let msg = match bincode::deserialize::<Message>(&packet.payload) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[tls_daemon] deserialization error: {e}");
                continue;
            }
        };
        
        println!("[tls_daemon] received from {peer}: {msg:?}");
        
        // Process with dispatcher
        match dispatcher.dispatch(&msg) {
            Ok(reply) => {
                let reply_bytes = match bincode::serialize(&reply) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        eprintln!("[tls_daemon] serialization error: {e}");
                        continue;
                    }
                };
                
                let reply_packet = Packet {
                    version: packet.version,
                    payload: reply_bytes,
                };
                
                if let Err(e) = framed.send(reply_packet).await {
                    eprintln!("[tls_daemon] send error: {e}");
                    break;
                }
            },
            Err(e) => {
                eprintln!("[tls_daemon] dispatch error: {e}");
                break;
            }
        }
    }
    
    println!("[tls_daemon] disconnected: {peer}");
    Ok(())
}
