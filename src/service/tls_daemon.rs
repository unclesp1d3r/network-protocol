use tokio_rustls::server::TlsStream;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;
use futures::{StreamExt, SinkExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};

use crate::core::codec::PacketCodec;
use crate::core::packet::Packet;
use crate::protocol::message::Message;
use crate::protocol::dispatcher::Dispatcher;
// Secure connection not needed since TLS handles encryption
use crate::transport::tls::TlsServerConfig;
use crate::error::Result;

/// Start a secure TLS server and listen for connections
pub async fn start(addr: &str, tls_config: TlsServerConfig) -> Result<()> {
    // Create shutdown channel
    let (_, shutdown_rx) = mpsc::channel::<()>(1);
    
    // Start with internal shutdown channel
    start_with_shutdown(addr, tls_config, shutdown_rx).await
}

/// Start a secure TLS server with an external shutdown channel
pub async fn start_with_shutdown(addr: &str, tls_config: TlsServerConfig, mut shutdown_rx: mpsc::Receiver<()>) -> Result<()> {
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
    
    // Track active connections
    let active_connections = Arc::new(Mutex::new(0u32));
    
    // Spawn ctrl-c handler to forward to the provided shutdown channel
    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            println!("[tls_daemon] Received shutdown signal, initiating graceful shutdown");
        }
    });
    
    // Server main loop with graceful shutdown
    loop {
        tokio::select! {
            // Check for shutdown signal
            _ = shutdown_rx.recv() => {     
                println!("[tls_daemon] Shutting down server. Waiting for connections to close...");
                
                // Wait for active connections to close (with timeout)
                let timeout = tokio::time::sleep(Duration::from_secs(10));
                tokio::pin!(timeout);
                
                loop {
                    tokio::select! {
                        _ = &mut timeout => {
                            println!("[tls_daemon] Shutdown timeout reached, forcing exit");
                            break;
                        }
                        _ = tokio::time::sleep(Duration::from_millis(500)) => {
                            let connections = *active_connections.lock().await;
                            println!("[tls_daemon] Waiting for {connections} connection(s) to close");
                            if connections == 0 {
                                println!("[tls_daemon] All connections closed, shutting down");
                                break;
                            }
                        }
                    }
                }
                
                return Ok(());
            }
            
            // Accept new connections
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, peer)) => {
                        println!("[tls_daemon] connection from {peer}");
                        let dispatcher = dispatcher.clone();
                        let acceptor = acceptor.clone();
                        let active_connections = active_connections.clone();
                        
                        // Increment active connections counter
                        {
                            let mut count = active_connections.lock().await;
                            *count += 1;
                        }
                        
                        tokio::spawn(async move {
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    if let Err(e) = handle_tls_connection(tls_stream, dispatcher, peer, active_connections).await {
                                        eprintln!("[tls_daemon] connection error: {e}");
                                    }
                                },
                                Err(e) => {
                                    eprintln!("[tls_daemon] TLS handshake failed: {e}");
                                    // Decrement connections on handshake failure
                                    let mut count = active_connections.lock().await;
                                    *count -= 1;
                                }
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("[tls_daemon] Error accepting connection: {e}");
                    }
                }
            }
        }
    }
}

/// Handle a TLS connection
async fn handle_tls_connection(
    tls_stream: TlsStream<TcpStream>,
    dispatcher: Arc<Dispatcher>,
    peer: std::net::SocketAddr,
    active_connections: Arc<Mutex<u32>>
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
    
    // Decrement connection counter on disconnect
    {
        let mut count = active_connections.lock().await;
        *count -= 1;
    }
    
    Ok(())
}
