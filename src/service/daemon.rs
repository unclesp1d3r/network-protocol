use tokio::net::TcpListener;
use tokio_util::codec::Framed;
use futures::{StreamExt, SinkExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use bincode;

use crate::core::codec::PacketCodec;
use crate::core::packet::Packet;
use crate::protocol::message::Message;
// Import secure handshake functions
use crate::protocol::handshake::{server_secure_handshake_response, server_secure_handshake_finalize, clear_handshake_data};
// Legacy imports (commented out for reference)
// use crate::protocol::handshake::{server_handshake_response, derive_shared_key};
use crate::protocol::dispatcher::Dispatcher;
use crate::service::secure::SecureConnection;
use crate::error::{Result, ProtocolError};

/// Start a secure server and listen for connections
pub async fn start(addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("[daemon] listening on {addr}");

    // 🔁 Shared dispatcher
    let dispatcher = Arc::new({
        let d = Dispatcher::new();
        let _ = d.register("PING", |_| Ok(Message::Pong));
        let _ = d.register("ECHO", |msg| Ok(msg.clone()));
        d
    });
    
    // Track active connections
    let active_connections = Arc::new(Mutex::new(0u32));
    
    // Create shutdown channel
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    
    // Spawn ctrl-c handler
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            println!("[daemon] Received shutdown signal, initiating graceful shutdown");
            let _ = shutdown_tx_clone.send(()).await;
        }
    });
    
    // Server main loop with graceful shutdown
    loop {
        tokio::select! {
            // Check for shutdown signal
            _ = shutdown_rx.recv() => {     
                println!("[daemon] Shutting down server. Waiting for connections to close...");
                
                // Wait for active connections to close (with timeout)
                let timeout = tokio::time::sleep(Duration::from_secs(10));
                tokio::pin!(timeout);
                
                loop {
                    tokio::select! {
                        _ = &mut timeout => {
                            println!("[daemon] Shutdown timeout reached, forcing exit");
                            break;
                        }
                        _ = tokio::time::sleep(Duration::from_millis(500)) => {
                            let connections = *active_connections.lock().await;
                            println!("[daemon] Waiting for {} connection(s) to close", connections);
                            if connections == 0 {
                                println!("[daemon] All connections closed, shutting down");
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
                        println!("[daemon] connection from {peer}");
                        let dispatcher = dispatcher.clone();
                        let active_connections = active_connections.clone();
                        // We don't need this clone if we're not using it in this scope
                        // let _shutdown_tx = shutdown_tx.clone();
                        
                        // Increment active connections counter
                        {
                            let mut count = active_connections.lock().await;
                            *count += 1;
                        }
                        
                        tokio::spawn(async move {
                            handle_connection(stream, peer, dispatcher, active_connections).await;
                        });
                    }
                    Err(e) => {
                        eprintln!("[daemon] Error accepting connection: {e}");
                    }
                }
            }
        }
    }
}

/// Handle a new connection including handshake
async fn handle_connection(
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    dispatcher: Arc<Dispatcher>,
    active_connections: Arc<Mutex<u32>>,
) {
    // Setup the connection with cleanup
    let result = process_connection(stream, peer, dispatcher).await;
    
    // If there was an error, log it
    if let Err(e) = result {
        eprintln!("[daemon] Connection error for {peer}: {e}");
    }
    
    // Always decrement active connections on exit
    {
        let mut count = active_connections.lock().await;
        *count -= 1;
    }
    
    println!("[daemon] disconnected: {peer}");
}

/// Process a connection with proper error handling
async fn process_connection(
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    dispatcher: Arc<Dispatcher>,
) -> Result<()> {
    let mut framed = Framed::new(stream, PacketCodec);

    // --- Expect Secure Handshake Init ---
    let init = match framed.next().await {
        Some(Ok(pkt)) => bincode::deserialize::<Message>(&pkt.payload)
            .map_err(|e| ProtocolError::DeserializeError(e.to_string()))?,
        Some(Err(e)) => return Err(ProtocolError::TransportError(e.to_string())),
        None => return Err(ProtocolError::ConnectionClosed),
    };

    // Extract the client's handshake init data
    let (client_pub_key, client_timestamp, client_nonce) = match init {
        Message::SecureHandshakeInit { pub_key, timestamp, nonce } => {
            (pub_key, timestamp, nonce)
        },
        _ => return Err(ProtocolError::HandshakeError("Unexpected message type".to_string())),
    };

    // --- Send Secure Handshake Response ---
    let response = server_secure_handshake_response(client_pub_key, client_nonce, client_timestamp)?;
    
    let response_bytes = bincode::serialize(&response)
        .map_err(|e| ProtocolError::SerializeError(e.to_string()))?;
        
    framed.send(Packet { version: 1, payload: response_bytes }).await
        .map_err(|e| ProtocolError::TransportError(e.to_string()))?;
    
    // --- Expect Handshake Confirmation ---
    let confirm = match framed.next().await {
        Some(Ok(pkt)) => bincode::deserialize::<Message>(&pkt.payload)
            .map_err(|e| ProtocolError::DeserializeError(e.to_string()))?,
        Some(Err(e)) => return Err(ProtocolError::TransportError(e.to_string())),
        None => return Err(ProtocolError::ConnectionClosed),
    };
    
    let nonce_verification = match confirm {
        Message::SecureHandshakeConfirm { nonce_verification } => nonce_verification,
        _ => return Err(ProtocolError::HandshakeError("Expected handshake confirmation".to_string())),
    };
    
    // --- Finalize Handshake and Derive Session Key ---
    let session_key = server_secure_handshake_finalize(nonce_verification)?;
    
    // Clear sensitive handshake data from memory
    let _ = clear_handshake_data();
    
    // Create secure connection with derived key
    let conn = SecureConnection::new(framed, session_key);
    
    // Handle the secure message loop
    handle_secure_connection(conn, dispatcher, peer).await?;
    
    Ok(())
}

/// Handle a secure connection after handshake
async fn handle_secure_connection(
    mut conn: SecureConnection,
    dispatcher: Arc<Dispatcher>,
    peer: std::net::SocketAddr
) -> Result<()> {
    // --- Secure Message Loop ---
    loop {
        let msg: Message = conn.secure_recv().await?;
        
        println!("[daemon] received from {peer}: {msg:?}");
        
        // Check for disconnect message
        if matches!(msg, Message::Disconnect) {
            println!("[daemon] received disconnect request from {peer}");
            break;
        }

        let reply = dispatcher.dispatch(&msg)?;
        conn.secure_send(reply).await?;
    }

    Ok(())
}
