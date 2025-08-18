use tokio::net::TcpListener;
use tokio_util::codec::Framed;
use futures::{StreamExt, SinkExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, oneshot};
use tokio::time;
use bincode;
use tracing::{info, debug, warn, error, instrument};

use crate::utils::timeout::{with_timeout_error, HANDSHAKE_TIMEOUT, SHUTDOWN_TIMEOUT};

use crate::core::codec::PacketCodec;
use crate::core::packet::Packet;
use crate::protocol::message::Message;
// Import secure handshake functions
use crate::protocol::handshake::{server_secure_handshake_response, server_secure_handshake_finalize, clear_handshake_data};
use crate::protocol::dispatcher::Dispatcher;
use crate::protocol::keepalive::KeepAliveManager;
use crate::protocol::heartbeat::{build_ping, is_pong};
use crate::service::secure::SecureConnection;
use crate::error::{Result, ProtocolError};

/// Start a secure server and listen for connections
#[instrument(skip(addr), fields(address = %addr))]
pub async fn start(addr: &str) -> Result<()> {
    // Create a never-resolving shutdown receiver for standard operation
    let (_, shutdown_rx) = oneshot::channel::<()>();
    start_with_shutdown(addr, shutdown_rx).await
}

/// Start a secure server with shutdown control for testing
#[instrument(skip(addr, shutdown_rx), fields(address = %addr))]
pub async fn start_with_shutdown(
    addr: &str,
    shutdown_rx: oneshot::Receiver<()>
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(address = %addr, "Server listening");

    // Shared dispatcher
    let dispatcher = Arc::new(Dispatcher::new());
    
    // Register default handlers
    register_default_handlers(&dispatcher)?;
    
    // Track active connections for graceful shutdown
    let active_connections = Arc::new(Mutex::new(0u32));
    
    // Create a shutdown channel for CTRL+C
    let (shutdown_tx, mut internal_shutdown_rx) = mpsc::channel::<()>(1);
    
    // Set up a Ctrl+C handler to initiate graceful shutdown
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                info!("Shutdown signal received");
                let _ = shutdown_tx_clone.send(()).await;
            },
            Err(err) => {
                error!(error = %err, "Failed to listen for shutdown signal");
            },
        }
    });
    
    // Also set up the oneshot receiver to trigger shutdown
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        if shutdown_rx.await.is_ok() {
            info!("External shutdown signal received");
            let _ = shutdown_tx_clone.send(()).await;
        }
    });
    
    // Server main loop with graceful shutdown
    loop {
        tokio::select! {
            // Check for shutdown signal
            _ = internal_shutdown_rx.recv() => {     
                info!("Shutting down server. Waiting for connections to close...");
                
                // Wait for active connections to close (with timeout)
                let timeout = tokio::time::sleep(SHUTDOWN_TIMEOUT);
                tokio::pin!(timeout);
                
                loop {
                    tokio::select! {
                        _ = &mut timeout => {
                            warn!("Shutdown timeout reached, forcing exit");
                            break;
                        }
                        _ = tokio::time::sleep(Duration::from_millis(500)) => {
                            let connections = *active_connections.lock().await;
                            info!(connections = %connections, "Waiting for connections to close");
                            if connections == 0 {
                                info!("All connections closed, shutting down");
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
                        info!(peer = %peer, "New connection established");
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
                        error!(error = %e, "Error accepting connection");
                    }
                }
            }
        }
    }
}

/// Handle a new connection including handshake
#[instrument(skip(stream, dispatcher, active_connections), fields(peer = %peer))]
async fn handle_connection(
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    dispatcher: Arc<Dispatcher>,
    active_connections: Arc<Mutex<u32>>,
) {
    // Setup the connection with cleanup
    let result = with_timeout_error(
        async {
            process_connection(stream, peer, dispatcher).await
        },
        HANDSHAKE_TIMEOUT
    ).await;
    
    // If there was an error, log it
    match result {
        Ok(_) => info!("Connection closed gracefully"),
        Err(ProtocolError::Timeout) => warn!("Connection timed out"),
        Err(e) => error!(error = %e, "Connection error"),
    }
    
    // Always decrement active connections on exit
    {
        let mut count = active_connections.lock().await;
        *count -= 1;
    }
    
    info!("Client disconnected");
}

/// Process a connection with proper error handling
#[instrument(skip(stream, dispatcher), fields(peer = %peer))]
async fn process_connection(
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    dispatcher: Arc<Dispatcher>,
) -> Result<()> {
    let mut framed = Framed::new(stream, PacketCodec);

    // --- Expect Secure Handshake Init (with timeout) ---
    let init = with_timeout_error(
        async {
            match framed.next().await {
                Some(Ok(pkt)) => bincode::deserialize::<Message>(&pkt.payload)
                    .map_err(|e| ProtocolError::DeserializeError(e.to_string())),
                Some(Err(e)) => Err(ProtocolError::TransportError(e.to_string())),
                None => Err(ProtocolError::ConnectionClosed),
            }
        },
        HANDSHAKE_TIMEOUT
    ).await?;

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
    
    // --- Expect Handshake Confirmation (with timeout) ---
    let confirm = with_timeout_error(
        async {
            match framed.next().await {
                Some(Ok(pkt)) => bincode::deserialize::<Message>(&pkt.payload)
                    .map_err(|e| ProtocolError::DeserializeError(e.to_string())),
                Some(Err(e)) => Err(ProtocolError::TransportError(e.to_string())),
                None => Err(ProtocolError::ConnectionClosed),
            }
        },
        HANDSHAKE_TIMEOUT
    ).await?;
    
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

/// Register default message handlers
#[instrument(skip(dispatcher))]
fn register_default_handlers(dispatcher: &Arc<Dispatcher>) -> Result<()> {
    // Handle Ping messages
    dispatcher.register("PING", |_| {
        debug!("Responding to ping with pong");
        Ok(Message::Pong)
    })?;
    
    // Handle Echo messages
    dispatcher.register("ECHO", |msg| {
        if let Message::Echo(text) = msg {
            debug!(text = %text, "Echoing message");
            Ok(Message::Echo(text.clone()))
        } else {
            Err(ProtocolError::Custom("Invalid Echo message format".to_string()))
        }
    })?;
    
    Ok(())
}

/// Handle a secure connection after handshake
#[instrument(skip(conn, dispatcher), fields(peer = %peer))]
async fn handle_secure_connection(
    mut conn: SecureConnection,
    dispatcher: Arc<Dispatcher>,
    peer: std::net::SocketAddr
) -> Result<()> {
    // --- Initialize Keep-Alive Manager ---
    let mut keep_alive = KeepAliveManager::new();
    let mut ping_interval = time::interval(keep_alive.ping_interval());
    
    // --- Secure Message Loop ---
    loop {
        tokio::select! {
            // Check if we need to send a ping
            _ = ping_interval.tick() => {
                if keep_alive.should_ping() {
                    debug!("Sending keep-alive ping");
                    let ping = build_ping();
                    conn.secure_send(ping).await?;
                    keep_alive.update_send();
                }
                
                // Check if connection is dead
                if keep_alive.is_connection_dead() {
                    warn!(dead_seconds = ?keep_alive.time_since_last_recv().as_secs(), 
                          "Connection appears dead, closing");
                    return Err(ProtocolError::ConnectionTimeout);
                }
            }
            
            // Try to receive a message
            recv_result = conn.secure_recv::<Message>() => {
                match recv_result {
                    Ok(msg) => {
                        debug!(message = ?msg, "Received message");
                        keep_alive.update_recv();
                        
                        // Check for disconnect message
                        if matches!(msg, Message::Disconnect) {
                            info!("Received disconnect request");
                            return Ok(());
                        }
                        
                        // Special handling for pong messages
                        if is_pong(&msg) {
                            debug!("Received pong response");
                            continue;
                        }
                        
                        // Process normal messages
                        let reply = dispatcher.dispatch(&msg)?;
                        conn.secure_send(reply).await?;
                        keep_alive.update_send();
                    }
                    Err(ProtocolError::Timeout) => {
                        // Timeout is expected, just continue the loop
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }
}
