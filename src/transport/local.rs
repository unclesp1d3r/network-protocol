#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio_util::codec::Framed;
use futures::{StreamExt, SinkExt};
#[cfg(unix)]
use std::path::Path;

use crate::core::codec::PacketCodec;
use crate::core::packet::Packet;
use crate::error::{Result, ProtocolError};
#[cfg(windows)]
use tokio::net::{TcpListener, TcpStream};
#[cfg(windows)]
use std::net::SocketAddr;

/// Start a local server for IPC
/// 
/// On Unix systems, this uses Unix Domain Sockets
/// On Windows, this falls back to TCP localhost connections
#[cfg(unix)]
pub async fn start_server<P: AsRef<Path>>(path: P) -> Result<()> {
    if path.as_ref().exists() {
        tokio::fs::remove_file(&path).await.ok();
    }

    let listener = UnixListener::bind(path)?;
    println!("[local] listening on unix socket...");

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut framed = Framed::new(stream, PacketCodec);

            while let Some(Ok(packet)) = framed.next().await {
                println!("[local] recv: {} bytes", packet.payload.len());

                // Echo it back
                let _ = framed.send(packet).await;
            }
        });
    }
}

/// Windows implementation using TCP on localhost instead of Unix sockets
#[cfg(windows)]
pub async fn start_server<S: AsRef<str>>(path: S) -> Result<()> {
    // On Windows, interpret the path as a port number on localhost
    // Extract just the port number or use a default
    let addr = format!("127.0.0.1:{}", extract_port_or_default(path.as_ref()));
    
    let listener = TcpListener::bind(&addr).await?;
    println!("[local] listening on {addr} (Windows compatibility mode)");

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut framed = Framed::new(stream, PacketCodec);

            while let Some(Ok(packet)) = framed.next().await {
                println!("[local] recv: {} bytes", packet.payload.len());

                // Echo it back
                let _ = framed.send(packet).await;
            }
        });
    }
}

/// Connect to a local IPC socket
/// 
/// On Unix systems, this uses Unix Domain Sockets
/// On Windows, this falls back to TCP localhost connections
#[cfg(unix)]
pub async fn connect<P: AsRef<Path>>(path: P) -> Result<Framed<UnixStream, PacketCodec>> {
    let stream = UnixStream::connect(path).await?;
    Ok(Framed::new(stream, PacketCodec))
}

#[cfg(windows)]
pub async fn connect<S: AsRef<str>>(path: S) -> Result<Framed<TcpStream, PacketCodec>> {
    // On Windows, interpret the path as a port number on localhost
    let addr = format!("127.0.0.1:{}", extract_port_or_default(path.as_ref()));
    
    let stream = TcpStream::connect(&addr).await?;
    Ok(Framed::new(stream, PacketCodec))
}

#[cfg(windows)]
fn extract_port_or_default(path: &str) -> u16 {
    // Try to extract a port number from the path string
    // Default to 8080 if we can't parse anything
    path.split('/').last()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(8080)
}
