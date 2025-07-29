//! # Remote Transport Layer
//! 
//! This file is part of the Network Protocol project.
//!
//! It defines the remote transport layer for network communication,
//! including TCP-based client-server interactions.
//!
//! The remote transport layer is responsible for handling the actual data transmission
//! between nodes in a network, ensuring that packets are sent and received correctly.
//! 
//! It abstracts the underlying network details,
//! allowing higher-level protocol logic to focus on message routing and processing.
//! 
//! The remote transport layer is designed to be modular and extensible,
//! supporting various transport mechanisms such as TCP, UDP, and custom protocols.
//! 
//! ## Responsibilities
//! - Send and receive packets over the network
//! - Handle connection management
//! - Provide a unified interface for different transport protocols
//! 
//! This module is essential for processing protocol packets in a networked environment,
//! ensuring correct parsing and serialization.
//! 
//! It is designed to be efficient, minimal, and easy to integrate into the protocol layer.
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;
use crate::core::codec::PacketCodec;
use crate::core::packet::Packet;
use crate::error::Result;
use futures::StreamExt;
use futures::SinkExt;
use std::net::SocketAddr;

/// Starts a TCP server at the given address
pub async fn start_server(addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;

    println!("[server] listening on {}", addr);

    loop {
        let (stream, peer) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer).await {
                eprintln!("[server] connection error: {}", e);
            }
        });
    }
}

/// Handles a single client connection
async fn handle_connection(stream: TcpStream, peer: SocketAddr) -> Result<()> {
    let mut framed = Framed::new(stream, PacketCodec);

    println!("[server] connected: {}", peer);

    while let Some(packet) = framed.next().await {
        match packet {
            Ok(pkt) => {
                println!("[server] received {} bytes from {}...", pkt.payload.len(), peer);
                on_packet(pkt, &mut framed).await?;
            }
            Err(e) => {
                eprintln!("[server] protocol error from {}: {}", peer, e);
                break;
            }
        }
    }

    println!("[server] disconnected: {}", peer);
    Ok(())
}

/// Placeholder: handles incoming packets
async fn on_packet(pkt: Packet, framed: &mut Framed<TcpStream, PacketCodec>) -> Result<()> {
    // Echo the packet back
    let response = Packet {
        version: pkt.version,
        payload: pkt.payload,
    };

    framed.send(response).await?;
    Ok(())
}

/// Connect to a remote server and return the framed transport
pub async fn connect(addr: &str) -> Result<Framed<TcpStream, PacketCodec>> {
    let stream = TcpStream::connect(addr).await?;
    let framed = Framed::new(stream, PacketCodec);
    Ok(framed)
}
