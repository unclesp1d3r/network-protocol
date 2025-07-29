//! # Network Protocol
//! This file is part of the Network Protocol project.
//! 
//! It provides the main entry point for the protocol layer,
//! including the core components, transport mechanisms,
//! and utility functions.
//! 
//! The protocol is designed to be modular, high-performance,
//! and suitable for local, remote, and cluster communication.
//! 
//! The main components include:
//! - Core: packet handling, codec, error management
//! - Transport: network communication, remote operations
//! - Protocol: message routing, handshake logic
//! - Service: client and daemon abstractions
//! - Utils: cryptography, compression, time management
//! 
//! The protocol layer is built with a focus on performance,
//! scalability, and ease of integration with other systems.
pub mod config;
pub mod error;

pub mod core {
    pub mod codec;
    pub mod packet;
}

pub mod transport; // will add files shortly
pub mod protocol;  // message + handshake routing
pub mod service;   // client/daemon abstraction
pub mod utils;     // crypto/compression/time/etc

pub use config::*;
pub use error::*;
pub use core::packet::Packet;
pub use core::codec::PacketCodec;