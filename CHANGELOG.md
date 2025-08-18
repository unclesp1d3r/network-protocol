# Changelog

All notable changes to the Network Protocol project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Integrated structured logging with `tracing` crate throughout the codebase
- Added `#[tracing::instrument]` attributes to key async functions for enhanced contextual logging
- Created logging configuration module with flexible log level control via environment variables
- Implemented concurrent-safe logging infrastructure for better debugging and observability
- Added configurable connection timeouts for all network operations
- Implemented heartbeat mechanism with keep-alive ping/pong messages
- Added automatic detection and cleanup of dead connections
- Implemented client-side timeout handling with automatic reconnection capability

### Changed
- Replaced all `println!` and `eprintln!` calls with appropriate structured logging macros (`debug!`, `info!`, `warn!`, `error!`)
- Enhanced logging detail with structured fields for better filtering and analysis
- Improved error logging with contextual information across all modules
- Updated documentation examples to use structured logging
- Modified connection handling to use timeout wrappers for all I/O operations
- Enhanced client and server implementations to support configurable timeouts
- Updated network transport layer to detect and report connection timeouts
- Refactored message processing loops to handle keep-alive messages transparently

### Fixed
- Removed deprecated legacy handshake functions (`derive_shared_key`, `verify_server_ack`, `server_handshake_response`)
- Removed deprecated message types (`HandshakeInit`, `HandshakeAck`)
- Removed references to deprecated code from dispatcher, client, and daemon
- Updated API documentation to reflect removal of legacy handshake functionality
- Fixed double error unwrapping in timeout handlers for client and server code
- Corrected handshake state management in parallel test executions
- Fixed client send_and_wait functionality to properly handle timeout errors
- Added proper cleanup of connection resources when timeout or keep-alive failures occur

### Security
- Enhanced security by removing insecure legacy handshake implementation


## [0.9.3] - 2025-08-17

### Added
- Cross-platform support for local transport (Windows compatibility)
- Windows-compatible alternative for Unix Domain Sockets using TCP
- Updated client and server binaries to work across platforms
- Secure handshake protocol using ECDH key exchange
- Protection against replay attacks using timestamps and nonce verification
- TLS support for secure external connections
- Self-signed certificate generation capability for development
- Dedicated TLS transport layer with client and server implementations
- Certificate pinning functionality for enhanced security in TLS connections
- Mutual TLS authentication (mTLS) support for bidirectional certificate verification
- Configuration options for TLS protocol versions (TLS 1.2, TLS 1.3)
- Customizable cipher suite selection for TLS connections
- Graceful shutdown support for all server implementations:
  - Signal handling (CTRL+C) for clean termination
  - Active connection tracking and draining
  - Configurable shutdown timeouts
  - Resource cleanup during shutdown (sockets, files, etc.)
  - Heartbeat task termination for cluster transport

### Changed
- Improved error handling in client/server binaries
- Updated format strings to use modern Rust syntax
- Fixed Clippy warnings throughout the codebase
- Added Default implementation for Dispatcher
- Replaced manual slice copying with more efficient `copy_from_slice` operations
- Added proper deprecated attribute handling for legacy message variants
- Fixed key derivation to ensure consistent shared secrets in secure handshake
- Replaced all `unwrap()` and `expect()` calls with proper error handling using Result propagation
- Added serialization support for ProtocolError with serde's Serialize/Deserialize traits
- Updated return types for handshake functions to use Result consistently
- Modified client handshake code to properly handle Result types
- Implemented graceful shutdown mechanism for the daemon server with proper signal handling
- Added comprehensive error propagation throughout the service layer
- Standardized graceful shutdown mechanism across all transport implementations
- Implemented proper shutdown test suite for verifying graceful termination

### Fixed
- Fixed intermittent test failures in secure handshake tests
- Added deterministic test keys for stable test behavior
- Implemented explicit nonce setting for reproducible tests
- Fixed integration tests to use random available ports to avoid port conflicts
- Corrected type mismatches in client connection code
- Resolved unused variable warnings
- Fixed unused Result warnings in daemon and server code

### Security
- Implemented Elliptic Curve Diffie-Hellman (ECDH) key exchange using x25519-dalek
- Added timestamp verification to prevent replay attacks
- Enhanced key derivation using SHA-256 and multiple entropy sources
- Ensured forward secrecy with ephemeral key pairs
- Deprecated the previous insecure handshake implementation



## [0.9.0] - 2025-07-29

### Added
- Initial release of Network Protocol
- Core packet structure with serialization and deserialization
- Protocol message types and dispatcher
- Transport layer with remote and cluster support
- Service layer with client and daemon implementations
- Secure connection handling with handshake protocol
- Cross-platform CI testing workflow

### Security
- Implemented secure handshake mechanism
- Added encryption for protocol messages

[Unreleased]: https://github.com/jamesgober/network-protocol/compare/0.9.0...HEAD
[1.0.0]: https://github.com/jamesgober/network-protocol/compare/v0.9.9...v1.0.0
[0.9.9]: https://github.com/jamesgober/network-protocol/compare/v0.9.6...v0.9.9
[0.9.6]: https://github.com/jamesgober/network-protocol/compare/v0.9.3...v0.9.6
[0.9.3]: https://github.com/jamesgober/network-protocol/compare/0.9.0...v0.9.3
[0.9.0]: https://github.com/jamesgober/network-protocol/releases/tag/0.9.0