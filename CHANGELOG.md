# Changelog

All notable changes to the Network Protocol project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

## [0.9.0] - 2025-08-17

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