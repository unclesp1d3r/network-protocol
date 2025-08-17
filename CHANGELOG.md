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

### Changed
- Improved error handling in client/server binaries
- Updated format strings to use modern Rust syntax
- Fixed Clippy warnings throughout the codebase
- Added Default implementation for Dispatcher

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