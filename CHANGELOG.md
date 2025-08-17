# Changelog

All notable changes to the Network Protocol project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Cross-platform support for local transport (Windows compatibility)
- Windows-compatible alternative for Unix Domain Sockets using TCP
- Updated client and server binaries to work across platforms

### Changed
- Improved error handling in client/server binaries
- Updated format strings to use modern Rust syntax
- Fixed Clippy warnings throughout the codebase
- Added Default implementation for Dispatcher

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
[0.9.1]: https://github.com/jamesgober/network-protocol/compare/0.9.0...v0.9.1
[0.9.0]: https://github.com/jamesgober/network-protocol/releases/tag/0.9.0