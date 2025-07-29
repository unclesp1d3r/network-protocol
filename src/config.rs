/// Current supported protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Magic bytes to identify protocol packets (e.g., 0x4E50524F → "NPRO")
pub const MAGIC_BYTES: [u8; 4] = [0x4E, 0x50, 0x52, 0x4F];

/// Max allowed payload size (e.g. 16 MB)
pub const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

/// Whether to enable compression by default
pub const ENABLE_COMPRESSION: bool = false;

/// Whether to enable encryption by default
pub const ENABLE_ENCRYPTION: bool = true;
