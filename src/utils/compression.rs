use crate::error::{Result, ProtocolError};

pub enum CompressionKind {
    Lz4,
    Zstd,
}

pub fn compress(data: &[u8], kind: CompressionKind) -> Result<Vec<u8>> {
    match kind {
        CompressionKind::Lz4 => Ok(lz4_flex::compress_prepend_size(data)),
        CompressionKind::Zstd => {
            let mut out = Vec::new();
            zstd::stream::copy_encode(data, &mut out, 1)
                .map_err(|_| ProtocolError::CompressionFailure)?;
            Ok(out)
        }
    }
}

pub fn decompress(data: &[u8], kind: CompressionKind) -> Result<Vec<u8>> {
    match kind {
        CompressionKind::Lz4 => lz4_flex::decompress_size_prepended(data)
            .map_err(|_| ProtocolError::DecompressionFailure),
        CompressionKind::Zstd => {
            let mut out = Vec::new();
            zstd::stream::copy_decode(data, &mut out)
                .map_err(|_| ProtocolError::DecompressionFailure)?;
            Ok(out)
        }
    }
}
