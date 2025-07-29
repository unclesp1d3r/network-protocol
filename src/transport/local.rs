use tokio::net::{UnixListener, UnixStream};
use tokio_util::codec::Framed;
use futures::{StreamExt, SinkExt};
use std::path::Path;

use crate::core::codec::PacketCodec;
//use crate::core::packet::Packet;
use crate::error::Result;

/// Start a UDS server at a given socket path
pub async fn start_server<P: AsRef<Path>>(path: P) -> Result<()> {
    if path.as_ref().exists() {
        tokio::fs::remove_file(&path).await.ok();
    }

    let listener = UnixListener::bind(path)?;
    println!("[uds] listening...");

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut framed = Framed::new(stream, PacketCodec);

            while let Some(Ok(packet)) = framed.next().await {
                println!("[uds] recv: {} bytes", packet.payload.len());

                // Echo it back
                let _ = framed.send(packet).await;
            }
        });
    }
}

/// Connect to a local UDS socket
pub async fn connect<P: AsRef<Path>>(path: P) -> Result<Framed<UnixStream, PacketCodec>> {
    let stream = UnixStream::connect(path).await?;
    Ok(Framed::new(stream, PacketCodec))
}
