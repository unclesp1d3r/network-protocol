use network_protocol::transport::local;
use network_protocol::core::packet::Packet;
use tokio_util::codec::Framed;
use tokio::net::UnixStream;
use futures::{SinkExt, StreamExt};
use std::path::Path;

#[tokio::main]
async fn main() {
    let mut framed: Framed<UnixStream, _> = local::connect("/tmp/my.sock").await.unwrap();

    let msg = Packet {
        version: 1,
        payload: b"test-uds-message".to_vec(),
    };

    framed.send(msg).await.unwrap();

    if let Some(Ok(response)) = framed.next().await {
        println!("UDS Echo: {:?}", String::from_utf8_lossy(&response.payload));
    }
}
