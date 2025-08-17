use network_protocol::transport::local;
use network_protocol::core::packet::Packet;
use futures::{SinkExt, StreamExt};

#[tokio::main]
async fn main() {
    // Path is interpreted as a unix socket path on Unix systems
    // and as a TCP port on localhost for Windows systems
    let socket_path = "/tmp/my.sock";
    
    let mut framed = match local::connect(socket_path).await {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to connect: {e}");
            return;
        }
    };

    let msg = Packet {
        version: 1,
        payload: b"test-message".to_vec(),
    };

    if let Err(e) = framed.send(msg).await {
        eprintln!("Failed to send message: {e}");
        return;
    }

    if let Some(Ok(response)) = framed.next().await {
        println!("Echo response: {}", String::from_utf8_lossy(&response.payload));
    } else {
        eprintln!("No valid response received");
    }
}
