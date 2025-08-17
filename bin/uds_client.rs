use network_protocol::transport::local;
use network_protocol::core::packet::Packet;
use futures::{SinkExt, StreamExt};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Path is interpreted as a unix socket path on Unix systems
    // and as a TCP port on localhost for Windows systems
    let socket_path = "/tmp/my.sock";
    
    // Connect with proper error handling
    let mut framed = local::connect(socket_path).await?
        ;

    // Prepare and send message
    let msg = Packet {
        version: 1,
        payload: b"test-message".to_vec(),
    };

    framed.send(msg).await?
        ;

    // Wait for response with proper error handling
    match framed.next().await {
        Some(Ok(response)) => {
            println!("Echo response: {}", String::from_utf8_lossy(&response.payload));
        },
        Some(Err(e)) => {
            eprintln!("Error receiving response: {e}");
            return Err(e.into());
        },
        None => {
            let err = std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "Connection closed");
            return Err(err.into());
        }
    }
    
    Ok(())
}
