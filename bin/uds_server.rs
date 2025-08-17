use network_protocol::transport::local;

#[tokio::main]
async fn main() {
    // Path is interpreted as a unix socket path on Unix systems
    // and as a TCP port on localhost for Windows systems
    let socket_path = "/tmp/my.sock";
    
    if let Err(e) = local::start_server(socket_path).await {
        eprintln!("Server failed: {e}");
    }
}
