use network_protocol::transport::remote;
use network_protocol::error::Result;
use std::process;

#[tokio::main]
async fn main() -> Result<()> {
    match remote::start_server("127.0.0.1:7777").await {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("Server error: {}", e);
            process::exit(1);
        }
    }
}