use network_protocol::transport::remote;

#[tokio::main]
async fn main() {
    remote::start_server("127.0.0.1:7777").await.unwrap();
}