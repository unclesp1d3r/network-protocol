use network_protocol::transport::local;

#[tokio::main]
async fn main() {
    local::start_server("/tmp/my.sock").await.unwrap();
}
