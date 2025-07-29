use network_protocol::service::client::Client;
use network_protocol::service::daemon;
use network_protocol::protocol::message::Message;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_secure_handshake_and_messages() {
    let addr = "127.0.0.1:7888";

    // Spawn the daemon server in background
    tokio::spawn(async move {
        daemon::start(addr).await.unwrap();
    });

    // Give the server a moment to start
    sleep(Duration::from_millis(100)).await;

    // Connect the client (includes secure handshake)
    let mut client = Client::connect(addr).await.expect("Failed to connect");

    // --- Test Ping → Pong ---
    client.send(Message::Ping).await.expect("Failed to send ping");
    let response = client.recv().await.expect("No pong received");
    assert!(matches!(response, Message::Pong), "Expected Pong, got {:?}", response);

    // --- Test Echo ---
    let echo_msg = "Secure echo test!".to_string();
    client.send(Message::Echo(echo_msg.clone())).await.expect("Failed to send echo");
    let response = client.recv().await.expect("No echo received");
    match response {
        Message::Echo(reply) => assert_eq!(reply, echo_msg),
        _ => panic!("Expected Echo, got {:?}", response),
    }

    // --- Disconnect (optional) ---
    client.send(Message::Disconnect).await.expect("Failed to disconnect");
}
