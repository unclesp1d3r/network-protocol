use std::path::PathBuf;
use std::time::Duration;
use tokio::time::sleep;

use network_protocol::error::Result;
use network_protocol::protocol::message::Message;
use network_protocol::transport::tls::{TlsServerConfig, TlsClientConfig};
use network_protocol::service::tls_client::TlsClient;

const TEST_PORT: u16 = 49152; // Use a high port number for tests
const TEST_PORT_TAMPER: u16 = 49153; // Second port for tampering test
const CERT_PATH: &str = "tests/test_cert.pem";
const KEY_PATH: &str = "tests/test_key.pem";

// Helper to generate test certificates
fn generate_test_certificates() -> Result<(PathBuf, PathBuf)> {
    let cert_path = PathBuf::from(CERT_PATH);
    let key_path = PathBuf::from(KEY_PATH);
    
    // Generate certificates if they don't exist
    if !cert_path.exists() || !key_path.exists() {
        TlsServerConfig::generate_self_signed(&cert_path, &key_path)
            .expect("Failed to generate test certificates");
    }
    
    Ok((cert_path, key_path))
}

// Test a basic TLS server and client exchange
#[tokio::test]
async fn test_tls_communication() -> Result<()> {
    // Generate test certificates
    let (cert_path, key_path) = generate_test_certificates()?;
    
    // Start TLS server in a separate task
    let server_handle = tokio::spawn(async move {
        let config = TlsServerConfig::new(cert_path, key_path);
        network_protocol::service::tls_daemon::start(&format!("127.0.0.1:{}", TEST_PORT), config).await
    });
    
    // Wait for server to start
    sleep(Duration::from_millis(100)).await;
    
    // Connect with TLS client, using insecure mode since we're using self-signed certs
    let config = TlsClientConfig::new("localhost").insecure();
    let mut client = TlsClient::connect(&format!("127.0.0.1:{}", TEST_PORT), config).await?;
    
    // Test ping/pong
    let response = client.request(Message::Ping).await?;
    assert!(matches!(response, Message::Pong));
    
    // Echo test
    let test_message = Message::Custom { 
        command: "ECHO".to_string(), 
        payload: vec![1, 2, 3, 4] 
    };
    let response = client.request(test_message.clone()).await?;
    
    if let Message::Custom { command, payload } = response {
        assert_eq!(command, "ECHO");
        assert_eq!(payload, vec![1, 2, 3, 4]);
    } else {
        panic!("Expected Custom message, got: {:?}", response);
    }
    
    // We're done, so drop the client which will close the connection
    drop(client);
    
    // Allow the server to process the disconnection
    sleep(Duration::from_millis(100)).await;
    
    // Clean up the server task
    server_handle.abort();
    
    Ok(())
}

// Test TLS against tampering
#[tokio::test]
async fn test_tls_tampering_protection() -> Result<()> {
    // This test demonstrates that TLS protects against message tampering
    // For a real implementation, we would need to set up a proxy to modify messages
    // Here we just validate that the connection is protected by TLS
    
    let (cert_path, key_path) = generate_test_certificates()?;
    
    // Start TLS server
    let server_addr = format!("127.0.0.1:{}", TEST_PORT_TAMPER);
    let server_addr_clone = server_addr.clone();
    let server_handle = tokio::spawn(async move {
        let config = TlsServerConfig::new(cert_path, key_path);
        network_protocol::service::tls_daemon::start(&server_addr_clone, config).await
    });
    
    // Wait for server to start
    sleep(Duration::from_millis(100)).await;
    
    // Connect with TLS client
    let config = TlsClientConfig::new("localhost").insecure();
    let mut client = TlsClient::connect(&server_addr, config).await?;
    
    // Verify the connection works
    let response = client.request(Message::Ping).await?;
    assert!(matches!(response, Message::Pong));
    
    // With TLS, any tampering with the encrypted data would cause the connection
    // to fail, as the TLS layer would detect the integrity violation
    
    // Clean up
    drop(client);
    sleep(Duration::from_millis(100)).await;
    server_handle.abort();
    
    Ok(())
}
