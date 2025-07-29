use crate::protocol::message::Message;

/// Initiates handshake from the client side.
/// Returns a Message that should be sent to the server.
pub fn client_handshake_init() -> Message {
    let nonce: u64 = rand::random();
    Message::HandshakeInit { client_nonce: nonce }
}

/// Handles server-side handshake response
pub fn server_handshake_response(client_nonce: u64) -> Message {
    let server_nonce: u64 = client_nonce ^ 0xDEADBEEFCAFEBABE; // Dummy transformation
    Message::HandshakeAck { server_nonce }
}

/// Verifies the server's handshake response
pub fn verify_server_ack(server_nonce: u64, client_nonce: u64) -> bool {
    server_nonce == (client_nonce ^ 0xDEADBEEFCAFEBABE)
}

/// Generates a 32-byte symmetric key from the client_nonce
pub fn derive_shared_key(client_nonce: u64) -> [u8; 32] {
    let mut key = [0u8; 32];
    let nonce_bytes = client_nonce.to_le_bytes();
    for i in 0..32 {
        key[i] = nonce_bytes[i % 8] ^ (0xA5 ^ (i as u8));
    }
    key
}