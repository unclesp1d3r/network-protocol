use crate::protocol::message::Message;

/// Builds a heartbeat ping message
pub fn build_ping() -> Message {
    Message::Ping
}

/// Returns true if a received message is a valid pong
pub fn is_pong(msg: &Message) -> bool {
    matches!(msg, Message::Pong)
}
