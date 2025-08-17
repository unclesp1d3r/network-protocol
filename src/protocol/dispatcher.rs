use crate::protocol::message::Message;
use crate::error::{Result, ProtocolError};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

type HandlerFn = dyn Fn(&Message) -> Result<Message> + Send + Sync + 'static;

pub struct Dispatcher {
    handlers: Arc<RwLock<HashMap<String, Box<HandlerFn>>>>,
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Dispatcher {
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn register<F>(&self, opcode: &str, handler: F)
    where
        F: Fn(&Message) -> Result<Message> + Send + Sync + 'static,
    {
        self.handlers.write().unwrap().insert(opcode.to_string(), Box::new(handler));
    }

    pub fn dispatch(&self, msg: &Message) -> Result<Message> {
        let opcode = get_opcode(msg);
        let handlers = self.handlers.read().unwrap();

        match handlers.get(&opcode) {
            Some(handler) => handler(msg),
            None => Err(ProtocolError::UnexpectedMessage),
        }
    }
}

/// Determine message type name for routing
fn get_opcode(msg: &Message) -> String {
    match msg {
        Message::Ping => "PING",
        Message::Pong => "PONG",
        Message::Echo(_) => "ECHO",
        // Deprecated handshake messages (still need to handle them)
        #[allow(deprecated)]
        Message::HandshakeInit { .. } => "HS_INIT",
        #[allow(deprecated)]
        Message::HandshakeAck { .. } => "HS_ACK",
        // Secure handshake messages
        Message::SecureHandshakeInit { .. } => "SEC_HS_INIT",
        Message::SecureHandshakeResponse { .. } => "SEC_HS_RESP",
        Message::SecureHandshakeConfirm { .. } => "SEC_HS_CONFIRM",
        Message::Custom { command, .. } => command,
        Message::Disconnect => "DISCONNECT",
        Message::Unknown => "UNKNOWN",
    }
    .to_string()
}
