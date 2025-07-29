use std::collections::HashMap;
use std::time::{Duration, Instant};
//use tokio::net::TcpStream;
use tokio::time::sleep;

use crate::service::client::Client;
use crate::protocol::message::Message;
//use crate::error::Result;

#[derive(Debug, Clone)]
pub struct ClusterNode {
    pub id: String,
    pub addr: String,
    pub last_seen: Option<Instant>,
}

pub struct Cluster {
    peers: HashMap<String, ClusterNode>,
}

impl Cluster {
    pub fn new(peers: Vec<(String, String)>) -> Self {
        let peers = peers.into_iter().map(|(id, addr)| {
            (id.clone(), ClusterNode { id, addr, last_seen: None })
        }).collect();

        Self { peers }
    }

    pub async fn start_heartbeat(&mut self, interval: Duration) {
        loop {
            for (id, node) in self.peers.iter_mut() {
                if let Ok(mut client) = Client::connect(&node.addr).await {
                    if let Ok(Message::Pong) = client.send_and_wait(Message::Ping).await {
                        node.last_seen = Some(Instant::now());
                        println!("[cluster] {} alive", id);
                    } else {
                        println!("[cluster] {} timeout", id);
                    }
                } else {
                    println!("[cluster] {} unreachable", id);
                }
            }

            sleep(interval).await;
        }
    }

    pub fn get_peers(&self) -> Vec<&ClusterNode> {
        self.peers.values().collect()
    }
}
