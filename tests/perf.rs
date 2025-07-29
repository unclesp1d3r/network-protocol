use network_protocol::service::{client::Client, daemon};
use network_protocol::protocol::message::Message;
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[tokio::test]
async fn benchmark_roundtrip_latency() {
    let addr = "127.0.0.1:7799";

    tokio::spawn(async move {
        daemon::start(addr).await.unwrap();
    });

    sleep(Duration::from_millis(100)).await;

    let mut client = Client::connect(addr).await.expect("Failed to connect");

    let rounds = 100;
    let mut total = Duration::ZERO;

    for _ in 0..rounds {
        let start = Instant::now();
        client.send(Message::Ping).await.unwrap();
        let _ = client.recv().await.unwrap();
        total += start.elapsed();
    }

    let avg = total / rounds;
    println!("Average roundtrip latency over {} packets: {:?} per message", rounds, avg);
}

#[tokio::test]
async fn benchmark_throughput() {
    let addr = "127.0.0.1:7798";

    tokio::spawn(async move {
        daemon::start(addr).await.unwrap();
    });

    sleep(Duration::from_millis(100)).await;

    let mut client = Client::connect(addr).await.expect("Failed to connect");

    let rounds = 1_000;
    let payload = Message::Echo("x".repeat(128));
    let start = Instant::now();

    for _ in 0..rounds {
        client.send(payload.clone()).await.unwrap();
        let _ = client.recv().await.unwrap();
    }

    let elapsed = start.elapsed();
    let per_sec = rounds as f64 / elapsed.as_secs_f64();
    println!("Throughput: {:.0} messages/sec over {:?} total", per_sec, elapsed);
}
