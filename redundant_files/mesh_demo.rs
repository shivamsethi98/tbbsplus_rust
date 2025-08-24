#[cfg(feature = "mpc")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use libp2p::Multiaddr;
    use tbbsplus_rust::orchestration::mesh::p2p::Mesh;
    use serde::{Serialize, Deserialize};
    use tokio::time::{sleep, timeout, Duration};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct Ping { from: String, msg: String }

    // Peer A: listen on a fixed loopback port and subscribe to topic
    let a_addr: Multiaddr = "/ip4/127.0.0.1/tcp/9500".parse()?;
    let mut a = Mesh::new(Some(a_addr.clone())).await?;
    // Peer A also needs to subscribe to the topic for gossipsub to work properly
    let _a_sub = a.subscribe::<Ping>("topic-demo").await?;

    // Peer B: listen on random loopback and subscribe
    let mut b = Mesh::new(Some("/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?)).await?;
    let mut b_sub = b.subscribe::<Ping>("topic-demo").await?;

    // Start background loops for BOTH peers
    let a_handle = a.run_background();
    let b_handle = b.run_background();

    // Dial and establish connection
    b_handle.dial(a_addr).await?;
    // Wait until at least one peer is connected
    b_handle.await_peers(1).await?;
    
    // Give gossipsub mesh time to establish properly
    sleep(Duration::from_millis(500)).await;
    
    // Try a few publishes with short backoff to allow gossipsub mesh to warm up
    let mut received = false;
    for attempt in 0..10 {
        println!("mesh_demo: attempt {} - publishing message from A", attempt + 1);
        a_handle.publish("topic-demo", &Ping { from: "A".into(), msg: format!("hello {}", attempt) }).await?;
        
        if let Ok(Some(p)) = timeout(Duration::from_millis(500), b_sub.recv()).await {
            println!("mesh_demo: received: {:?}", p);
            received = true;
            break;
        }
        
        // Small delay between attempts
        sleep(Duration::from_millis(100)).await;
    }
    
    if !received {
        println!("mesh_demo: timed out waiting for message after 10 attempts");
    } else {
        println!("mesh_demo: Successfully established mesh communication!");
    }

    Ok(())
}

#[cfg(not(feature = "mpc"))]
fn main() {
    eprintln!("mesh_demo requires feature 'mpc' (libp2p)\nTry: cargo run --features mpc --bin mesh_demo");
}
