use serde::{Deserialize, Serialize};

#[cfg(feature = "mpc")]
pub mod p2p {
    use super::*;
    use libp2p::futures::StreamExt;
    use libp2p::{dns, gossipsub, identity, noise, tcp, yamux, Multiaddr, Transport as _};
    use serde::de::DeserializeOwned;
    use std::collections::HashMap;
    use tokio::sync::mpsc::{channel, Receiver, Sender};
    use tokio::sync::oneshot;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct MeshMsg<T> {
        pub topic: String,
        pub payload: T,
    }

    enum Command {
        Publish { topic: String, bytes: Vec<u8> },
        Dial(Multiaddr),
        AwaitPeers { min: usize, respond_to: oneshot::Sender<()> },
    }

    pub struct Mesh {
        swarm: libp2p::swarm::Swarm<gossipsub::Behaviour>,
    sinks: HashMap<gossipsub::TopicHash, Sender<Vec<u8>>>,
        cmd_tx: Sender<Command>,
        cmd_rx: Option<Receiver<Command>>,
    }

    #[derive(Clone)]
    pub struct MeshHandle {
        cmd_tx: Sender<Command>,
    }

    impl Mesh {
        pub async fn new(listen: Option<Multiaddr>) -> anyhow::Result<Self> {
            let local_key = identity::Keypair::generate_ed25519();
            let peer_id = local_key.public().to_peer_id();
            let transport = dns::tokio::Transport::system(tcp::tokio::Transport::new(tcp::Config::default()))
                .map_err(|e| anyhow::anyhow!(e))?
                .upgrade(libp2p::core::upgrade::Version::V1Lazy)
                .authenticate(noise::Config::new(&local_key)?)
                .multiplex(yamux::Config::default())
                .boxed();

            let gs = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(local_key.clone()),
                gossipsub::Config::default(),
            )
            .map_err(anyhow::Error::msg)?;

            let mut swarm = libp2p::swarm::Swarm::new(
                transport,
                gs,
                peer_id,
                libp2p::swarm::Config::with_tokio_executor(),
            );
            if let Some(addr) = listen {
                libp2p::swarm::Swarm::listen_on(&mut swarm, addr)?;
            }
            let (tx, rx) = channel(64);
            Ok(Self {
                swarm,
                sinks: HashMap::new(),
                cmd_tx: tx,
                cmd_rx: Some(rx),
            })
        }

        pub async fn publish<T: Serialize>(&mut self, topic: &str, payload: &T) -> anyhow::Result<()> {
            let topic = gossipsub::IdentTopic::new(topic);
            self.swarm.behaviour_mut().subscribe(&topic)?;
            let bytes = serde_json::to_vec(payload)?;
            self.swarm.behaviour_mut().publish(topic, bytes)?;
            Ok(())
        }

        pub async fn publish_json<T: Serialize>(&mut self, topic: &str, payload: &T) -> anyhow::Result<()> {
            self.publish(topic, payload).await
        }

        pub async fn subscribe_raw(&mut self, topic: &str) -> anyhow::Result<Receiver<Vec<u8>>> {
            let topic = gossipsub::IdentTopic::new(topic);
            self.swarm.behaviour_mut().subscribe(&topic)?;
            let (tx, rx) = channel(64);
            self.sinks.insert(topic.hash().clone(), tx);
            Ok(rx)
        }

        pub async fn subscribe<T: DeserializeOwned + Send + 'static>(
            &mut self,
            topic: &str,
        ) -> anyhow::Result<Receiver<T>> {
            let mut raw = self.subscribe_raw(topic).await?;
            let (tx, rx) = channel::<T>(64);
            tokio::spawn(async move {
                while let Some(bytes) = raw.recv().await {
                    if let Ok(msg) = serde_json::from_slice::<T>(&bytes) {
                        let _ = tx.send(msg).await;
                    }
                }
            });
            Ok(rx)
        }

        pub fn run_background(mut self) -> MeshHandle {
            let mut cmd_rx = self.cmd_rx.take().expect("mesh background already running");
            let handle = MeshHandle {
                cmd_tx: self.cmd_tx.clone(),
            };
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        maybe_evt = self.swarm.next() => {
                            match maybe_evt {
                                Some(libp2p::swarm::SwarmEvent::Behaviour(gossipsub::Event::Message { message, .. })) => {
                                    println!("[mesh] rx gossipsub on topic {:?}, {} bytes", message.topic, message.data.len());
                                    let key = message.topic.clone();
                                    if let Some(sink) = self.sinks.get(&key) {
                                        let _ = sink.send(message.data.clone()).await;
                                    }
                                }
                                Some(_) => {}
                                None => break,
                            }
                        }
                        maybe_cmd = cmd_rx.recv() => {
                            match maybe_cmd {
                                Some(Command::Publish { topic, bytes }) => {
                                    println!("[mesh] tx gossipsub topic {}, {} bytes", topic, bytes.len());
                                    let topic = gossipsub::IdentTopic::new(&topic);
                                    let _ = self.swarm.behaviour_mut().subscribe(&topic);
                                    let _ = self.swarm.behaviour_mut().publish(topic, bytes);
                                }
                                Some(Command::Dial(addr)) => {
                                    let _ = libp2p::swarm::Swarm::dial(&mut self.swarm, addr);
                                }
                                Some(Command::AwaitPeers { min, respond_to }) => {
                                    let peers = self.swarm.connected_peers().count();
                                    if peers >= min {
                                        let _ = respond_to.send(());
                                    } else {
                                        // Requeue check after a short delay by spawning a tiny watchdog
                                        let tx = self.cmd_tx.clone();
                                        tokio::spawn(async move {
                                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                                            let _ = tx.send(Command::AwaitPeers { min, respond_to }).await;
                                        });
                                    }
                                }
                                None => break,
                            }
                        }
                    }
                }
            });
            handle
        }

        pub fn listeners(&self) -> Vec<Multiaddr> {
            self.swarm.listeners().cloned().collect()
        }
    }

    impl MeshHandle {
        pub async fn publish<T: Serialize>(&self, topic: &str, payload: &T) -> anyhow::Result<()> {
            let bytes = serde_json::to_vec(payload)?;
            self.cmd_tx
                .send(Command::Publish { topic: topic.to_string(), bytes })
                .await
                .map_err(|e| anyhow::anyhow!(e))
        }

        pub async fn dial(&self, addr: Multiaddr) -> anyhow::Result<()> {
            self.cmd_tx
                .send(Command::Dial(addr))
                .await
                .map_err(|e| anyhow::anyhow!(e))
        }

        pub async fn await_peers(&self, min: usize) -> anyhow::Result<()> {
            let (tx, rx) = oneshot::channel();
            self.cmd_tx
                .send(Command::AwaitPeers { min, respond_to: tx })
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            rx.await.map_err(|e| anyhow::anyhow!(e))
        }
    }
}

#[cfg(not(feature = "mpc"))]
pub mod p2p {
    use super::*;
    use tokio::sync::mpsc::{channel, Receiver};
    pub struct Mesh;
    impl Mesh {
        pub async fn new(_listen: Option<()>) -> anyhow::Result<Self> { Ok(Self) }
        pub async fn publish<T: Serialize>(&mut self, _topic: &str, _payload: &T) -> anyhow::Result<()> { Ok(()) }
        pub async fn subscribe<T: for<'a> Deserialize<'a>>(&mut self, _topic: &str) -> anyhow::Result<Receiver<T>> { let (_tx, rx) = channel(1); Ok(rx) }
    }
}
