// Simplified hybrid mesh network without Kademlia DHT
use anyhow::{anyhow, Result};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;

#[cfg(feature = "mpc")]
pub mod p2p {
    use super::*;
    use libp2p::{
        gossipsub::{self, MessageId, MessageAuthenticity, TopicHash, Sha256Topic as MyTopic},
        identity::Keypair,
        mdns,
        noise,
        request_response::{self, ProtocolSupport},
        swarm::{NetworkBehaviour, SwarmEvent},
        tcp,
        yamux,
        Multiaddr, PeerId, StreamProtocol, SwarmBuilder,
    };
    use futures::StreamExt;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    // Protocol for direct messages
    const DIRECT_PROTOCOL: &str = "/threshold-bbs/direct/1.0.0";
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DirectMessage {
        pub from: u16,
        pub to: u16,
        pub data: Vec<u8>,
        pub nonce: u64,
    }
    
    // Combined network behaviour without Kademlia
    #[derive(NetworkBehaviour)]
    struct MeshBehaviour {
        gossipsub: gossipsub::Behaviour,
        request_response: request_response::cbor::Behaviour<Vec<u8>, Vec<u8>>,
        mdns: mdns::tokio::Behaviour,
    }
    
    enum Command {
        Broadcast {
            topic: String,
            data: Vec<u8>,
        },
        SendDirect {
            to: u16,
            data: Vec<u8>,
            respond_to: oneshot::Sender<Result<()>>,
        },
        RegisterPeer {
            participant_id: u16,
            peer_id: PeerId,
        },
    }
    
    pub struct Mesh {
        local_peer_id: PeerId,
        participant_id: u16,
        swarm: libp2p::Swarm<MeshBehaviour>,
        cmd_tx: Sender<Command>,
        cmd_rx: Option<Receiver<Command>>,
        broadcast_sinks: HashMap<TopicHash, Sender<Vec<u8>>>,
        direct_sink: Option<Sender<DirectMessage>>,
        participant_to_peer: HashMap<u16, PeerId>,
        peer_to_participant: HashMap<PeerId, u16>,
    }
    
    #[derive(Clone)]
    pub struct MeshHandle {
        cmd_tx: Sender<Command>,
        participant_id: u16,
    }
    
    impl Mesh {
        pub async fn new(
            participant_id: u16,
            listen_addr: Option<Multiaddr>,
            bootstrap_peers: Vec<(u16, Multiaddr)>,
        ) -> Result<Self> {
            // Generate deterministic keypair
            let keypair = {
                let mut bytes = [0u8; 32];
                bytes[0] = participant_id as u8;
                bytes[1] = (participant_id >> 8) as u8;
                // Fill rest with deterministic pattern
                for i in 2..32 {
                    bytes[i] = ((participant_id as usize + i) % 256) as u8;
                }
                Keypair::ed25519_from_bytes(bytes)?
            };
            
            let local_peer_id = PeerId::from(keypair.public());
            
            // Configure gossipsub
            let message_id_fn = |message: &gossipsub::Message| {
                let mut hasher = DefaultHasher::new();
                message.data.hash(&mut hasher);
                MessageId::from(hasher.finish().to_string())
            };
            
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(1))
                .validation_mode(gossipsub::ValidationMode::Permissive)
                .message_id_fn(message_id_fn)
                .build()
                .map_err(|e| anyhow!("gossipsub config error: {}", e))?;
            
            let gossipsub = gossipsub::Behaviour::new(
                MessageAuthenticity::Signed(keypair.clone()),
                gossipsub_config,
            ).map_err(|e| anyhow!("Failed to create gossipsub: {}", e))?;
            
            // Configure request-response using CBOR
            let request_response = request_response::cbor::Behaviour::new(
                [(StreamProtocol::new(DIRECT_PROTOCOL), ProtocolSupport::Full)],
                request_response::Config::default(),
            );
            
            // Configure mDNS
            let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;
            
            // Build swarm using SwarmBuilder for libp2p 0.54
            let mut swarm = SwarmBuilder::with_existing_identity(keypair.clone())
                .with_tokio()
                .with_tcp(
                    tcp::Config::default(),
                    noise::Config::new,
                    yamux::Config::default,
                )?
                .with_dns()?
                .with_behaviour(|_keypair| {
                    Ok(MeshBehaviour {
                        gossipsub,
                        request_response,
                        mdns,
                    })
                })?
                .build();
            
            // Listen on provided address
            if let Some(addr) = listen_addr {
                swarm.listen_on(addr)?;
            }
            
            // Create command channel
            let (cmd_tx, cmd_rx) = channel(100);
            
            // Create mesh instance
            let mut mesh = Self {
                local_peer_id,
                participant_id,
                swarm,
                cmd_tx: cmd_tx.clone(),
                cmd_rx: Some(cmd_rx),
                broadcast_sinks: HashMap::new(),
                direct_sink: None,
                participant_to_peer: HashMap::new(),
                peer_to_participant: HashMap::new(),
            };
            
            // Register self
            mesh.participant_to_peer.insert(participant_id, local_peer_id);
            mesh.peer_to_participant.insert(local_peer_id, participant_id);
            
            // Dial bootstrap peers
            for (_pid, addr) in bootstrap_peers {
                mesh.swarm.dial(addr)?;
                // Note: peer_id will be discovered via mDNS or when they connect
            }
            
            Ok(mesh)
        }

        pub fn local_peer_id(&self) -> PeerId {
            self.local_peer_id
        }
        
        pub async fn subscribe_broadcast(&mut self, topic: &str) -> Result<Receiver<Vec<u8>>> {
            let topic = MyTopic::new(topic);
            self.swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
            
            let (tx, rx) = channel(64);
            self.broadcast_sinks.insert(topic.hash(), tx);
            Ok(rx)
        }
        
        pub async fn subscribe_direct(&mut self) -> Result<Receiver<DirectMessage>> {
            let (tx, rx) = channel(64);
            self.direct_sink = Some(tx);
            Ok(rx)
        }
        
        pub fn run_background(mut self) -> MeshHandle {
            let mut cmd_rx = self.cmd_rx.take().expect("already running");
            let handle = MeshHandle {
                cmd_tx: self.cmd_tx.clone(),
                participant_id: self.participant_id,
            };
            
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        event = self.swarm.select_next_some() => {
                            match event {
                                SwarmEvent::Behaviour(MeshBehaviourEvent::Gossipsub(
                                    gossipsub::Event::Message { message, .. }
                                )) => {
                                    if let Some(sink) = self.broadcast_sinks.get(&message.topic) {
                                        let _ = sink.send(message.data).await;
                                    }
                                }
                                
                                SwarmEvent::Behaviour(MeshBehaviourEvent::RequestResponse(
                                    request_response::Event::Message { peer, message }
                                )) => {
                                    match message {
                                        request_response::Message::Request { request, channel, .. } => {
                                            // Try to deserialize as DirectMessage
                                            if let Ok(msg) = serde_json::from_slice::<DirectMessage>(&request) {
                                                // Learn mapping from incoming message
                                                // This allows peers to discover participant_id -> peer_id mapping lazily
                                                // and enables subsequent direct sends without prior registration.
                                                // Safe to overwrite to keep most recent mapping.
                                                // Note: no authentication of mapping beyond transport channel.
                                                self.participant_to_peer.insert(msg.from, peer);
                                                self.peer_to_participant.insert(peer, msg.from);
                                                if let Some(sink) = &self.direct_sink {
                                                    let _ = sink.send(msg).await;
                                                }
                                            }
                                            
                                            // Send acknowledgment
                                            let _ = self.swarm.behaviour_mut().request_response
                                                .send_response(channel, b"ACK".to_vec());
                                        }
                                        request_response::Message::Response { .. } => {}
                                    }
                                }
                                
                                SwarmEvent::Behaviour(MeshBehaviourEvent::Mdns(
                                    mdns::Event::Discovered(peers)
                                )) => {
                                    for (peer_id, addr) in peers {
                                        // Auto-discover peers via mDNS and proactively dial
                                        // so that direct request-response channels can be established.
                                        let _ = self.swarm.dial(addr);
                                        // Note: participant_id mapping is learned lazily from incoming
                                        // direct messages or explicit registration at higher layers.
                                        let _ = peer_id; // suppress unused warning if addr move fails
                                    }
                                }
                                
                                SwarmEvent::NewListenAddr { address, .. } => {
                                    println!("Listening on {}", address);
                                }
                                
                                _ => {}
                            }
                        }
                        
                        Some(cmd) = cmd_rx.recv() => {
                            match cmd {
                                Command::Broadcast { topic, data } => {
                                    let topic = MyTopic::new(&topic);
                                    let _ = self.swarm.behaviour_mut().gossipsub.subscribe(&topic);
                                    let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, data);
                                }
                                
                                Command::SendDirect { to, data, respond_to } => {
                                    if let Some(peer_id) = self.participant_to_peer.get(&to) {
                                        let msg = DirectMessage {
                                            from: self.participant_id,
                                            to,
                                            data: data.clone(),
                                            nonce: rand::random(),
                                        };
                                        
                                        let serialized = serde_json::to_vec(&msg).unwrap();
                                        let _request_id = self.swarm.behaviour_mut().request_response
                                            .send_request(peer_id, serialized);
                                        
                                        let _ = respond_to.send(Ok(()));
                                    } else {
                                        let _ = respond_to.send(Err(anyhow!("Unknown participant: {}", to)));
                                    }
                                }
                                
                                Command::RegisterPeer { participant_id, peer_id } => {
                                    self.participant_to_peer.insert(participant_id, peer_id);
                                    self.peer_to_participant.insert(peer_id, participant_id);
                                }
                            }
                        }
                    }
                }
            });
            
            handle
        }
    }
    
    impl MeshHandle {
        pub async fn broadcast(&self, topic: &str, data: Vec<u8>) -> Result<()> {
            self.cmd_tx.send(Command::Broadcast {
                topic: topic.to_string(),
                data,
            }).await?;
            Ok(())
        }
        
        pub async fn send_to(&self, participant_id: u16, data: Vec<u8>) -> Result<()> {
            let (tx, rx) = oneshot::channel();
            self.cmd_tx.send(Command::SendDirect {
                to: participant_id,
                data,
                respond_to: tx,
            }).await?;
            rx.await?
        }
        
        pub async fn register_peer(&self, participant_id: u16, peer_id: PeerId) -> Result<()> {
            self.cmd_tx.send(Command::RegisterPeer {
                participant_id,
                peer_id,
            }).await?;
            Ok(())
        }
        
        pub fn participant_id(&self) -> u16 {
            self.participant_id
        }
    }
}

// Stub for non-MPC builds
#[cfg(not(feature = "mpc"))]
pub mod p2p {
    use super::*;
    
    pub struct Mesh;
    pub struct MeshHandle;
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DirectMessage {
        pub from: u16,
        pub to: u16,
        pub data: Vec<u8>,
        pub nonce: u64,
    }
    
    impl Mesh {
        pub async fn new(
            _participant_id: u16,
            _listen_addr: Option<()>,
            _bootstrap_peers: Vec<(u16, ())>,
        ) -> Result<Self> {
            Ok(Self)
        }
        
        pub async fn subscribe_broadcast(&mut self, _topic: &str) -> Result<Receiver<Vec<u8>>> {
            let (_tx, rx) = channel(1);
            Ok(rx)
        }
        
        pub async fn subscribe_direct(&mut self) -> Result<Receiver<DirectMessage>> {
            let (_tx, rx) = channel(1);
            Ok(rx)
        }
        
        pub fn run_background(self) -> MeshHandle {
            MeshHandle
        }
    }
    
    impl MeshHandle {
        pub async fn broadcast(&self, _topic: &str, _data: Vec<u8>) -> Result<()> {
            Ok(())
        }
        
        pub async fn send_to(&self, _participant_id: u16, _data: Vec<u8>) -> Result<()> {
            Ok(())
        }
        
        pub fn participant_id(&self) -> u16 {
            0
        }
    }
}
