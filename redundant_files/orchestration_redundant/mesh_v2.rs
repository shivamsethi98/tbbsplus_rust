// Hybrid mesh network implementation supporting both broadcast and point-to-point communication
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use tokio::sync::{mpsc::{channel, Sender, Receiver}, oneshot};

#[cfg(feature = "mpc")]
pub mod p2p {
    use super::*;
    use libp2p::{
        gossipsub::{self, MessageId, MessageAuthenticity, Topic},
        identity::Keypair,
        kad::{self, store::MemoryStore},
        mdns,
        noise,
        request_response::{self, ProtocolSupport},
        swarm::{NetworkBehaviour, SwarmEvent},
        tcp,
        yamux,
        Multiaddr, PeerId, Transport, SwarmBuilder,
    };
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    // Protocol for direct messages
    #[derive(Debug, Clone)]
    struct DirectMessageProtocol;
    
    impl request_response::ProtocolName for DirectMessageProtocol {
        fn protocol_name(&self) -> &[u8] {
            b"/threshold-bbs/direct/1.0.0"
        }
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DirectMessage {
        pub from: u16,  // ParticipantId
        pub to: u16,    // ParticipantId
        pub data: Vec<u8>,
        pub nonce: u64,
    }
    
    // Combined network behaviour
    #[derive(NetworkBehaviour)]
    struct MeshBehaviour {
        gossipsub: gossipsub::Behaviour,
        request_response: request_response::Behaviour<DirectMessageCodec>,
        kademlia: Kademlia<MemoryStore>,
        mdns: mdns::tokio::Behaviour,
    }
    
    // Codec for direct messages
    #[derive(Clone)]
    struct DirectMessageCodec;
    
    impl request_response::Codec for DirectMessageCodec {
        type Protocol = DirectMessageProtocol;
        type Request = Vec<u8>;
        type Response = Vec<u8>;
        
        async fn read_request<T>(
            &mut self,
            _: &DirectMessageProtocol,
            io: &mut T,
        ) -> std::io::Result<Self::Request>
        where
            T: futures::AsyncRead + Unpin + Send,
        {
            let mut buf = Vec::new();
            futures::AsyncReadExt::read_to_end(io, &mut buf).await?;
            Ok(buf)
        }
        
        async fn read_response<T>(
            &mut self,
            _: &DirectMessageProtocol,
            io: &mut T,
        ) -> std::io::Result<Self::Response>
        where
            T: futures::AsyncRead + Unpin + Send,
        {
            let mut buf = Vec::new();
            futures::AsyncReadExt::read_to_end(io, &mut buf).await?;
            Ok(buf)
        }
        
        async fn write_request<T>(
            &mut self,
            _: &DirectMessageProtocol,
            io: &mut T,
            req: Self::Request,
        ) -> std::io::Result<()>
        where
            T: futures::AsyncWrite + Unpin + Send,
        {
            futures::AsyncWriteExt::write_all(io, &req).await
        }
        
        async fn write_response<T>(
            &mut self,
            _: &DirectMessageProtocol,
            io: &mut T,
            res: Self::Response,
        ) -> std::io::Result<()>
        where
            T: futures::AsyncWrite + Unpin + Send,
        {
            futures::AsyncWriteExt::write_all(io, &res).await
        }
    }
    
    // Command for internal communication
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
        GetPeers {
            respond_to: oneshot::Sender<HashMap<u16, PeerId>>,
        },
    }
    
    pub struct Mesh {
        local_peer_id: PeerId,
        participant_id: u16,
        swarm: libp2p::Swarm<MeshBehaviour>,
        
        // Channels for async operation
        cmd_tx: Sender<Command>,
        cmd_rx: Option<Receiver<Command>>,
        
        // Subscriptions
        broadcast_sinks: HashMap<Topic, Sender<Vec<u8>>>,
        direct_sink: Option<Sender<DirectMessage>>,
        
        // Peer mappings
        participant_to_peer: HashMap<u16, PeerId>,
        peer_to_participant: HashMap<PeerId, u16>,
    }
    
    pub struct MeshHandle {
        cmd_tx: Sender<Command>,
        participant_id: u16,
    }
    
    impl Mesh {
        pub async fn new(
            participant_id: u16,
            listen_addr: Option<Multiaddr>,
            bootstrap_peers: Vec<(u16, Multiaddr)>,  // (ParticipantId, Address) pairs
        ) -> Result<Self> {
            // Generate deterministic keypair based on participant ID for reproducibility
            let keypair = {
                let mut bytes = [0u8; 32];
                bytes[0] = participant_id as u8;
                bytes[1] = (participant_id >> 8) as u8;
                Keypair::ed25519_from_bytes(bytes)?
            };
            
            let local_peer_id = PeerId::from(keypair.public());
            
            // Create transport
            let transport = tcp::tokio::Transport::new(tcp::Config::new())
                .upgrade(upgrade::Version::V1)
                .authenticate(noise::Config::new(&keypair)?)
                .multiplex(yamux::Config::default())
                .boxed();
            
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
            )?;
            
            // Configure request-response
            let request_response = request_response::Behaviour::new(
                DirectMessageCodec,
                [(DirectMessageProtocol, ProtocolSupport::Full)],
                request_response::Config::default(),
            );
            
            // Configure Kademlia
            let mut kad_config = KademliaConfig::default();
            kad_config.set_query_timeout(Duration::from_secs(5));
            let kademlia = Kademlia::with_config(
                local_peer_id,
                MemoryStore::new(local_peer_id),
                kad_config,
            );
            
            // Configure mDNS
            let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;
            
            // Create swarm
            let behaviour = MeshBehaviour {
                gossipsub,
                request_response,
                kademlia,
                mdns,
            };
            
            let mut swarm = SwarmBuilder::with_tokio_executor(transport, behaviour, local_peer_id)
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
            
            // Add bootstrap peers
            for (pid, addr) in bootstrap_peers {
                // Extract peer_id from address if possible
                if let Some(peer_id) = addr.iter().find_map(|p| {
                    if let libp2p::multiaddr::Protocol::P2p(hash) = p {
                        PeerId::from_multihash(hash).ok()
                    } else {
                        None
                    }
                }) {
                    mesh.participant_to_peer.insert(pid, peer_id);
                    mesh.peer_to_participant.insert(peer_id, pid);
                    mesh.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                }
                
                // Dial the peer
                mesh.swarm.dial(addr)?;
            }
            
            Ok(mesh)
        }
        
        pub async fn subscribe_broadcast(&mut self, topic: &str) -> Result<Receiver<Vec<u8>>> {
            let topic = Topic::new(topic);
            self.swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
            
            let (tx, rx) = channel(64);
            self.broadcast_sinks.insert(topic, tx);
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
                        // Handle swarm events
                        event = self.swarm.select_next_some() => {
                            match event {
                                SwarmEvent::Behaviour(MeshBehaviourEvent::Gossipsub(
                                    gossipsub::Event::Message { propagation_source, message_id, message }
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
                                            // Handle incoming direct message
                                            if let Ok(msg) = serde_json::from_slice::<DirectMessage>(&request) {
                                                if let Some(sink) = &self.direct_sink {
                                                    let _ = sink.send(msg).await;
                                                }
                                            }
                                            
                                            // Send acknowledgment
                                            let _ = self.swarm.behaviour_mut().request_response
                                                .send_response(channel, b"ACK".to_vec());
                                        }
                                        request_response::Message::Response { .. } => {
                                            // Response handled elsewhere
                                        }
                                    }
                                }
                                
                                SwarmEvent::Behaviour(MeshBehaviourEvent::Mdns(
                                    mdns::Event::Discovered(peers)
                                )) => {
                                    for (peer_id, addr) in peers {
                                        self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                                    }
                                }
                                
                                _ => {}
                            }
                        }
                        
                        // Handle commands
                        Some(cmd) = cmd_rx.recv() => {
                            match cmd {
                                Command::Broadcast { topic, data } => {
                                    let topic = Topic::new(&topic);
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
                                        let request_id = self.swarm.behaviour_mut().request_response
                                            .send_request(peer_id, serialized);
                                        
                                        // For now, assume success
                                        let _ = respond_to.send(Ok(()));
                                    } else {
                                        let _ = respond_to.send(Err(anyhow!("Unknown participant: {}", to)));
                                    }
                                }
                                
                                Command::RegisterPeer { participant_id, peer_id } => {
                                    self.participant_to_peer.insert(participant_id, peer_id);
                                    self.peer_to_participant.insert(peer_id, participant_id);
                                }
                                
                                Command::GetPeers { respond_to } => {
                                    let _ = respond_to.send(self.participant_to_peer.clone());
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
        
        pub async fn get_peers(&self) -> Result<HashMap<u16, PeerId>> {
            let (tx, rx) = oneshot::channel();
            self.cmd_tx.send(Command::GetPeers {
                respond_to: tx,
            }).await?;
            Ok(rx.await?)
        }
        
        pub fn participant_id(&self) -> u16 {
            self.participant_id
        }
    }
}

// Stub implementation for non-MPC builds
#[cfg(not(feature = "mpc"))]
pub mod p2p {
    use super::*;
    
    pub struct Mesh;
    pub struct MeshHandle;
    
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
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DirectMessage {
        pub from: u16,
        pub to: u16,
        pub data: Vec<u8>,
        pub nonce: u64,
    }
    
    impl MeshHandle {
        pub async fn broadcast(&self, _topic: &str, _data: Vec<u8>) -> Result<()> {
            Ok(())
        }
        
        pub async fn send_to(&self, _participant_id: u16, _data: Vec<u8>) -> Result<()> {
            Ok(())
        }
    }
}
