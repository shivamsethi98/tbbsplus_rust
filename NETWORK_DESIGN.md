# Network Design for Threshold BBS+ MPC

## Overview
This document describes the networking layer for the threshold BBS+ signature protocol, focusing on privacy, reliability, and proper MPC semantics.

## Requirements

### Functional Requirements
1. **Peer Discovery**: Nodes must find each other by ParticipantID
2. **Broadcast**: Some messages (commitments) need to reach all participants
3. **Point-to-Point**: Share exchanges must be private between two parties
4. **Reliability**: Critical messages must be delivered exactly once
5. **Ordering**: Messages within a phase must be processed in correct order

### Privacy Requirements
1. **No Public Shares**: Secret shares must never be broadcast
2. **Encrypted Channels**: All communication must be encrypted
3. **Authenticated Peers**: Only authorized participants can join

### Performance Requirements
1. Support up to 100 participants
2. Handle messages up to 10MB
3. Complete protocol in < 10 seconds on LAN

## Architecture

### Three-Layer Design

```
┌─────────────────────────────────────┐
│         Application Layer           │
│   (ThresholdPhases, Coordinators)   │
└─────────────────────────────────────┘
                  ↕
┌─────────────────────────────────────┐
│        Messaging Layer              │
│  (Broadcast, P2P, Request-Response) │
└─────────────────────────────────────┘
                  ↕
┌─────────────────────────────────────┐
│         Transport Layer             │
│    (libp2p with TLS/Noise)          │
└─────────────────────────────────────┘
```

### Discovery Mechanism

1. **Bootstrap Phase**
   - Nodes start with a list of known peers (seed nodes)
   - Exchange ParticipantID ↔ PeerID mappings
   - Build routing table

2. **Runtime Discovery**
   - Use Kademlia DHT for finding peers by ID
   - mDNS for local network discovery
   - Fallback to bootstrap nodes if needed

### Communication Patterns

#### Pattern 1: Broadcast (for public data)
```rust
// Used for: Phase 1 commitments, final signature shares
mesh.broadcast("topic", data).await?;
```

#### Pattern 2: Direct Send (for private data)
```rust
// Used for: Phase 1 shares, Phase 2 round 1&2 messages
mesh.send_to(participant_id, data).await?;
```

#### Pattern 3: Request-Response (for reliability)
```rust
// Used when acknowledgment is needed
let response = mesh.request(participant_id, request).await?;
```

## Message Types

### Phase 1 Messages
```rust
enum Phase1Message {
    // Broadcast to all
    Commitment {
        from: ParticipantId,
        data: Vec<u8>,
    },
    
    // Direct send to specific peer
    ShareExchange {
        from: ParticipantId,
        to: ParticipantId,
        share: Vec<u8>,
        zero_share: Vec<u8>,
    },
}
```

### Phase 2 Messages
```rust
enum Phase2Message {
    // Direct send to specific peer
    Round1 {
        from: ParticipantId,
        to: ParticipantId,
        data: Vec<u8>,
    },
    
    // Direct response to Round1
    Round2 {
        from: ParticipantId,
        to: ParticipantId,
        data: Vec<u8>,
    },
}
```

## Implementation Plan

### Step 1: Core Mesh Module
```rust
pub struct Mesh {
    peer_id: PeerId,
    participant_id: ParticipantId,
    swarm: Swarm<CombinedBehaviour>,
    peers: HashMap<ParticipantId, PeerId>,
}

impl Mesh {
    // Broadcast to all peers
    pub async fn broadcast(&mut self, topic: &str, data: &[u8]) -> Result<()>;
    
    // Send directly to a specific participant
    pub async fn send_to(&mut self, to: ParticipantId, data: &[u8]) -> Result<()>;
    
    // Request-response pattern
    pub async fn request(&mut self, to: ParticipantId, req: &[u8]) -> Result<Vec<u8>>;
    
    // Subscribe to broadcasts
    pub async fn subscribe(&mut self, topic: &str) -> Result<Receiver<Vec<u8>>>;
    
    // Get incoming direct messages
    pub async fn direct_messages(&mut self) -> Receiver<(ParticipantId, Vec<u8>)>;
}
```

### Step 2: Combined Network Behaviour
```rust
#[derive(NetworkBehaviour)]
struct CombinedBehaviour {
    gossipsub: Gossipsub,        // For broadcasts
    request_response: RequestResponse,  // For direct messages
    kademlia: Kademlia,          // For peer discovery
    mdns: Mdns,                  // For local discovery
    identify: Identify,          // For peer identification
}
```

### Step 3: Message Routing
- Commitments → Gossipsub broadcast
- Share exchanges → Request-Response protocol
- Phase 2 messages → Request-Response protocol

## Security Considerations

1. **Transport Security**: Use libp2p's Noise protocol
2. **Message Authentication**: Sign messages with participant keys
3. **Replay Protection**: Include nonces/timestamps
4. **DOS Protection**: Rate limiting per peer

## Migration Path

1. Keep existing message structures
2. Replace broadcast-only mesh with new hybrid mesh
3. Update coordinators to use appropriate communication pattern
4. Add peer discovery phase before protocol start
