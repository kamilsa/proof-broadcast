//! Networking layer: libp2p swarm with QUIC transport and Gossipsub.
//!
//! Slimmed from ec-sim's `network.rs`: one proofs topic, one mesh profile.
//! Builds and configures the swarm; the node loop in `node.rs` drives it.

use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder,
    gossipsub::{self, IdentTopic, MessageAuthenticity},
    identity,
    swarm::NetworkBehaviour,
};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tracing::info;

/// Global proofs topic. L2 provers subscribe; L1 provers only publish to it.
pub const TOPIC_PROOFS: &str = "/proofs/1";

pub fn proofs_topic() -> IdentTopic {
    IdentTopic::new(TOPIC_PROOFS)
}

#[derive(NetworkBehaviour)]
pub struct SimBehaviour {
    pub gossipsub: gossipsub::Behaviour,
}

/// Build a deterministic libp2p keypair from a seed.
pub fn keypair_from_seed(seed: u64) -> identity::Keypair {
    // Stretch the u64 seed into 32 bytes for ed25519 secret key.
    let mut secret = [0u8; 32];
    let seed_bytes = seed.to_le_bytes();
    for (i, &b) in seed_bytes.iter().enumerate() {
        secret[i] = b;
        secret[i + 8] = b.wrapping_mul(31);
        secret[i + 16] = b.wrapping_mul(47);
        secret[i + 24] = b.wrapping_mul(59);
    }
    identity::Keypair::ed25519_from_bytes(secret).expect("valid ed25519 key from seed")
}

/// Mesh degrees for the proofs topic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeshTuning {
    /// Target mesh size (`D`); also the fanout size L1 provers publish to.
    pub mesh_n: usize,
    /// Mesh low-water mark (`D_low`): below this the mesh is topped up.
    pub mesh_n_low: usize,
    /// Mesh high-water mark (`D_high`): above this the mesh is trimmed.
    pub mesh_n_high: usize,
    /// Minimum number of outbound peers to keep in the mesh.
    pub mesh_outbound_min: usize,
}

impl Default for MeshTuning {
    fn default() -> Self {
        Self {
            mesh_n: 8,
            mesh_n_low: 6,
            mesh_n_high: 12,
            mesh_outbound_min: 3,
        }
    }
}

impl MeshTuning {
    /// Check the mesh inequalities gossipsub documents.
    pub fn validate(&self) -> Result<(), String> {
        let Self {
            mesh_outbound_min: outbound_min,
            mesh_n_low: n_low,
            mesh_n: n,
            mesh_n_high: n_high,
        } = *self;
        if !(outbound_min <= n_low && n_low <= n && n <= n_high) {
            return Err(format!(
                "proofs mesh parameters must satisfy \
                 mesh_outbound_min <= mesh_n_low <= mesh_n <= mesh_n_high, got {outbound_min} <= {n_low} <= {n} <= {n_high}"
            ));
        }
        if outbound_min * 2 > n {
            return Err(format!(
                "proofs mesh parameters must satisfy mesh_outbound_min * 2 <= mesh_n, \
                 got {outbound_min} * 2 > {n}"
            ));
        }
        Ok(())
    }
}

/// Gossipsub fan-out tuning. Defaults follow Ethereum clients
/// (`flood_publish = false`) with lazy gossip off so amplification does not
/// dominate the comparison.
#[derive(Clone, Copy, Debug)]
pub struct GossipTuning {
    pub flood_publish: bool,
    pub gossip_lazy: usize,
    pub gossip_factor: f64,
    pub mesh: MeshTuning,
}

impl Default for GossipTuning {
    fn default() -> Self {
        Self {
            flood_publish: false,
            gossip_lazy: 0,
            gossip_factor: 0.0,
            mesh: MeshTuning::default(),
        }
    }
}

fn content_message_id(message: &gossipsub::Message) -> gossipsub::MessageId {
    let topic = message.topic.as_str().as_bytes();
    let mut hasher = Sha256::new();
    hasher.update((topic.len() as u64).to_le_bytes());
    hasher.update(topic);
    hasher.update(&message.data);
    gossipsub::MessageId::from(hasher.finalize().to_vec())
}

fn gossipsub_config(tuning: &GossipTuning) -> gossipsub::Config {
    let mesh = tuning.mesh;
    let mut builder = gossipsub::ConfigBuilder::default();
    builder
        .heartbeat_interval(Duration::from_millis(700))
        .mesh_n_low(mesh.mesh_n_low)
        .mesh_n(mesh.mesh_n)
        .mesh_n_high(mesh.mesh_n_high)
        .mesh_outbound_min(mesh.mesh_outbound_min)
        .flood_publish(tuning.flood_publish)
        .gossip_lazy(tuning.gossip_lazy)
        .gossip_factor(tuning.gossip_factor)
        .history_length(5)
        .history_gossip(3)
        .max_transmit_size(16 * 1024 * 1024)
        .message_id_fn(content_message_id)
        // L2 provers decide per message whether to forward it (first proof
        // per subnet only), so forwarding waits for the application verdict.
        .validate_messages()
        .validation_mode(gossipsub::ValidationMode::Permissive);
    builder.build().expect("valid gossipsub config")
}

/// Build and configure the libp2p swarm, listening on `listen_ip:listen_port`.
pub fn build_swarm(
    seed: u64,
    listen_ip: &str,
    listen_port: u16,
    tuning: &GossipTuning,
) -> (Swarm<SimBehaviour>, PeerId) {
    let keypair = keypair_from_seed(seed);
    let local_peer_id = PeerId::from(keypair.public());
    info!(%local_peer_id, "building swarm");

    let gossipsub = gossipsub::Behaviour::new(
        MessageAuthenticity::Signed(keypair.clone()),
        gossipsub_config(tuning),
    )
    .expect("valid gossipsub behaviour");

    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_quic()
        .with_dns()
        .expect("valid DNS configuration")
        .with_behaviour(|_key| SimBehaviour { gossipsub })
        .expect("valid behaviour")
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();

    let listen_addr: Multiaddr = format!("/ip4/{listen_ip}/udp/{listen_port}/quic-v1")
        .parse()
        .expect("valid multiaddr");
    swarm.listen_on(listen_addr).expect("listen on QUIC");

    (swarm, local_peer_id)
}

/// Subscribe to a topic with the gossipsub 1.3 partial-message protocol enabled.
///
/// `enable_partials_for_topic` must be called *before* `subscribe` — the
/// behaviour ignores it once the topic is already in the mesh.
pub fn subscribe_partial(swarm: &mut Swarm<SimBehaviour>, topic: &IdentTopic) {
    let gossipsub = &mut swarm.behaviour_mut().gossipsub;
    gossipsub.enable_partials_for_topic(topic.hash(), true);
    gossipsub.subscribe(topic).expect("subscribe partial topic");
}

/// Dial a list of bootstrap peer multiaddrs.
pub fn dial_peers(swarm: &mut Swarm<SimBehaviour>, peers: &[Multiaddr]) {
    for addr in peers {
        info!(peer = %addr, "dialing peer");
        swarm.dial(addr.clone()).expect("dial peer");
    }
}

/// Number of mesh peers currently grafted on `topic`.
pub fn mesh_peer_count(swarm: &Swarm<SimBehaviour>, topic: &IdentTopic) -> usize {
    swarm
        .behaviour()
        .gossipsub
        .mesh_peers(&topic.hash())
        .count()
}

/// Number of connected peers subscribed to `topic`. L1 provers never join the
/// mesh and publish through fanout, so this is their readiness signal.
pub fn topic_peer_count(swarm: &Swarm<SimBehaviour>, topic: &IdentTopic) -> usize {
    let hash = topic.hash();
    swarm
        .behaviour()
        .gossipsub
        .all_peers()
        .filter(|(_, topics)| topics.contains(&&hash))
        .count()
}

/// Cumulative gossipsub tx/rx bytes (payload + partial metadata + control).
pub fn gossip_byte_totals(swarm: &Swarm<SimBehaviour>) -> (u64, u64) {
    fn dir_total(c: &gossipsub::TrafficCounters) -> u64 {
        c.data_bytes + c.meta_bytes + c.control_bytes.iter().sum::<u64>()
    }
    let stats = swarm.behaviour().gossipsub.traffic();
    let mut tx = dir_total(&stats.untopiced.tx);
    let mut rx = dir_total(&stats.untopiced.rx);
    for d in stats.per_topic.values() {
        tx += dir_total(&d.tx);
        rx += dir_total(&d.rx);
    }
    (tx, rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mesh_is_valid() {
        MeshTuning::default().validate().unwrap();
    }

    #[test]
    fn rejects_inverted_mesh() {
        let mesh = MeshTuning {
            mesh_n: 4,
            mesh_n_low: 6,
            mesh_n_high: 12,
            mesh_outbound_min: 2,
        };
        assert!(mesh.validate().is_err());
    }

    #[test]
    fn rejects_outbound_heavy_mesh() {
        let mesh = MeshTuning {
            mesh_n: 4,
            mesh_n_low: 3,
            mesh_n_high: 12,
            mesh_outbound_min: 3,
        };
        assert!(mesh.validate().is_err());
    }

    #[test]
    fn keypairs_are_deterministic() {
        let a = PeerId::from(keypair_from_seed(7).public());
        let b = PeerId::from(keypair_from_seed(7).public());
        let c = PeerId::from(keypair_from_seed(8).public());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
