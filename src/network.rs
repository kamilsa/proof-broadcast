//! Networking layer: a libp2p swarm with QUIC transport and the
//! `/proof-tree/1` request-response protocol. No gossipsub.

use std::sync::Arc;
use std::time::Duration;

use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{Multiaddr, PeerId, Swarm, SwarmBuilder, identity};
use tracing::info;

use crate::protocol::{PROTOCOL, Traffic, TreeCodec};

#[derive(NetworkBehaviour)]
pub struct SimBehaviour {
    pub rr: request_response::Behaviour<TreeCodec>,
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

pub fn peer_id_from_seed(seed: u64) -> PeerId {
    PeerId::from(keypair_from_seed(seed).public())
}

/// Request-response limits.
#[derive(Clone, Copy, Debug)]
pub struct RrTuning {
    pub request_timeout: Duration,
    /// Inbound + outbound streams per connection (QUIC allows 256).
    pub max_concurrent_streams: usize,
}

impl Default for RrTuning {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(10),
            max_concurrent_streams: 256,
        }
    }
}

/// Build the swarm, listening on `listen_ip:listen_port`. Returns the
/// traffic counters the protocol codec fills.
pub fn build_swarm(
    seed: u64,
    listen_ip: &str,
    listen_port: u16,
    tuning: RrTuning,
) -> (Swarm<SimBehaviour>, PeerId, Arc<Traffic>) {
    let keypair = keypair_from_seed(seed);
    let local_peer_id = PeerId::from(keypair.public());
    info!(%local_peer_id, "building swarm");

    let codec = TreeCodec::default();
    let traffic = codec.traffic.clone();
    let config = request_response::Config::default()
        .with_request_timeout(tuning.request_timeout)
        .with_max_concurrent_streams(tuning.max_concurrent_streams);
    let rr = request_response::Behaviour::with_codec(codec, [(PROTOCOL, ProtocolSupport::Full)], config);

    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_quic()
        .with_dns()
        .expect("valid DNS configuration")
        .with_behaviour(|_key| SimBehaviour { rr })
        .expect("valid behaviour")
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();

    let listen_addr: Multiaddr = format!("/ip4/{listen_ip}/udp/{listen_port}/quic-v1")
        .parse()
        .expect("valid multiaddr");
    swarm.listen_on(listen_addr).expect("listen on QUIC");

    (swarm, local_peer_id, traffic)
}

/// Dial a list of peer multiaddrs.
pub fn dial_peers(swarm: &mut Swarm<SimBehaviour>, peers: &[Multiaddr]) {
    for addr in peers {
        info!(peer = %addr, "dialing peer");
        swarm.dial(addr.clone()).expect("dial peer");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypairs_are_deterministic() {
        assert_eq!(peer_id_from_seed(7), peer_id_from_seed(7));
        assert_ne!(peer_id_from_seed(7), peer_id_from_seed(8));
    }
}
