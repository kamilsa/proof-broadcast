//! Holder side: the peers we send chunks of each proof to.
//!
//! Every proof we hold, completely or in part, is served to at most `limit`
//! peers at a time: its downstream set. We announce (`Have`) a proof only to
//! its downstream peers, then keep them posted as our chunks grow. A slot
//! frees when its peer holds the proof (it says so with a full `Have`),
//! declines it (`Interest`), or disconnects; the node then offers the proof
//! to the next candidate. A `GetChunk` from a peer outside a full set is
//! refused (`Busy`).
//!
//! Candidates are tried in [`rank`] order: pseudo-random, deterministic, and
//! different for every proof, so load spreads over a node's peers.

use std::collections::{HashMap, HashSet};

use libp2p::PeerId;
use sha2::{Digest, Sha256};

/// Preference order of `peer` as a downstream of proof `hash` (lower first).
pub fn rank(peer: &PeerId, hash: &[u8; 32]) -> u64 {
    let mut h = Sha256::new();
    h.update(peer.to_bytes());
    h.update(hash);
    u64::from_le_bytes(h.finalize()[..8].try_into().expect("8 bytes"))
}

#[derive(Default)]
struct Downstream {
    /// Peers we serve, with the chunk count we last announced to them.
    active: Vec<(PeerId, usize)>,
    /// Peers holding the proof, or that declined it: never offered again.
    done: HashSet<PeerId>,
    /// Peers that got at least one chunk from us, and how many chunks.
    served: HashSet<PeerId>,
    chunks: usize,
}

pub struct Fanout {
    limit: usize,
    proofs: HashMap<[u8; 32], Downstream>,
    peak: usize,
}

impl Fanout {
    pub fn new(limit: usize) -> Self {
        Self {
            limit: limit.max(1),
            proofs: HashMap::new(),
            peak: 0,
        }
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    fn note_peak(&mut self, active: usize) {
        self.peak = self.peak.max(active);
    }

    /// Fill free slots of `hash` from `candidates` (in preference order),
    /// skipping peers already served or done. Returns the peers added.
    pub fn fill(&mut self, hash: &[u8; 32], candidates: impl IntoIterator<Item = PeerId>) -> Vec<PeerId> {
        let limit = self.limit;
        let d = self.proofs.entry(*hash).or_default();
        let mut added = Vec::new();
        for peer in candidates {
            if d.active.len() >= limit {
                break;
            }
            if d.done.contains(&peer) || d.active.iter().any(|(p, _)| *p == peer) {
                continue;
            }
            d.active.push((peer, 0));
            added.push(peer);
        }
        let active = d.active.len();
        self.note_peak(active);
        added
    }

    /// Downstream peers of `hash` last told about fewer than `held` chunks;
    /// they are now considered told about `held`.
    pub fn due(&mut self, hash: &[u8; 32], held: usize) -> Vec<PeerId> {
        let Some(d) = self.proofs.get_mut(hash) else {
            return Vec::new();
        };
        d.active
            .iter_mut()
            .filter(|(_, told)| *told < held)
            .map(|(peer, told)| {
                *told = held;
                *peer
            })
            .collect()
    }

    /// `peer` holds `hash` or will not fetch it from us: free its slot for
    /// good. True if it was a downstream peer.
    pub fn release(&mut self, hash: &[u8; 32], peer: PeerId) -> bool {
        let d = self.proofs.entry(*hash).or_default();
        d.done.insert(peer);
        let before = d.active.len();
        d.active.retain(|(p, _)| *p != peer);
        d.active.len() != before
    }

    /// A chunk request for `hash` from `peer`, who knows of `held` of our
    /// chunks: allowed if it is a downstream peer or a slot is free (it then
    /// becomes one).
    pub fn admit(&mut self, hash: &[u8; 32], peer: PeerId, held: usize) -> bool {
        let limit = self.limit;
        let d = self.proofs.entry(*hash).or_default();
        if d.active.iter().any(|(p, _)| *p == peer) {
            return true;
        }
        if d.active.len() >= limit {
            return false;
        }
        d.done.remove(&peer);
        d.active.push((peer, held));
        let active = d.active.len();
        self.note_peak(active);
        true
    }

    /// A chunk of `hash` was sent to `peer`.
    pub fn record_served(&mut self, hash: &[u8; 32], peer: PeerId) {
        let d = self.proofs.entry(*hash).or_default();
        d.served.insert(peer);
        d.chunks += 1;
    }

    pub fn is_done(&self, hash: &[u8; 32], peer: &PeerId) -> bool {
        self.proofs.get(hash).is_some_and(|d| d.done.contains(peer))
    }

    pub fn is_active(&self, hash: &[u8; 32], peer: &PeerId) -> bool {
        self.proofs
            .get(hash)
            .is_some_and(|d| d.active.iter().any(|(p, _)| p == peer))
    }

    pub fn active(&self, hash: &[u8; 32]) -> usize {
        self.proofs.get(hash).map_or(0, |d| d.active.len())
    }

    /// `peer` disconnected: free its slots. Returns the proofs with a slot
    /// freed.
    pub fn peer_gone(&mut self, peer: &PeerId) -> Vec<[u8; 32]> {
        let mut freed = Vec::new();
        for (hash, d) in &mut self.proofs {
            let before = d.active.len();
            d.active.retain(|(p, _)| p != peer);
            if d.active.len() != before {
                freed.push(*hash);
            }
        }
        freed
    }

    /// Most downstream peers any proof had at once.
    pub fn peak(&self) -> usize {
        self.peak
    }

    /// `(hash, distinct peers sent chunks, chunks sent)` for every proof we
    /// sent chunks of.
    pub fn served(&self) -> Vec<([u8; 32], usize, usize)> {
        let mut out: Vec<_> = self
            .proofs
            .iter()
            .filter(|(_, d)| d.chunks > 0)
            .map(|(h, d)| (*h, d.served.len(), d.chunks))
            .collect();
        out.sort();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::peer_id_from_seed as peer;

    const H: [u8; 32] = [1; 32];

    #[test]
    fn fill_respects_the_limit_and_skips_known_peers() {
        let mut f = Fanout::new(2);
        assert_eq!(f.fill(&H, [peer(1), peer(1), peer(2), peer(3)]), vec![peer(1), peer(2)]);
        assert_eq!(f.active(&H), 2);
        assert!(f.fill(&H, [peer(3)]).is_empty(), "no free slot");
        // A peer that declines frees its slot for good.
        assert!(f.release(&H, peer(1)));
        assert!(f.is_done(&H, &peer(1)));
        assert_eq!(f.fill(&H, [peer(1), peer(3)]), vec![peer(3)]);
        assert_eq!(f.peak(), 2);
        // Other proofs have their own slots.
        assert_eq!(f.fill(&[2; 32], [peer(1)]), vec![peer(1)]);
    }

    #[test]
    fn due_reports_peers_behind_our_chunk_count() {
        let mut f = Fanout::new(8);
        f.fill(&H, [peer(1), peer(2)]);
        assert_eq!(f.due(&H, 3), vec![peer(1), peer(2)]);
        assert!(f.due(&H, 3).is_empty(), "nothing new");
        f.fill(&H, [peer(3)]);
        assert_eq!(f.due(&H, 4), vec![peer(1), peer(2), peer(3)]);
        assert!(f.due(&[9; 32], 1).is_empty());
    }

    #[test]
    fn admit_takes_free_slots_only() {
        let mut f = Fanout::new(1);
        assert!(f.admit(&H, peer(1), 64));
        assert!(f.admit(&H, peer(1), 64), "already downstream");
        assert!(!f.admit(&H, peer(2), 64), "full: Busy");
        assert!(f.due(&H, 64).is_empty(), "it knows of all 64 chunks");
        let freed = f.peer_gone(&peer(1));
        assert_eq!(freed, vec![H]);
        assert!(!f.is_done(&H, &peer(1)), "a disconnect is not a refusal");
        assert!(f.admit(&H, peer(2), 64));
        assert!(f.is_active(&H, &peer(2)));
    }

    #[test]
    fn served_counts_distinct_peers_and_chunks() {
        let mut f = Fanout::new(8);
        f.record_served(&H, peer(1));
        f.record_served(&H, peer(1));
        f.record_served(&H, peer(2));
        assert_eq!(f.served(), vec![(H, 2, 3)]);
    }

    #[test]
    fn rank_differs_per_proof() {
        let order = |hash: &[u8; 32]| {
            let mut peers: Vec<PeerId> = (0..8).map(peer).collect();
            peers.sort_by_key(|p| rank(p, hash));
            peers
        };
        assert_eq!(order(&H), order(&H));
        assert_ne!(order(&H), order(&[2; 32]));
    }
}
