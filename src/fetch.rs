//! Requester side of the chunk pull: which proof fills each input slot of
//! our tree node, who holds which of its chunks, and which chunk to ask whom
//! for next.
//!
//! One slot per input of the node. The first proof announced (`Have`) for a
//! slot is committed; any other proof for that slot is declined, so an L2
//! never downloads two proofs covering the same input. Every peer that
//! announces the committed proof becomes a holder, with the chunks it holds
//! (a holder may still be downloading: its bitmap grows with later `Have`s).
//! Each missing chunk is asked of the least loaded holder that has it, at
//! most `max_inflight_per_peer` outstanding per peer (counted across slots).
//! Failed requests are re-queued.
//!
//! Pure state: the node turns [`ChunkRequest`]s into `GetChunk` requests and
//! reports back what happened to each.

use std::collections::{HashMap, HashSet};

use libp2p::PeerId;

use crate::assembly::{ChunkBits, ProofAssembly};
use crate::proof::{Committees, ProofId};

/// One chunk to ask one peer for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChunkRequest {
    pub peer: PeerId,
    pub hash: [u8; 32],
    pub index: u16,
}

/// What an announcement meant to us.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HaveOutcome {
    /// First proof seen for its slot: committed, the sender is its holder.
    Committed,
    /// A holder (new, or with more chunks) of a proof we are still fetching.
    Holder,
    /// We already hold this proof.
    Known,
    /// Another proof fills that slot. `first` the first time for this hash.
    Declined { first: bool },
    /// Not an input of our node.
    Unwanted,
}

impl HaveOutcome {
    /// Whether we may fetch chunks of this proof from the announcer.
    pub fn wanted(self) -> bool {
        matches!(self, Self::Committed | Self::Holder)
    }
}

/// What a received chunk did.
#[derive(Debug, PartialEq, Eq)]
pub enum ChunkOutcome {
    /// Not a chunk we are fetching (late, or of a proof we finished).
    Unexpected,
    /// Wrong length for its index: the request is re-queued.
    Malformed,
    /// Already held.
    Duplicate,
    /// New chunk; `held` chunks of the proof are now present.
    Added { id: ProofId, held: usize },
    /// The last chunk: the proof is verified and complete.
    Completed { id: ProofId, proof: Vec<u8> },
    /// Every chunk arrived but the hash did not match; fetching restarts.
    Invalid { id: ProofId },
}

struct Holder {
    peer: PeerId,
    chunks: ChunkBits,
}

struct Choice {
    assembly: ProofAssembly,
    /// In announcement order.
    holders: Vec<Holder>,
    /// Chunk index -> peer asked for it.
    inflight: HashMap<u16, PeerId>,
}

struct Slot {
    mask: Committees,
    choice: Option<Choice>,
    done: bool,
}

pub struct Fetcher {
    max_inflight_per_peer: usize,
    slots: Vec<Slot>,
    peer_load: HashMap<PeerId, usize>,
    declined: HashSet<[u8; 32]>,
}

impl Fetcher {
    pub fn new(input_masks: &[Committees], max_inflight_per_peer: usize) -> Self {
        Self {
            max_inflight_per_peer: max_inflight_per_peer.max(1),
            slots: input_masks
                .iter()
                .map(|&mask| Slot {
                    mask,
                    choice: None,
                    done: false,
                })
                .collect(),
            peer_load: HashMap::new(),
            declined: HashSet::new(),
        }
    }

    fn slot_of_hash(&self, hash: &[u8; 32]) -> Option<usize> {
        self.slots.iter().position(|s| {
            s.choice
                .as_ref()
                .is_some_and(|c| &c.assembly.id.hash == hash)
        })
    }

    fn load(&self, peer: &PeerId) -> usize {
        self.peer_load.get(peer).copied().unwrap_or(0)
    }

    /// `peer` announced it holds `chunks` of `id` (`chunks` must already be
    /// valid for `id`).
    pub fn on_have(&mut self, peer: PeerId, id: &ProofId, chunks: &ChunkBits) -> HaveOutcome {
        let Some(slot) = self.slots.iter_mut().find(|s| s.mask == id.committees) else {
            return HaveOutcome::Unwanted;
        };
        match &mut slot.choice {
            None => {
                slot.choice = Some(Choice {
                    assembly: ProofAssembly::new(*id),
                    holders: vec![Holder {
                        peer,
                        chunks: chunks.clone(),
                    }],
                    inflight: HashMap::new(),
                });
                HaveOutcome::Committed
            }
            Some(choice) if choice.assembly.id.hash == id.hash => {
                if slot.done {
                    return HaveOutcome::Known;
                }
                match choice.holders.iter_mut().find(|h| h.peer == peer) {
                    Some(holder) => holder.chunks.union_with(chunks),
                    None => choice.holders.push(Holder {
                        peer,
                        chunks: chunks.clone(),
                    }),
                }
                HaveOutcome::Holder
            }
            Some(_) => HaveOutcome::Declined {
                first: self.declined.insert(id.hash),
            },
        }
    }

    /// The next chunk requests to send, up to every holder's capacity.
    pub fn next_requests(&mut self) -> Vec<ChunkRequest> {
        let mut out = Vec::new();
        let cap = self.max_inflight_per_peer;
        for s in 0..self.slots.len() {
            let slot = &self.slots[s];
            let Some(choice) = slot.choice.as_ref().filter(|_| !slot.done) else {
                continue;
            };
            let wanted: Vec<u16> = choice
                .assembly
                .missing()
                .map(|i| i as u16)
                .filter(|i| !choice.inflight.contains_key(i))
                .collect();
            let mut placed = Vec::new();
            for index in wanted {
                // The least loaded holder with room that has the chunk;
                // earlier holders win ties.
                let mut room = false;
                let mut pick: Option<(usize, PeerId)> = None;
                for h in &choice.holders {
                    let load = self.load(&h.peer);
                    if load >= cap {
                        continue;
                    }
                    room = true;
                    if h.chunks.get(index as usize) && pick.is_none_or(|(best, _)| load < best) {
                        pick = Some((load, h.peer));
                    }
                }
                if !room {
                    break;
                }
                if let Some((_, peer)) = pick {
                    *self.peer_load.entry(peer).or_default() += 1;
                    placed.push((index, peer));
                }
            }
            let choice = self.slots[s].choice.as_mut().expect("checked above");
            for (index, peer) in placed {
                choice.inflight.insert(index, peer);
                out.push(ChunkRequest {
                    peer,
                    hash: choice.assembly.id.hash,
                    index,
                });
            }
        }
        out
    }

    /// Clear the in-flight entry of `req` (if it is still the live one).
    fn settle(&mut self, req: &ChunkRequest) -> Option<usize> {
        let slot = self.slot_of_hash(&req.hash)?;
        let choice = self.slots[slot].choice.as_mut()?;
        if choice.inflight.get(&req.index) == Some(&req.peer) {
            choice.inflight.remove(&req.index);
            if let Some(load) = self.peer_load.get_mut(&req.peer) {
                *load = load.saturating_sub(1);
            }
        }
        Some(slot)
    }

    /// A chunk arrived in answer to `req`.
    pub fn on_chunk(&mut self, req: &ChunkRequest, data: &[u8]) -> ChunkOutcome {
        let Some(slot) = self.settle(req) else {
            return ChunkOutcome::Unexpected;
        };
        if self.slots[slot].done {
            return ChunkOutcome::Unexpected;
        }
        let choice = self.slots[slot].choice.as_mut().expect("settled slot has a choice");
        let id = choice.assembly.id;
        if id.chunk_len(req.index as usize) != Some(data.len()) {
            return ChunkOutcome::Malformed;
        }
        let out = choice.assembly.merge_one(req.index as usize, data);
        if let Some(proof) = out.completed {
            self.slots[slot].done = true;
            return ChunkOutcome::Completed { id, proof };
        }
        if out.invalid {
            return ChunkOutcome::Invalid { id };
        }
        if out.added == 0 {
            return ChunkOutcome::Duplicate;
        }
        ChunkOutcome::Added { id, held: out.held }
    }

    /// `req` failed (timeout, error, or the peer answered `Missing`/`Busy`).
    /// With `drop_holder`, the peer is no longer asked for that proof (until
    /// it announces it again).
    pub fn on_failure(&mut self, req: &ChunkRequest, drop_holder: bool) {
        let Some(slot) = self.settle(req) else {
            return;
        };
        if drop_holder && let Some(choice) = self.slots[slot].choice.as_mut() {
            choice.holders.retain(|h| h.peer != req.peer);
        }
    }

    /// `peer` disconnected: forget it as a holder and re-queue its chunks.
    pub fn on_peer_gone(&mut self, peer: &PeerId) {
        for choice in self.slots.iter_mut().filter_map(|s| s.choice.as_mut()) {
            choice.holders.retain(|h| &h.peer != peer);
            choice.inflight.retain(|_, p| p != peer);
        }
        self.peer_load.remove(peer);
    }

    /// Peers that announced the proof `hash` to us.
    pub fn holders(&self, hash: &[u8; 32]) -> Vec<PeerId> {
        self.slot_of_hash(hash)
            .and_then(|s| self.slots[s].choice.as_ref())
            .map(|c| c.holders.iter().map(|h| h.peer).collect())
            .unwrap_or_default()
    }

    /// The assembly of a committed proof (complete or not), to serve from.
    pub fn assembly(&self, hash: &[u8; 32]) -> Option<&ProofAssembly> {
        let slot = self.slot_of_hash(hash)?;
        self.slots[slot].choice.as_ref().map(|c| &c.assembly)
    }

    /// Committed proofs still being fetched of which we hold some chunks.
    pub fn partial(&self) -> impl Iterator<Item = &ProofAssembly> {
        self.slots
            .iter()
            .filter(|s| !s.done)
            .filter_map(|s| s.choice.as_ref())
            .map(|c| &c.assembly)
            .filter(|a| a.held() > 0)
    }

    pub fn slots(&self) -> usize {
        self.slots.len()
    }

    pub fn done(&self) -> usize {
        self.slots.iter().filter(|s| s.done).count()
    }

    pub fn all_done(&self) -> bool {
        self.slots.iter().all(|s| s.done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::peer_id_from_seed as peer;
    use crate::proof::{make_proof, split};

    fn proof(subnet: u16, prover: u16, chunks: usize) -> (ProofId, Vec<Vec<u8>>) {
        let bytes = make_proof(subnet as u64 * 10 + prover as u64, 800);
        let id = ProofId::for_proof(subnet, prover, &bytes, chunks);
        (id, split(&bytes, id.chunks()))
    }

    fn all(id: &ProofId) -> ChunkBits {
        ChunkBits::full(id.chunks())
    }

    fn some(id: &ProofId, indices: &[usize]) -> ChunkBits {
        let mut b = ChunkBits::empty(id.chunks());
        indices.iter().for_each(|&i| b.set(i));
        b
    }

    #[test]
    fn first_announced_proof_per_slot_is_committed() {
        let (a, _) = proof(0, 0, 4);
        let (b, _) = proof(0, 1, 4);
        let (c, _) = proof(2, 0, 4);
        let mut f = Fetcher::new(&[0b01, 0b10], 64);
        assert_eq!(f.on_have(peer(1), &a, &all(&a)), HaveOutcome::Committed);
        assert_eq!(f.on_have(peer(2), &a, &all(&a)), HaveOutcome::Holder);
        assert_eq!(f.on_have(peer(2), &b, &all(&b)), HaveOutcome::Declined { first: true });
        assert_eq!(f.on_have(peer(3), &b, &all(&b)), HaveOutcome::Declined { first: false });
        assert_eq!(f.on_have(peer(1), &c, &all(&c)), HaveOutcome::Unwanted);
        assert!(HaveOutcome::Committed.wanted() && HaveOutcome::Holder.wanted());
        assert!(!HaveOutcome::Declined { first: true }.wanted());
        assert_eq!(f.holders(&a.hash), vec![peer(1), peer(2)]);
        assert!(f.holders(&b.hash).is_empty());
        assert_eq!(f.slots(), 2);
    }

    #[test]
    fn chunks_are_striped_over_holders_within_the_cap() {
        let (a, parts) = proof(0, 0, 8);
        let mut f = Fetcher::new(&[0b1], 3);
        f.on_have(peer(1), &a, &all(&a));
        f.on_have(peer(2), &a, &all(&a));
        let reqs = f.next_requests();
        assert_eq!(reqs.len(), 6);
        assert_eq!(reqs.iter().filter(|r| r.peer == peer(1)).count(), 3);
        assert_eq!(reqs.iter().filter(|r| r.peer == peer(2)).count(), 3);
        assert!(f.next_requests().is_empty(), "both holders are at the cap");
        let first = reqs[0];
        assert_eq!(
            f.on_chunk(&first, &parts[first.index as usize]),
            ChunkOutcome::Added { id: a, held: 1 }
        );
        // One slot freed: one more request, to the peer that answered.
        let more = f.next_requests();
        assert_eq!(more.len(), 1);
        assert_eq!(more[0].peer, first.peer);
    }

    #[test]
    fn partial_holders_are_asked_only_for_chunks_they_have() {
        let (a, parts) = proof(0, 0, 8);
        let mut f = Fetcher::new(&[0b1], 64);
        // A relay still downloading: it has chunks 0 and 1 so far.
        assert_eq!(f.on_have(peer(1), &a, &some(&a, &[0, 1])), HaveOutcome::Committed);
        let reqs = f.next_requests();
        assert_eq!(reqs.iter().map(|r| r.index).collect::<Vec<_>>(), vec![0, 1]);
        assert!(f.next_requests().is_empty(), "nobody has the rest yet");
        // Its bitmap grows: only the new chunks are asked for.
        assert_eq!(f.on_have(peer(1), &a, &some(&a, &[0, 1, 2, 5])), HaveOutcome::Holder);
        let reqs: Vec<u16> = f.next_requests().iter().map(|r| r.index).collect();
        assert_eq!(reqs, vec![2, 5]);
        // A full holder takes everything else.
        f.on_have(peer(2), &a, &all(&a));
        let rest = f.next_requests();
        assert_eq!(rest.iter().map(|r| r.index).collect::<Vec<_>>(), vec![3, 4, 6, 7]);
        assert!(rest.iter().all(|r| r.peer == peer(2)));
        // We serve what we hold while still fetching.
        let r = rest[0];
        f.on_chunk(&r, &parts[r.index as usize]);
        let asm = f.assembly(&a.hash).unwrap();
        assert_eq!(asm.chunk(3), Some(parts[3].as_slice()));
        assert_eq!(f.partial().count(), 1);
    }

    #[test]
    fn failures_and_disconnects_requeue_chunks() {
        let (a, parts) = proof(0, 0, 4);
        let mut f = Fetcher::new(&[0b1], 64);
        f.on_have(peer(1), &a, &all(&a));
        let reqs = f.next_requests();
        assert_eq!(reqs.len(), 4);
        // A timeout re-queues the chunk to the same holder.
        f.on_failure(&reqs[0], false);
        assert_eq!(f.next_requests(), vec![reqs[0]]);
        // A disconnect re-queues everything in flight to the other holder.
        f.on_have(peer(2), &a, &all(&a));
        f.on_peer_gone(&peer(1));
        let again = f.next_requests();
        assert_eq!(again.len(), 4);
        assert!(again.iter().all(|r| r.peer == peer(2)));
        // `Missing`/`Busy` drops the holder: nobody is left to ask.
        f.on_failure(&again[0], true);
        assert!(f.next_requests().is_empty());
        for r in &again[1..] {
            f.on_chunk(r, &parts[r.index as usize]);
        }
        assert!(!f.all_done());
        f.on_have(peer(3), &a, &all(&a));
        let last = f.next_requests();
        assert_eq!(last.len(), 1);
        match f.on_chunk(&last[0], &parts[last[0].index as usize]) {
            ChunkOutcome::Completed { id, proof } => {
                assert_eq!(id, a);
                assert_eq!(proof, parts.concat());
            }
            other => panic!("expected completion, got {other:?}"),
        }
        assert!(f.all_done());
        assert_eq!(f.partial().count(), 0);
        assert_eq!(f.on_have(peer(4), &a, &all(&a)), HaveOutcome::Known);
        assert!(f.next_requests().is_empty());
    }

    #[test]
    fn malformed_and_unexpected_chunks() {
        let (a, parts) = proof(0, 0, 4);
        let mut f = Fetcher::new(&[0b1], 64);
        f.on_have(peer(1), &a, &all(&a));
        let reqs = f.next_requests();
        assert_eq!(f.on_chunk(&reqs[0], &[1, 2, 3]), ChunkOutcome::Malformed);
        // The malformed chunk is asked for again.
        assert_eq!(f.next_requests(), vec![reqs[0]]);
        let stranger = ChunkRequest { peer: peer(9), hash: [7; 32], index: 0 };
        assert_eq!(f.on_chunk(&stranger, &parts[0]), ChunkOutcome::Unexpected);
        let r = reqs[1];
        f.on_chunk(&r, &parts[r.index as usize]);
        assert_eq!(f.on_chunk(&r, &parts[r.index as usize]), ChunkOutcome::Duplicate);
    }

    #[test]
    fn two_slots_complete_independently() {
        let (a, pa) = proof(0, 0, 2);
        let (b, pb) = proof(1, 0, 2);
        let mut f = Fetcher::new(&[0b01, 0b10], 64);
        f.on_have(peer(1), &a, &all(&a));
        f.on_have(peer(2), &b, &all(&b));
        for r in f.next_requests() {
            let parts = if r.hash == a.hash { &pa } else { &pb };
            f.on_chunk(&r, &parts[r.index as usize]);
        }
        assert_eq!(f.done(), 2);
        assert!(f.all_done());
    }
}
