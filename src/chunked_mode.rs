//! `gossipsub-chunked` transport: every proof is split into `chunk_count`
//! chunks, each published as an ordinary gossipsub message on
//! `/proofs_chunked/1` (as in ec-sim's `gossipsub-chunked` mode).
//!
//! An L2 decides on the first chunk of a proof whether to relay it: only if
//! no other proof covering its committees was seen before (for a subnet
//! proof: no other L1 proof of that subnet). Every chunk is still received
//! and assembled — Ignore only stops forwarding — and the L2 uses whichever
//! proof of a subnet completes first, relayed or not.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::partial_mode::ProofAssembly;
use crate::proof::{Committees, ProofId, split};

/// One chunk on the wire. bincode lays it out as `subnet u16 || prover u16 ||
/// committees u64 || index u16 || ..` (LE), which the wire tracer relies on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkMessage {
    /// Proven subnet, or [`AGGREGATE_SUBNET`](crate::proof::AGGREGATE_SUBNET).
    pub subnet: u16,
    pub prover: u16,
    pub committees: Committees,
    pub index: u16,
    pub chunk_count: u16,
    pub proof_len: u32,
    pub hash: [u8; 32],
    pub data: Vec<u8>,
}

impl ChunkMessage {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("serialize chunk message")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// The proof this chunk belongs to, or `None` if the chunk is malformed
    /// (inconsistent mask, bad layout, index out of range, wrong length).
    pub fn id(&self) -> Option<ProofId> {
        let id = ProofId::from_header(
            self.subnet,
            self.prover,
            self.committees,
            self.proof_len,
            self.chunk_count,
            self.hash,
        )?;
        (id.chunk_len(self.index as usize) == Some(self.data.len())).then_some(id)
    }
}

/// Every chunk of `proof`, in index order.
pub fn chunk_messages(id: &ProofId, proof: &[u8]) -> Vec<ChunkMessage> {
    split(proof, id.chunks())
        .into_iter()
        .enumerate()
        .map(|(index, data)| ChunkMessage {
            subnet: id.subnet,
            prover: id.prover,
            committees: id.committees,
            index: index as u16,
            chunk_count: id.chunk_count,
            proof_len: id.proof_len,
            hash: id.hash,
            data,
        })
        .collect()
}

/// An L2's view of one proof seen on the chunked topic.
pub struct ChunkedProof {
    pub assembly: ProofAssembly,
    /// Decided on the first chunk: forward (Accept) or not (Ignore).
    pub relay: bool,
}

/// Per-node `gossipsub-chunked` state, keyed by proof hash.
#[derive(Default)]
pub struct ChunkedState {
    pub proofs: HashMap<[u8; 32], ChunkedProof>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::{AGGREGATE_SUBNET, make_aggregate, make_proof, mask_of};

    #[test]
    fn round_trip_and_assembly() {
        let proof = make_proof(3, 1000);
        let id = ProofId::for_proof(2, 1, &proof, 8);
        let chunks = chunk_messages(&id, &proof);
        assert_eq!(chunks.len(), 8);
        let mut asm = ProofAssembly::new(id);
        let mut done = None;
        for chunk in chunks.iter().rev() {
            let decoded = ChunkMessage::decode(&chunk.encode()).unwrap();
            assert_eq!(decoded.id(), Some(id));
            let out = asm.merge_one(decoded.index as usize, &decoded.data);
            done = out.completed.or(done);
        }
        assert_eq!(done, Some(proof));
        // A repeated chunk adds nothing.
        let out = asm.merge_one(0, &chunks[0].data);
        assert_eq!((out.added, out.duplicate), (0, 1));
    }

    #[test]
    fn wire_layout_matches_tracer() {
        let mask = mask_of(&[1, 2]);
        let proof = make_aggregate(1, mask, 64);
        let id = ProofId::for_aggregate(7, mask, &proof, 4);
        let bytes = chunk_messages(&id, &proof)[3].encode();
        assert_eq!(&bytes[..2], &AGGREGATE_SUBNET.to_le_bytes());
        assert_eq!(&bytes[2..4], &7u16.to_le_bytes());
        assert_eq!(&bytes[4..12], &mask.to_le_bytes());
        assert_eq!(&bytes[12..14], &3u16.to_le_bytes());
    }

    #[test]
    fn malformed_chunks_are_rejected() {
        let proof = make_proof(3, 1000);
        let id = ProofId::for_proof(2, 1, &proof, 8);
        let good = chunk_messages(&id, &proof)[7].clone();
        let mut bad = good.clone();
        bad.index = 8;
        assert!(bad.id().is_none());
        let mut bad = good.clone();
        bad.data.push(0);
        assert!(bad.id().is_none());
        let mut bad = good.clone();
        bad.committees = 0b11;
        assert!(bad.id().is_none());
        let mut bad = good;
        bad.chunk_count = 0;
        assert!(bad.id().is_none());
    }
}
