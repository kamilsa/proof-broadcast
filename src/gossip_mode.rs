//! Baseline transport: whole proofs as ordinary gossipsub messages on the
//! global proofs topic.
//!
//! L1 provers publish without subscribing (gossipsub fanout). L2 provers
//! accept, and therefore forward, only proofs covering committees they have
//! not claimed yet; other proofs are ignored (not forwarded), but their bytes
//! were already downloaded — that redundancy is what the baseline measures.
//! With intermediate proofs on, L2s also publish their aggregates here.

use serde::{Deserialize, Serialize};

use crate::proof::{Committees, ProofId};

/// One proof on the wire. bincode lays it out as `subnet u16 || prover u16
/// || committees u64 || ..` (LE), which the wire tracer relies on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofMessage {
    /// Proven subnet, or [`AGGREGATE_SUBNET`](crate::proof::AGGREGATE_SUBNET).
    pub subnet: u16,
    pub prover: u16,
    pub committees: Committees,
    pub data: Vec<u8>,
}

impl ProofMessage {
    pub fn new(id: &ProofId, data: Vec<u8>) -> Self {
        Self {
            subnet: id.subnet,
            prover: id.prover,
            committees: id.committees,
            data,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("serialize proof message")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// The proof's identity, or `None` if subnet and committees disagree.
    pub fn id(&self, chunk_count: usize) -> Option<ProofId> {
        ProofId::from_parts(self.subnet, self.prover, self.committees, &self.data, chunk_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::AGGREGATE_SUBNET;

    #[test]
    fn round_trip() {
        let msg = ProofMessage {
            subnet: 3,
            prover: 1,
            committees: 0b1000,
            data: vec![1, 2, 3],
        };
        assert_eq!(ProofMessage::decode(&msg.encode()).unwrap(), msg);
        assert!(ProofMessage::decode(&[1]).is_err());
        assert!(msg.id(4).is_some());
    }

    #[test]
    fn wire_layout_matches_tracer() {
        let msg = ProofMessage {
            subnet: AGGREGATE_SUBNET,
            prover: 7,
            committees: 0b0110,
            data: vec![9; 4],
        };
        let bytes = msg.encode();
        assert_eq!(&bytes[..2], &AGGREGATE_SUBNET.to_le_bytes());
        assert_eq!(&bytes[2..4], &7u16.to_le_bytes());
        assert_eq!(&bytes[4..12], &0b0110u64.to_le_bytes());
    }

    #[test]
    fn inconsistent_mask_is_rejected() {
        let msg = ProofMessage {
            subnet: 3,
            prover: 1,
            committees: 0b0110,
            data: vec![1, 2, 3],
        };
        assert!(msg.id(4).is_none());
    }
}
