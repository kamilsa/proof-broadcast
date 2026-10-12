//! Baseline transport: whole proofs as ordinary gossipsub messages on the
//! global proofs topic.
//!
//! L1 provers publish without subscribing (gossipsub fanout). L2 provers
//! accept, and therefore forward, only the first proof they see from each
//! subnet; later proofs from the same subnet are ignored (not forwarded), but
//! their bytes were already downloaded — that redundancy is what the baseline
//! measures.

use serde::{Deserialize, Serialize};

/// One proof on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofMessage {
    pub subnet: u16,
    pub prover: u16,
    pub data: Vec<u8>,
}

impl ProofMessage {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("serialize proof message")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let msg = ProofMessage {
            subnet: 3,
            prover: 1,
            data: vec![1, 2, 3],
        };
        assert_eq!(ProofMessage::decode(&msg.encode()).unwrap(), msg);
        assert!(ProofMessage::decode(&[1]).is_err());
    }
}
