//! Chunk store for one proof: the requester's assembly buffer, and the
//! source a holder serves chunks from (also while it is still filling).

use serde::{Deserialize, Serialize};

use crate::proof::{ProofId, assemble, split};

/// Which chunks of a proof a peer holds: bit `i` = chunk `i`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkBits {
    len: u16,
    bits: Vec<u8>,
}

impl ChunkBits {
    pub fn empty(len: usize) -> Self {
        Self {
            len: len as u16,
            bits: vec![0; len.div_ceil(8)],
        }
    }

    pub fn full(len: usize) -> Self {
        let mut b = Self::empty(len);
        (0..len).for_each(|i| b.set(i));
        b
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn get(&self, index: usize) -> bool {
        index < self.len() && self.bits[index / 8] >> (index % 8) & 1 == 1
    }

    pub fn set(&mut self, index: usize) {
        if index < self.len() {
            self.bits[index / 8] |= 1 << (index % 8);
        }
    }

    pub fn count(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }

    pub fn is_full(&self) -> bool {
        self.count() == self.len()
    }

    /// Add every chunk of `other` (same length).
    pub fn union_with(&mut self, other: &Self) {
        for (a, b) in self.bits.iter_mut().zip(&other.bits) {
            *a |= b;
        }
    }

    /// Whether the bitmap came off the wire well formed for `len` chunks.
    pub fn is_valid_for(&self, len: usize) -> bool {
        self.len() == len
            && self.bits.len() == len.div_ceil(8)
            && (len.is_multiple_of(8) || self.bits.last().is_none_or(|last| last >> (len % 8) == 0))
    }
}

/// Outcome of merging one received chunk into an assembly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeOutcome {
    pub added: usize,
    pub duplicate: usize,
    pub held: usize,
    /// The full, verified proof, returned once when the last chunk lands.
    pub completed: Option<Vec<u8>>,
    /// All chunks arrived but the hash did not match (everything is dropped
    /// so the proof can be fetched again).
    pub invalid: bool,
}

/// Chunks collected (or held) for one proof.
pub struct ProofAssembly {
    pub id: ProofId,
    chunks: Vec<Option<Vec<u8>>>,
    complete: bool,
}

impl ProofAssembly {
    pub fn new(id: ProofId) -> Self {
        Self {
            id,
            chunks: vec![None; id.chunks()],
            complete: false,
        }
    }

    /// A proof we produced (or finished assembling): every chunk present.
    pub fn from_proof(id: ProofId, proof: &[u8]) -> Self {
        Self {
            id,
            chunks: split(proof, id.chunks()).into_iter().map(Some).collect(),
            complete: true,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn held(&self) -> usize {
        self.chunks.iter().filter(|c| c.is_some()).count()
    }

    pub fn has(&self, index: usize) -> bool {
        self.chunks.get(index).is_some_and(Option::is_some)
    }

    /// Chunk `index`, if held.
    pub fn chunk(&self, index: usize) -> Option<&[u8]> {
        self.chunks.get(index)?.as_deref()
    }

    /// The chunks held, as announced in `Have`.
    pub fn bits(&self) -> ChunkBits {
        let mut b = ChunkBits::empty(self.chunks.len());
        for (i, _) in self.chunks.iter().enumerate().filter(|(_, c)| c.is_some()) {
            b.set(i);
        }
        b
    }

    /// Indices of the chunks still missing, in order.
    pub fn missing(&self) -> impl Iterator<Item = usize> + '_ {
        self.chunks
            .iter()
            .enumerate()
            .filter(|(_, c)| c.is_none())
            .map(|(i, _)| i)
    }

    /// Merge one chunk. Its length must already match `id.chunk_len(index)`.
    pub fn merge_one(&mut self, index: usize, chunk: &[u8]) -> MergeOutcome {
        let mut out = MergeOutcome::default();
        match self.chunks.get_mut(index) {
            Some(slot @ None) => {
                *slot = Some(chunk.to_vec());
                out.added = 1;
            }
            Some(Some(_)) => out.duplicate = 1,
            None => {}
        }
        out.held = self.held();
        if !self.complete && out.added > 0 && out.held == self.chunks.len() {
            let parts: Vec<&[u8]> = self
                .chunks
                .iter()
                .map(|c| c.as_deref().expect("all chunks held"))
                .collect();
            match assemble(&self.id, &parts) {
                Some(proof) => {
                    self.complete = true;
                    out.completed = Some(proof);
                }
                None => {
                    self.chunks.iter_mut().for_each(|c| *c = None);
                    out.invalid = true;
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::make_proof;

    fn proof_id(len: usize, chunks: usize) -> (ProofId, Vec<u8>) {
        let proof = make_proof(5, len);
        (ProofId::for_proof(1, 2, &proof, chunks), proof)
    }

    #[test]
    fn chunk_bits() {
        let mut b = ChunkBits::empty(10);
        assert_eq!((b.count(), b.is_full()), (0, false));
        b.set(1);
        b.set(9);
        b.set(10); // out of range: ignored
        assert!(b.get(1) && b.get(9) && !b.get(0) && !b.get(10));
        assert_eq!(b.count(), 2);
        let mut c = ChunkBits::empty(10);
        c.set(0);
        c.union_with(&b);
        assert_eq!(c.count(), 3);
        assert!(ChunkBits::full(10).is_full());
        assert!(b.is_valid_for(10));
        assert!(!b.is_valid_for(11));
        let mut bad = ChunkBits::empty(10);
        bad.bits[1] = 0xff; // bits beyond the length
        assert!(!bad.is_valid_for(10));
    }

    #[test]
    fn assembly_completes_and_counts_duplicates() {
        let (id, proof) = proof_id(100, 3);
        let parts = split(&proof, 3);
        let mut asm = ProofAssembly::new(id);
        assert_eq!(asm.missing().collect::<Vec<_>>(), vec![0, 1, 2]);
        let out = asm.merge_one(2, &parts[2]);
        assert_eq!((out.added, out.duplicate, out.held), (1, 0, 1));
        let out = asm.merge_one(2, &parts[2]);
        assert_eq!((out.added, out.duplicate), (0, 1));
        assert!(asm.merge_one(0, &parts[0]).completed.is_none());
        assert_eq!(asm.missing().collect::<Vec<_>>(), vec![1]);
        assert_eq!(asm.bits().count(), 2);
        assert!(asm.bits().get(0) && !asm.bits().get(1));
        let out = asm.merge_one(1, &parts[1]);
        assert_eq!(out.completed.as_deref(), Some(proof.as_slice()));
        assert!(asm.is_complete());
        assert_eq!(asm.chunk(1), Some(parts[1].as_slice()));
        // Once complete, nothing more is ever returned.
        let out = asm.merge_one(0, &parts[0]);
        assert!(out.completed.is_none());
        assert_eq!(out.duplicate, 1);
    }

    #[test]
    fn tampered_chunk_resets_the_assembly() {
        let (id, proof) = proof_id(100, 2);
        let mut parts = split(&proof, 2);
        parts[0][0] ^= 1;
        let mut asm = ProofAssembly::new(id);
        asm.merge_one(0, &parts[0]);
        let out = asm.merge_one(1, &parts[1]);
        assert!(out.invalid);
        assert!(out.completed.is_none());
        assert_eq!(asm.held(), 0);
    }

    #[test]
    fn source_serves_every_chunk() {
        let (id, proof) = proof_id(1000, 8);
        let src = ProofAssembly::from_proof(id, &proof);
        assert!(src.is_complete());
        assert_eq!(src.missing().count(), 0);
        let joined: Vec<u8> = (0..8).flat_map(|i| src.chunk(i).unwrap().to_vec()).collect();
        assert_eq!(joined, proof);
        assert!(src.chunk(8).is_none());
    }
}
