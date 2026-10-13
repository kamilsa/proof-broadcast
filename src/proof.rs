//! Proof model: identity, deterministic bytes and chunking.
//!
//! A proof covers a set of committees (subnets), kept as a [`Committees`]
//! bitmask. An L1 (subnet) proof covers exactly one; the aggregate an L2
//! produces for its tree node covers that node's committees.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Upper bound on chunks per proof.
pub const MAX_CHUNKS: usize = 4096;

/// Committees fit a `u64` mask (the EIP's `ATTESTATION_SUBNET_COUNT`).
pub const MAX_SUBNETS: usize = 64;

/// `subnet` value marking an aggregate; its `prover` is the index of the L2
/// that produced it.
pub const AGGREGATE_SUBNET: u16 = u16::MAX;

/// Bitmask of committees (bit `s` = subnet `s`).
pub type Committees = u64;

pub fn mask_of(subnets: &[u16]) -> Committees {
    subnets
        .iter()
        .filter(|&&s| (s as usize) < MAX_SUBNETS)
        .fold(0, |m, &s| m | 1 << s)
}

pub fn subnets_of(mask: Committees) -> Vec<u16> {
    (0..MAX_SUBNETS as u16).filter(|&s| mask >> s & 1 == 1).collect()
}

/// Render subnets as `0-3-5` for event lines: no spaces, never parseable as
/// a float by the analyzer (`0.3` would be), and `none` when empty.
pub fn subnet_list(subnets: &[u16]) -> String {
    if subnets.is_empty() {
        return "none".to_string();
    }
    subnets.iter().map(u16::to_string).collect::<Vec<_>>().join("-")
}

/// Mask covering subnets `0..subnets`.
pub fn full_mask(subnets: usize) -> Committees {
    if subnets >= MAX_SUBNETS {
        u64::MAX
    } else {
        (1u64 << subnets) - 1
    }
}

/// Everything a receiver needs to decide whether to fetch a proof, and to
/// validate its chunks: the committees it proves, who produced it, its layout
/// and its SHA-256. Carried in `Have` announcements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProofId {
    /// The proven subnet, or [`AGGREGATE_SUBNET`] for an aggregate.
    pub subnet: u16,
    /// L1: index within its subnet. Aggregate: the producing L2's index.
    pub prover: u16,
    pub committees: Committees,
    pub proof_len: u32,
    pub chunk_count: u16,
    pub hash: [u8; 32],
}

impl ProofId {
    /// Identity of an L1 (single-subnet) proof.
    pub fn for_proof(subnet: u16, prover: u16, proof: &[u8], chunk_count: usize) -> Self {
        Self::build(subnet, prover, mask_of(&[subnet]), proof, chunk_count)
    }

    /// Identity of an aggregate produced by L2 `prover`.
    pub fn for_aggregate(prover: u16, committees: Committees, proof: &[u8], chunk_count: usize) -> Self {
        Self::build(AGGREGATE_SUBNET, prover, committees, proof, chunk_count)
    }

    fn build(subnet: u16, prover: u16, committees: Committees, proof: &[u8], chunk_count: usize) -> Self {
        let chunk_count = effective_chunk_count(proof.len(), chunk_count);
        Self {
            subnet,
            prover,
            committees,
            proof_len: proof.len() as u32,
            chunk_count: chunk_count as u16,
            hash: hash(proof),
        }
    }

    /// A leaf's mask is its own subnet's bit; an aggregate covers two or more.
    fn is_consistent(&self) -> bool {
        if self.is_aggregate() {
            self.committees.count_ones() >= 2
        } else {
            (self.subnet as usize) < MAX_SUBNETS && self.committees == 1 << self.subnet
        }
    }

    /// Identity from untrusted header fields, or `None` if the mask or the
    /// chunk layout is inconsistent.
    pub fn from_header(
        subnet: u16,
        prover: u16,
        committees: Committees,
        proof_len: u32,
        chunk_count: u16,
        hash: [u8; 32],
    ) -> Option<Self> {
        let chunks = chunk_count as usize;
        if chunks == 0 || chunks > MAX_CHUNKS || chunks > (proof_len as usize).max(1) {
            return None;
        }
        let id = Self {
            subnet,
            prover,
            committees,
            proof_len,
            chunk_count,
            hash,
        };
        id.is_consistent().then_some(id)
    }

    /// `self` if it came off the wire well formed.
    pub fn checked(self) -> Option<Self> {
        Self::from_header(
            self.subnet,
            self.prover,
            self.committees,
            self.proof_len,
            self.chunk_count,
            self.hash,
        )
    }

    pub fn is_aggregate(&self) -> bool {
        self.subnet == AGGREGATE_SUBNET
    }

    pub fn covered(&self) -> usize {
        self.committees.count_ones() as usize
    }

    pub fn subnets(&self) -> Vec<u16> {
        subnets_of(self.committees)
    }

    pub fn chunks(&self) -> usize {
        self.chunk_count as usize
    }

    /// Expected byte length of chunk `index`.
    pub fn chunk_len(&self, index: usize) -> Option<usize> {
        expected_chunk_len(self.proof_len as usize, self.chunks(), index)
    }

    /// Short hex label for event lines (first 8 hash bytes).
    pub fn label(&self) -> String {
        crate::events::hex_bytes(&self.hash[..8])
    }
}

pub fn hash(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Deterministic proof bytes; the launcher gives every L1 prover its own seed,
/// so every prover's proof (and hash) differs.
pub fn make_proof(seed: u64, len: usize) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut proof = vec![0u8; len];
    rng.fill_bytes(&mut proof);
    proof
}

/// Deterministic bytes of the aggregate an L2 (with node seed `seed`)
/// produces over `committees`. leanVM proofs have roughly constant size, so
/// an aggregate is as large as a subnet proof.
pub fn make_aggregate(seed: u64, committees: Committees, len: usize) -> Vec<u8> {
    make_proof(seed ^ committees.wrapping_mul(0x9E37_79B9_7F4A_7C15), len)
}

/// Chunk count actually used: never more chunks than bytes, at least one.
pub fn effective_chunk_count(proof_len: usize, configured: usize) -> usize {
    configured.clamp(1, MAX_CHUNKS).min(proof_len.max(1))
}

/// Byte length of chunk `index` when `len` bytes are split into `count`
/// contiguous chunks, or `None` for an out-of-range index.
pub fn expected_chunk_len(len: usize, count: usize, index: usize) -> Option<usize> {
    if count == 0 || index >= count {
        return None;
    }
    let chunk_len = len.div_ceil(count);
    let start = chunk_len.checked_mul(index)?;
    Some(len.saturating_sub(start).min(chunk_len))
}

/// Split `proof` into `count` contiguous chunks.
pub fn split(proof: &[u8], count: usize) -> Vec<Vec<u8>> {
    let chunk_len = proof.len().div_ceil(count.max(1));
    (0..count)
        .map(|i| {
            let start = (chunk_len * i).min(proof.len());
            let end = start.saturating_add(chunk_len).min(proof.len());
            proof[start..end].to_vec()
        })
        .collect()
}

/// Join chunks and verify them against `id`. Returns the proof on success.
pub fn assemble(id: &ProofId, chunks: &[&[u8]]) -> Option<Vec<u8>> {
    if chunks.len() != id.chunks() {
        return None;
    }
    let proof: Vec<u8> = chunks.concat();
    (proof.len() == id.proof_len as usize && hash(&proof) == id.hash).then_some(proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(subnet: u16, prover: u16) -> ProofId {
        let proof = make_proof(subnet as u64 * 100 + prover as u64, 1000);
        ProofId::for_proof(subnet, prover, &proof, 64)
    }

    fn agg(prover: u16, subnets: &[u16]) -> ProofId {
        let mask = mask_of(subnets);
        ProofId::for_aggregate(prover, mask, &make_aggregate(prover as u64, mask, 1000), 64)
    }

    #[test]
    fn masks() {
        assert_eq!(mask_of(&[0, 3]), 0b1001);
        assert_eq!(subnets_of(0b1001), vec![0, 3]);
        assert_eq!(full_mask(4), 0b1111);
        assert_eq!(full_mask(64), u64::MAX);
        assert_eq!(subnet_list(&[0, 3, 5]), "0-3-5");
        assert_eq!(subnet_list(&[]), "none");
    }

    #[test]
    fn checked_accepts_good_ids_and_rejects_inconsistent_ones() {
        for good in [id(3, 2), agg(7, &[0, 4, 5])] {
            assert_eq!(good.checked(), Some(good));
        }
        // A leaf whose mask is not its own subnet.
        let mut bad = id(1, 1);
        bad.committees = 0b100;
        assert!(bad.checked().is_none());
        // An "aggregate" of one committee.
        let mut bad = agg(1, &[2, 3]);
        bad.committees = 0b100;
        assert!(bad.checked().is_none());
        // More chunks than bytes, or none at all.
        let mut bad = id(1, 1);
        bad.chunk_count = 0;
        assert!(bad.checked().is_none());
        bad.chunk_count = 2000;
        assert!(bad.checked().is_none());
    }

    #[test]
    fn proofs_differ_per_seed() {
        assert_ne!(make_proof(1, 64), make_proof(2, 64));
        assert_eq!(make_proof(1, 64), make_proof(1, 64));
        assert_ne!(make_aggregate(1, 0b11, 64), make_aggregate(1, 0b101, 64));
    }

    #[test]
    fn split_and_assemble() {
        let proof = make_proof(9, 300 * 1024);
        let id = ProofId::for_proof(0, 0, &proof, 64);
        let chunks = split(&proof, id.chunks());
        assert_eq!(chunks.len(), 64);
        for (i, c) in chunks.iter().enumerate() {
            assert_eq!(Some(c.len()), id.chunk_len(i));
        }
        let refs: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
        assert_eq!(assemble(&id, &refs), Some(proof));
    }

    #[test]
    fn assemble_rejects_tampered_chunk() {
        let proof = make_proof(9, 1000);
        let id = ProofId::for_proof(0, 0, &proof, 8);
        let mut chunks = split(&proof, id.chunks());
        chunks[3][0] ^= 1;
        let refs: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
        assert!(assemble(&id, &refs).is_none());
    }

    #[test]
    fn uneven_and_tiny_proofs() {
        let proof = make_proof(1, 10);
        let id = ProofId::for_proof(0, 0, &proof, 64);
        assert_eq!(id.chunks(), 10);
        let proof = make_proof(1, 1001);
        let id = ProofId::for_proof(0, 0, &proof, 64);
        let chunks = split(&proof, id.chunks());
        assert_eq!(chunks.iter().map(Vec::len).sum::<usize>(), 1001);
        for (i, c) in chunks.iter().enumerate() {
            assert_eq!(Some(c.len()), id.chunk_len(i));
        }
    }
}
