//! Proof model: identity, deterministic bytes, chunking and the per-subnet
//! ledger that enforces "one proof per subnet" on L2 provers.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Version byte prefixing a proof group id.
pub const GROUP_ID_VERSION: u8 = 0x02;

/// `version || subnet u16 || prover u16 || proof_len u32 || chunk_count u16 || hash`.
pub const GROUP_ID_LEN: usize = 1 + 2 + 2 + 4 + 2 + 32;

/// Upper bound on chunks per proof (keeps partial metadata bitmaps small).
pub const MAX_CHUNKS: usize = 4096;

/// Everything a receiver needs to decide whether to fetch a proof, and to
/// validate its chunks: the subnet it proves, which prover produced it, its
/// layout and its SHA-256. Used verbatim as the partial-message group id, so
/// an L2 can decline a proof from the announcement alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProofId {
    pub subnet: u16,
    pub prover: u16,
    pub proof_len: u32,
    pub chunk_count: u16,
    pub hash: [u8; 32],
}

impl ProofId {
    pub fn for_proof(subnet: u16, prover: u16, proof: &[u8], chunk_count: usize) -> Self {
        let chunk_count = effective_chunk_count(proof.len(), chunk_count);
        Self {
            subnet,
            prover,
            proof_len: proof.len() as u32,
            chunk_count: chunk_count as u16,
            hash: hash(proof),
        }
    }

    pub fn group_id(&self) -> Vec<u8> {
        let mut id = Vec::with_capacity(GROUP_ID_LEN);
        id.push(GROUP_ID_VERSION);
        id.extend_from_slice(&self.subnet.to_le_bytes());
        id.extend_from_slice(&self.prover.to_le_bytes());
        id.extend_from_slice(&self.proof_len.to_le_bytes());
        id.extend_from_slice(&self.chunk_count.to_le_bytes());
        id.extend_from_slice(&self.hash);
        id
    }

    pub fn from_group_id(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != GROUP_ID_LEN || bytes[0] != GROUP_ID_VERSION {
            return None;
        }
        let u16_at = |i: usize| u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        let proof_len = u32::from_le_bytes(bytes[5..9].try_into().ok()?);
        let chunk_count = u16_at(9);
        if chunk_count == 0 || chunk_count as usize > MAX_CHUNKS {
            return None;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[11..43]);
        Some(Self {
            subnet: u16_at(1),
            prover: u16_at(3),
            proof_len,
            chunk_count,
            hash,
        })
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

/// Split `proof` into `id.chunks()` contiguous chunks.
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

/// Ledger verdict for a proof an L2 has just heard about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// No proof chosen for this subnet yet: this one may be taken.
    Free,
    /// This is the proof already chosen for its subnet.
    Mine,
    /// A different proof was already chosen for this subnet.
    Taken,
}

/// Per-subnet choice of proof. Enforces the rule that an L2 never fetches or
/// relays two different proofs from the same subnet.
#[derive(Debug, Clone)]
pub struct SubnetLedger {
    committed: Vec<Option<[u8; 32]>>,
    completed: Vec<bool>,
    declined: HashSet<[u8; 32]>,
}

impl SubnetLedger {
    pub fn new(subnets: usize) -> Self {
        Self {
            committed: vec![None; subnets],
            completed: vec![false; subnets],
            declined: HashSet::new(),
        }
    }

    pub fn subnets(&self) -> usize {
        self.committed.len()
    }

    /// Out-of-range subnets are treated as taken (never fetched).
    pub fn verdict(&self, id: &ProofId) -> Verdict {
        match self.committed.get(id.subnet as usize) {
            None => Verdict::Taken,
            Some(None) => Verdict::Free,
            Some(Some(hash)) if *hash == id.hash => Verdict::Mine,
            Some(Some(_)) => Verdict::Taken,
        }
    }

    /// Choose `id` for its subnet. Returns false if the subnet was not free.
    pub fn commit(&mut self, id: &ProofId) -> bool {
        if self.verdict(id) != Verdict::Free {
            return false;
        }
        self.committed[id.subnet as usize] = Some(id.hash);
        true
    }

    /// Record a declined proof; true the first time this hash is declined.
    pub fn decline(&mut self, id: &ProofId) -> bool {
        self.declined.insert(id.hash)
    }

    /// Mark a subnet's chosen proof as fully held; true on the first call.
    pub fn complete(&mut self, subnet: u16) -> bool {
        match self.completed.get_mut(subnet as usize) {
            Some(done) if !*done => {
                *done = true;
                true
            }
            _ => false,
        }
    }

    pub fn subnets_done(&self) -> usize {
        self.completed.iter().filter(|&&d| d).count()
    }

    pub fn all_done(&self) -> bool {
        self.completed.iter().all(|&d| d)
    }

    pub fn declined(&self) -> usize {
        self.declined.len()
    }

    /// Committed proof hash for `subnet`, if any.
    pub fn committed(&self, subnet: usize) -> Option<[u8; 32]> {
        self.committed.get(subnet).copied().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(subnet: u16, prover: u16) -> ProofId {
        let proof = make_proof(subnet as u64 * 100 + prover as u64, 1000);
        ProofId::for_proof(subnet, prover, &proof, 64)
    }

    #[test]
    fn group_id_round_trip() {
        let id = id(3, 2);
        let bytes = id.group_id();
        assert_eq!(bytes.len(), GROUP_ID_LEN);
        assert_eq!(ProofId::from_group_id(&bytes), Some(id));
    }

    #[test]
    fn group_id_rejects_garbage() {
        let mut bytes = id(1, 1).group_id();
        assert!(ProofId::from_group_id(&bytes[1..]).is_none());
        bytes[0] = 0x01;
        assert!(ProofId::from_group_id(&bytes).is_none());
    }

    #[test]
    fn proofs_differ_per_seed() {
        assert_ne!(make_proof(1, 64), make_proof(2, 64));
        assert_eq!(make_proof(1, 64), make_proof(1, 64));
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

    #[test]
    fn ledger_one_proof_per_subnet() {
        let mut ledger = SubnetLedger::new(2);
        let a = id(0, 0);
        let b = id(0, 1);
        let c = id(1, 0);
        assert_eq!(ledger.verdict(&a), Verdict::Free);
        assert!(ledger.commit(&a));
        assert_eq!(ledger.verdict(&a), Verdict::Mine);
        assert_eq!(ledger.verdict(&b), Verdict::Taken);
        assert!(!ledger.commit(&b));
        assert!(ledger.decline(&b));
        assert!(!ledger.decline(&b));
        assert_eq!(ledger.verdict(&c), Verdict::Free);
        assert!(ledger.complete(0));
        assert!(!ledger.complete(0));
        assert!(!ledger.all_done());
        assert!(ledger.commit(&c));
        assert!(ledger.complete(1));
        assert!(ledger.all_done());
        assert_eq!(ledger.subnets_done(), 2);
    }

    #[test]
    fn ledger_out_of_range_subnet_is_taken() {
        let ledger = SubnetLedger::new(2);
        assert_eq!(ledger.verdict(&id(5, 0)), Verdict::Taken);
    }
}
