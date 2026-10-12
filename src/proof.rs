//! Proof model: identity, deterministic bytes, chunking and the coverage
//! ledger that enforces "at most one proof per committee" on L2 provers.
//!
//! A proof covers a set of committees (subnets), kept as a [`Committees`]
//! bitmask. An L1 (subnet) proof covers exactly one; an intermediate
//! aggregate published by an L2 covers several.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// Version byte prefixing a proof group id.
pub const GROUP_ID_VERSION: u8 = 0x03;

/// `version || subnet u16 || prover u16 || committees u64 || proof_len u32 ||
/// chunk_count u16 || hash`, all little endian. The committee mask sits at the
/// same offset (after subnet and prover) as in a bincode [`ProofMessage`], so
/// the wire tracer reads both the same way.
///
/// [`ProofMessage`]: crate::gossip_mode::ProofMessage
pub const GROUP_ID_LEN: usize = 1 + 2 + 2 + 8 + 4 + 2 + 32;

/// Upper bound on chunks per proof (keeps partial metadata bitmaps small).
pub const MAX_CHUNKS: usize = 4096;

/// Committees fit a `u64` mask (the EIP's `ATTESTATION_SUBNET_COUNT`).
pub const MAX_SUBNETS: usize = 64;

/// `subnet` value marking an intermediate aggregate; its `prover` is the
/// index of the L2 that produced it.
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
/// and its SHA-256. Used verbatim as the partial-message group id, so an L2
/// can decline a proof from the announcement alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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

    /// Identity of an intermediate aggregate produced by L2 `prover`.
    pub fn for_aggregate(prover: u16, committees: Committees, proof: &[u8], chunk_count: usize) -> Self {
        Self::build(AGGREGATE_SUBNET, prover, committees, proof, chunk_count)
    }

    /// Identity from untrusted parts; `None` if they are inconsistent.
    pub fn from_parts(
        subnet: u16,
        prover: u16,
        committees: Committees,
        proof: &[u8],
        chunk_count: usize,
    ) -> Option<Self> {
        let id = Self::build(subnet, prover, committees, proof, chunk_count);
        id.is_consistent().then_some(id)
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

    pub fn is_aggregate(&self) -> bool {
        self.subnet == AGGREGATE_SUBNET
    }

    pub fn covered(&self) -> usize {
        self.committees.count_ones() as usize
    }

    pub fn subnets(&self) -> Vec<u16> {
        subnets_of(self.committees)
    }

    pub fn group_id(&self) -> Vec<u8> {
        let mut id = Vec::with_capacity(GROUP_ID_LEN);
        id.push(GROUP_ID_VERSION);
        id.extend_from_slice(&self.subnet.to_le_bytes());
        id.extend_from_slice(&self.prover.to_le_bytes());
        id.extend_from_slice(&self.committees.to_le_bytes());
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
        let committees = u64::from_le_bytes(bytes[5..13].try_into().ok()?);
        let proof_len = u32::from_le_bytes(bytes[13..17].try_into().ok()?);
        let chunk_count = u16_at(17);
        if chunk_count == 0 || chunk_count as usize > MAX_CHUNKS {
            return None;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[19..51]);
        let id = Self {
            subnet: u16_at(1),
            prover: u16_at(3),
            committees,
            proof_len,
            chunk_count,
            hash,
        };
        id.is_consistent().then_some(id)
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

/// Which advertised proofs an L2 may fetch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum FetchPolicy {
    /// Only proofs whose committees are disjoint from everything claimed.
    #[default]
    Disjoint,
    /// Also proofs that fully contain some held items (which are then
    /// dropped) as long as they add a committee and split no claimed item.
    Subsume,
}

impl std::fmt::Display for FetchPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Disjoint => "disjoint",
            Self::Subsume => "subsume",
        })
    }
}

/// Ledger verdict for a proof an L2 has just heard about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Disjoint from everything claimed: this one may be taken.
    Free,
    /// Overlaps only items it fully contains: may be taken, replacing them.
    Subsume,
    /// Already claimed (being fetched, held, or our own).
    Mine,
    /// Overlaps what we hold or fetch: declined.
    Taken,
}

impl Verdict {
    pub fn is_fetch(self) -> bool {
        matches!(self, Self::Free | Self::Subsume)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimState {
    Downloading,
    Held,
}

#[derive(Debug, Clone, Copy)]
struct Claim {
    committees: Committees,
    state: ClaimState,
}

/// The committees an L2 has claimed. Enforces the rule that an L2 never
/// fetches (or relays) two proofs covering the same committee, except
/// under [`FetchPolicy::Subsume`] where a proof may replace items it fully
/// contains.
///
/// Proofs being downloaded live here; what is held or being merged lives in
/// the [`Aggregator`](crate::aggregation::Aggregator), whose units are passed
/// to [`CoverageLedger::verdict`].
#[derive(Debug, Clone)]
pub struct CoverageLedger {
    subnets: usize,
    policy: FetchPolicy,
    claims: HashMap<[u8; 32], Claim>,
    own: HashSet<[u8; 32]>,
    /// Committees covered by fully received proofs.
    held: Committees,
    /// First proof claimed per subnet.
    committed: Vec<Option<[u8; 32]>>,
    declined: HashSet<[u8; 32]>,
}

impl CoverageLedger {
    pub fn new(subnets: usize, policy: FetchPolicy) -> Self {
        Self {
            subnets,
            policy,
            claims: HashMap::new(),
            own: HashSet::new(),
            held: 0,
            committed: vec![None; subnets],
            declined: HashSet::new(),
        }
    }

    pub fn subnets(&self) -> usize {
        self.subnets
    }

    fn downloading(&self) -> impl Iterator<Item = Committees> + '_ {
        self.claims
            .values()
            .filter(|c| c.state == ClaimState::Downloading)
            .map(|c| c.committees)
    }

    /// Verdict for `id`, given the aggregator's live `work` units (pool items
    /// and running merge outputs).
    pub fn verdict(&self, id: &ProofId, work: &[Committees]) -> Verdict {
        if self.claims.contains_key(&id.hash) || self.own.contains(&id.hash) {
            return Verdict::Mine;
        }
        let c = id.committees;
        if c == 0 || c & !full_mask(self.subnets) != 0 {
            return Verdict::Taken;
        }
        let downloading = self.downloading().fold(0, |m, d| m | d);
        let claimed = work.iter().fold(downloading, |m, w| m | w);
        if c & claimed == 0 {
            return Verdict::Free;
        }
        // A download cannot be cancelled (request bits only grow), so it
        // must stay disjoint; held items must be inside `c` or outside it.
        let subsumes = self.policy == FetchPolicy::Subsume
            && c & !claimed != 0
            && c & downloading == 0
            && work.iter().all(|&w| w & c == 0 || w & !c == 0);
        if subsumes { Verdict::Subsume } else { Verdict::Taken }
    }

    /// Claim `id` (download started). False if already claimed.
    pub fn commit(&mut self, id: &ProofId) -> bool {
        if self.claims.contains_key(&id.hash) || self.own.contains(&id.hash) {
            return false;
        }
        self.claims.insert(
            id.hash,
            Claim {
                committees: id.committees,
                state: ClaimState::Downloading,
            },
        );
        for s in id.subnets() {
            if let Some(slot @ None) = self.committed.get_mut(s as usize) {
                *slot = Some(id.hash);
            }
        }
        true
    }

    /// Record one of our own aggregates so it is never fetched back.
    pub fn own(&mut self, id: &ProofId) {
        self.own.insert(id.hash);
    }

    /// A claimed proof is fully held. Returns the committees it newly
    /// covers, or `None` if it was not a pending claim.
    pub fn complete(&mut self, id: &ProofId) -> Option<Committees> {
        let claim = self.claims.get_mut(&id.hash)?;
        if claim.state == ClaimState::Held {
            return None;
        }
        claim.state = ClaimState::Held;
        let new = claim.committees & !self.held;
        self.held |= claim.committees;
        Some(new)
    }

    /// Record a declined proof; true the first time this hash is declined.
    pub fn decline(&mut self, id: &ProofId) -> bool {
        self.declined.insert(id.hash)
    }

    pub fn held(&self) -> Committees {
        self.held
    }

    pub fn subnets_done(&self) -> usize {
        self.held.count_ones() as usize
    }

    pub fn all_done(&self) -> bool {
        self.held & full_mask(self.subnets) == full_mask(self.subnets)
    }

    pub fn declined(&self) -> usize {
        self.declined.len()
    }

    /// First proof claimed for `subnet`, if any.
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
    }

    #[test]
    fn group_id_round_trip() {
        for id in [id(3, 2), agg(7, &[0, 4, 5])] {
            let bytes = id.group_id();
            assert_eq!(bytes.len(), GROUP_ID_LEN);
            assert_eq!(ProofId::from_group_id(&bytes), Some(id));
        }
    }

    #[test]
    fn group_id_rejects_garbage() {
        let mut bytes = id(1, 1).group_id();
        assert!(ProofId::from_group_id(&bytes[1..]).is_none());
        bytes[0] = 0x02;
        assert!(ProofId::from_group_id(&bytes).is_none());
        // A leaf whose mask is not its own subnet.
        let mut bytes = id(1, 1).group_id();
        bytes[5] = 0b100;
        assert!(ProofId::from_group_id(&bytes).is_none());
        // An "aggregate" of one committee.
        let mut bytes = agg(1, &[2, 3]).group_id();
        bytes[5] = 0b100;
        assert!(ProofId::from_group_id(&bytes).is_none());
    }

    #[test]
    fn from_parts_checks_mask() {
        let proof = make_proof(1, 100);
        assert!(ProofId::from_parts(2, 0, 0b100, &proof, 4).is_some());
        assert!(ProofId::from_parts(2, 0, 0b110, &proof, 4).is_none());
        assert!(ProofId::from_parts(AGGREGATE_SUBNET, 0, 0b110, &proof, 4).is_some());
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

    #[test]
    fn ledger_one_proof_per_subnet() {
        let mut ledger = CoverageLedger::new(2, FetchPolicy::Disjoint);
        let a = id(0, 0);
        let b = id(0, 1);
        let c = id(1, 0);
        assert_eq!(ledger.verdict(&a, &[]), Verdict::Free);
        assert!(ledger.commit(&a));
        assert_eq!(ledger.verdict(&a, &[]), Verdict::Mine);
        assert_eq!(ledger.verdict(&b, &[]), Verdict::Taken);
        assert!(ledger.decline(&b));
        assert!(!ledger.decline(&b));
        assert_eq!(ledger.verdict(&c, &[]), Verdict::Free);
        assert_eq!(ledger.complete(&a), Some(0b01));
        assert_eq!(ledger.complete(&a), None);
        // Once held, subnet 0 is claimed through the aggregator's pool.
        assert_eq!(ledger.verdict(&b, &[0b01]), Verdict::Taken);
        assert!(!ledger.all_done());
        assert!(ledger.commit(&c));
        assert_eq!(ledger.complete(&c), Some(0b10));
        assert!(ledger.all_done());
        assert_eq!(ledger.subnets_done(), 2);
        assert_eq!(ledger.committed(0), Some(a.hash));
    }

    #[test]
    fn ledger_out_of_range_subnet_is_taken() {
        let ledger = CoverageLedger::new(2, FetchPolicy::Disjoint);
        assert_eq!(ledger.verdict(&id(5, 0), &[]), Verdict::Taken);
        assert_eq!(ledger.verdict(&agg(0, &[1, 5]), &[]), Verdict::Taken);
    }

    #[test]
    fn own_aggregates_are_mine() {
        let mut ledger = CoverageLedger::new(4, FetchPolicy::Disjoint);
        let a = agg(0, &[0, 1]);
        ledger.own(&a);
        assert_eq!(ledger.verdict(&a, &[0b11]), Verdict::Mine);
        assert!(!ledger.commit(&a));
    }

    #[test]
    fn disjoint_aggregates() {
        let mut ledger = CoverageLedger::new(8, FetchPolicy::Disjoint);
        let work = [mask_of(&[0])];
        assert_eq!(ledger.verdict(&agg(1, &[2, 3]), &work), Verdict::Free);
        assert_eq!(ledger.verdict(&agg(1, &[0, 1]), &work), Verdict::Taken);
        let a = agg(1, &[2, 3]);
        ledger.commit(&a);
        assert_eq!(ledger.complete(&a), Some(0b1100));
        assert_eq!(ledger.committed(2), Some(a.hash));
        assert_eq!(ledger.verdict(&agg(2, &[3, 4]), &[0b1, 0b1100]), Verdict::Taken);
    }

    #[test]
    fn subsume_rules() {
        let mut ledger = CoverageLedger::new(8, FetchPolicy::Subsume);
        let work = [mask_of(&[0]), mask_of(&[1, 2])];
        // Contains every overlapping item and adds 3: subsumes.
        assert_eq!(ledger.verdict(&agg(1, &[0, 1, 2, 3]), &work), Verdict::Subsume);
        // Splits the {1,2} item: taken.
        assert_eq!(ledger.verdict(&agg(1, &[0, 1, 3]), &work), Verdict::Taken);
        // Adds nothing new: taken.
        assert_eq!(ledger.verdict(&agg(1, &[0, 1, 2]), &work), Verdict::Taken);
        // Overlapping a download (even fully containing it) is never allowed.
        let leaf = id(5, 0);
        ledger.commit(&leaf);
        assert_eq!(ledger.verdict(&agg(1, &[5, 6]), &work), Verdict::Taken);
        assert_eq!(ledger.verdict(&agg(1, &[6, 7]), &work), Verdict::Free);
        // Disjoint policy never subsumes.
        let disjoint = CoverageLedger::new(8, FetchPolicy::Disjoint);
        assert_eq!(disjoint.verdict(&agg(1, &[0, 1, 2, 3]), &work), Verdict::Taken);
    }
}
