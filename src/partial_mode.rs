//! Gossipsub 1.3 partial-message transport for chunked proofs.
//!
//! Adapted from ec-sim's `payload_chunks.rs`. The group id is the
//! [`ProofId`], so an announcement alone tells an L2 which subnet a proof
//! proves. Metadata is a pair of chunk bitmaps (`available`, `requests`):
//!
//! - An L1 prover advertises `available = all`, `requests = none`. It sends a
//!   chunk body only to peers whose metadata requests chunks.
//! - An L2 that has not chosen a proof for that subnet commits to the first
//!   one a peer holds chunks of, and advertises `requests = all`. Any holder
//!   (the L1 or another L2) then sends it what it lacks.
//! - An L2 that already chose another proof for the subnet never advertises
//!   the group, so it never receives (or relays) that proof's chunks.

use std::collections::HashMap;
use std::sync::Arc;

use libp2p::PeerId;
use libp2p::gossipsub::partial_messages::{Metadata, Partial, PartialAction, PartialError};
use serde::{Deserialize, Serialize};

use crate::proof::{ProofId, assemble};

/// A growable-length bitmap. Backing storage is `ceil(len / 8)` bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellBitmap {
    len: usize,
    bits: Vec<u8>,
}

impl CellBitmap {
    pub fn with_len(len: usize) -> Self {
        Self {
            len,
            bits: vec![0u8; len.div_ceil(8)],
        }
    }

    pub fn all_set(len: usize) -> Self {
        let mut b = Self::with_len(len);
        for i in 0..len {
            b.set(i);
        }
        b
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn get(&self, idx: usize) -> bool {
        idx < self.len && (self.bits[idx / 8] >> (idx % 8)) & 1 == 1
    }

    pub fn set(&mut self, idx: usize) {
        if idx < self.len {
            self.bits[idx / 8] |= 1 << (idx % 8);
        }
    }

    pub fn ones(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.len).filter(|&i| self.get(i))
    }

    pub fn count(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }

    pub fn is_full(&self) -> bool {
        self.count() == self.len
    }

    pub fn union(&self, other: &Self) -> Self {
        let mut out = self.clone();
        for i in other.ones() {
            out.set(i);
        }
        out
    }

    pub fn difference(&self, other: &Self) -> Self {
        let mut out = Self::with_len(self.len);
        for i in self.ones().filter(|&i| !other.get(i)) {
            out.set(i);
        }
        out
    }

    pub fn intersection(&self, other: &Self) -> Self {
        let mut out = Self::with_len(self.len);
        for i in self.ones().filter(|&i| other.get(i)) {
            out.set(i);
        }
        out
    }

    pub fn is_subset(&self, other: &Self) -> bool {
        self.ones().all(|i| other.get(i))
    }

    /// Whether the bitmap is well formed for a `len`-chunk proof (decoded
    /// bitmaps come from the wire).
    pub fn is_valid_for(&self, len: usize) -> bool {
        self.len == len
            && self.bits.len() == len.div_ceil(8)
            && (len.is_multiple_of(8) || self.bits.last().is_none_or(|last| last >> (len % 8) == 0))
    }
}

/// What a peer holds (`available`) and wants (`requests`) of one proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartsMetadata {
    pub available: CellBitmap,
    pub requests: CellBitmap,
}

impl PartsMetadata {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("serialize parts metadata")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PartialError> {
        bincode::deserialize(bytes).map_err(|_| PartialError::InvalidFormat)
    }

    fn decode_for(bytes: &[u8], chunks: usize) -> Result<Self, PartialError> {
        let meta = Self::decode(bytes)?;
        if meta.available.is_valid_for(chunks) && meta.requests.is_valid_for(chunks) {
            Ok(meta)
        } else {
            Err(PartialError::InvalidFormat)
        }
    }
}

/// A sparse set of a proof's chunks: the partial-message body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkBody {
    pub present: CellBitmap,
    /// Present chunks, ascending by index.
    pub chunks: Vec<Vec<u8>>,
}

impl ChunkBody {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("serialize chunk body")
    }

    /// Decode and check the body against the proof layout (bitmap length,
    /// chunk count and every chunk's length).
    pub fn decode_for(bytes: &[u8], id: &ProofId) -> Result<Self, PartialError> {
        let body: Self = bincode::deserialize(bytes).map_err(|_| PartialError::InvalidFormat)?;
        let valid = body.present.is_valid_for(id.chunks())
            && body.present.count() == body.chunks.len()
            && body
                .present
                .ones()
                .zip(&body.chunks)
                .all(|(idx, chunk)| id.chunk_len(idx) == Some(chunk.len()));
        if valid {
            Ok(body)
        } else {
            Err(PartialError::InvalidFormat)
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (usize, &Vec<u8>)> {
        self.present.ones().zip(&self.chunks)
    }
}

/// Our view of a peer's metadata (or the peer's view of ours), as tracked by
/// the gossipsub partial extension. Bits only ever grow.
#[derive(Debug, Clone)]
pub enum ProofMetadata {
    Unknown { chunks: usize },
    Known {
        metadata: PartsMetadata,
        encoded: Vec<u8>,
    },
}

impl ProofMetadata {
    fn known(metadata: PartsMetadata) -> Self {
        let encoded = metadata.encode();
        Self::Known { metadata, encoded }
    }

    fn chunks(&self) -> usize {
        match self {
            Self::Unknown { chunks } => *chunks,
            Self::Known { metadata, .. } => metadata.available.len(),
        }
    }

    fn merge(&mut self, incoming: PartsMetadata) -> bool {
        match self {
            Self::Unknown { .. } => {
                *self = Self::known(incoming);
                true
            }
            Self::Known { metadata, .. } => {
                let merged = PartsMetadata {
                    available: metadata.available.union(&incoming.available),
                    requests: metadata.requests.union(&incoming.requests),
                };
                if merged == *metadata {
                    false
                } else {
                    *self = Self::known(merged);
                    true
                }
            }
        }
    }
}

impl Metadata for ProofMetadata {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Unknown { .. } => &[],
            Self::Known { encoded, .. } => encoded,
        }
    }

    fn update(&mut self, data: &[u8]) -> Result<bool, PartialError> {
        let incoming = PartsMetadata::decode_for(data, self.chunks())?;
        Ok(self.merge(incoming))
    }

    fn update_from_data(&mut self, data: &[u8]) -> Result<(), PartialError> {
        if data.is_empty() {
            return Ok(());
        }
        let body: ChunkBody = bincode::deserialize(data).map_err(|_| PartialError::InvalidFormat)?;
        if !body.present.is_valid_for(self.chunks()) {
            return Err(PartialError::InvalidFormat);
        }
        // A peer that received these chunks now has (and wanted) them.
        self.merge(PartsMetadata {
            available: body.present.clone(),
            requests: body.present,
        });
        Ok(())
    }
}

/// Chunk storage shared between the assembler and published snapshots.
pub type ChunkStore = Arc<Vec<Option<Arc<Vec<u8>>>>>;

/// One proof as published through the partial extension. The extension
/// caches the latest published instance per group and answers peer metadata
/// through [`Partial::partial_action_from_metadata`].
pub struct OutgoingProof {
    id: ProofId,
    chunks: ChunkStore,
    available: CellBitmap,
    metadata: ProofMetadata,
}

impl OutgoingProof {
    /// `requests` is what we still want: nothing for an L1 prover, every
    /// chunk for an L2 that committed to this proof.
    pub fn new(id: ProofId, chunks: ChunkStore, requests: CellBitmap) -> Self {
        let mut available = CellBitmap::with_len(id.chunks());
        for (i, chunk) in chunks.iter().enumerate() {
            if chunk.is_some() {
                available.set(i);
            }
        }
        let metadata = ProofMetadata::known(PartsMetadata {
            available: available.clone(),
            requests: requests.union(&available),
        });
        Self {
            id,
            chunks,
            available,
            metadata,
        }
    }

    fn body(&self, want: &CellBitmap) -> ChunkBody {
        let mut present = CellBitmap::with_len(self.id.chunks());
        let mut chunks = Vec::new();
        for idx in want.ones() {
            if let Some(Some(chunk)) = self.chunks.get(idx) {
                present.set(idx);
                chunks.push(chunk.as_ref().clone());
            }
        }
        ChunkBody { present, chunks }
    }
}

impl Partial for OutgoingProof {
    fn group_id(&self) -> Vec<u8> {
        self.id.group_id()
    }

    fn metadata(&self) -> Box<dyn Metadata> {
        Box::new(self.metadata.clone())
    }

    fn partial_action_from_metadata(
        &self,
        _peer_id: PeerId,
        metadata: Option<&[u8]>,
    ) -> Result<PartialAction, PartialError> {
        let nothing = PartialAction {
            need: false,
            send: None,
        };
        // First contact carries only our metadata (the announcement); chunk
        // bodies go only to peers that asked for them.
        let Some(bytes) = metadata.filter(|b| !b.is_empty()) else {
            return Ok(nothing);
        };
        let peer = PartsMetadata::decode_for(bytes, self.id.chunks())?;
        // Surface every peer message to the application, not only those
        // carrying chunks we lack, so duplicate chunk bodies get counted.
        let need = true;
        let want = peer
            .requests
            .difference(&peer.available)
            .intersection(&self.available);
        if want.count() == 0 {
            return Ok(PartialAction { need, send: None });
        }
        let body = self.body(&want);
        let updated = PartsMetadata {
            available: peer.available.union(&body.present),
            requests: peer.requests.union(&body.present),
        };
        Ok(PartialAction {
            need,
            send: Some((
                body.encode(),
                Box::new(ProofMetadata::known(updated)) as Box<dyn Metadata>,
            )),
        })
    }
}

/// Outcome of merging a received body into an assembly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeOutcome {
    pub added: usize,
    pub duplicate: usize,
    pub held: usize,
    /// The full, verified proof, returned once when the last chunk lands.
    pub completed: Option<Vec<u8>>,
    /// All chunks arrived but the hash did not match.
    pub invalid: bool,
}

/// Chunks collected for one committed proof.
pub struct ProofAssembly {
    pub id: ProofId,
    chunks: Vec<Option<Arc<Vec<u8>>>>,
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

    /// The source's own proof: every chunk present.
    pub fn from_chunks(id: ProofId, chunks: Vec<Vec<u8>>) -> Self {
        Self {
            id,
            chunks: chunks.into_iter().map(|c| Some(Arc::new(c))).collect(),
            complete: true,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn held(&self) -> usize {
        self.chunks.iter().filter(|c| c.is_some()).count()
    }

    pub fn store(&self) -> ChunkStore {
        Arc::new(self.chunks.clone())
    }

    pub fn merge(&mut self, body: &ChunkBody) -> MergeOutcome {
        let mut out = MergeOutcome::default();
        for (idx, chunk) in body.iter() {
            match self.chunks.get_mut(idx) {
                Some(slot @ None) => {
                    *slot = Some(Arc::new(chunk.clone()));
                    out.added += 1;
                }
                Some(Some(_)) => out.duplicate += 1,
                None => {}
            }
        }
        out.held = self.held();
        if !self.complete && out.added > 0 && out.held == self.chunks.len() {
            let parts: Vec<&[u8]> = self
                .chunks
                .iter()
                .map(|c| c.as_ref().expect("all chunks held").as_slice())
                .collect();
            match assemble(&self.id, &parts) {
                Some(proof) => {
                    self.complete = true;
                    out.completed = Some(proof);
                }
                None => {
                    // Drop everything so the proof can be fetched again.
                    self.chunks.iter_mut().for_each(|c| *c = None);
                    out.invalid = true;
                }
            }
        }
        out
    }
}

/// Per-node partial-mode state: assemblies for the proofs this node holds or
/// has committed to, keyed by proof hash.
#[derive(Default)]
pub struct PartialState {
    pub assemblies: HashMap<[u8; 32], ProofAssembly>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::{make_proof, split};

    fn proof_id(len: usize, chunks: usize) -> (ProofId, Vec<Vec<u8>>) {
        let proof = make_proof(5, len);
        let id = ProofId::for_proof(1, 2, &proof, chunks);
        let parts = split(&proof, id.chunks());
        (id, parts)
    }

    fn peer() -> PeerId {
        PeerId::random()
    }

    fn meta(available: &CellBitmap, requests: &CellBitmap) -> Vec<u8> {
        PartsMetadata {
            available: available.clone(),
            requests: requests.clone(),
        }
        .encode()
    }

    #[test]
    fn bitmap_ops() {
        let mut a = CellBitmap::with_len(10);
        a.set(1);
        a.set(9);
        let mut b = CellBitmap::with_len(10);
        b.set(9);
        assert_eq!(a.count(), 2);
        assert!(b.is_subset(&a));
        assert!(!a.is_subset(&b));
        assert_eq!(a.difference(&b).ones().collect::<Vec<_>>(), vec![1]);
        assert_eq!(a.intersection(&b).ones().collect::<Vec<_>>(), vec![9]);
        assert!(CellBitmap::all_set(10).is_full());
        assert!(a.is_valid_for(10));
        assert!(!a.is_valid_for(11));
    }

    #[test]
    fn source_announces_without_body() {
        let (id, parts) = proof_id(1000, 8);
        let source = ProofAssembly::from_chunks(id, parts);
        let out = OutgoingProof::new(id, source.store(), CellBitmap::with_len(8));
        let action = out.partial_action_from_metadata(peer(), None).unwrap();
        assert!(action.send.is_none());
        let advertised = PartsMetadata::decode(out.metadata().as_slice()).unwrap();
        assert!(advertised.available.is_full());
        assert_eq!(advertised.requests, CellBitmap::all_set(8));
    }

    #[test]
    fn serves_requested_missing_chunks() {
        let (id, parts) = proof_id(1000, 8);
        let source = ProofAssembly::from_chunks(id, parts.clone());
        let out = OutgoingProof::new(id, source.store(), CellBitmap::with_len(8));
        let mut have = CellBitmap::with_len(8);
        have.set(0);
        have.set(5);
        let action = out
            .partial_action_from_metadata(peer(), Some(&meta(&have, &CellBitmap::all_set(8))))
            .unwrap();
        let (bytes, _) = action.send.expect("chunks sent");
        let body = ChunkBody::decode_for(&bytes, &id).unwrap();
        assert_eq!(body.present.ones().collect::<Vec<_>>(), vec![1, 2, 3, 4, 6, 7]);
        for (idx, chunk) in body.iter() {
            assert_eq!(chunk, &parts[idx]);
        }
    }

    #[test]
    fn sends_nothing_without_requests() {
        let (id, parts) = proof_id(1000, 8);
        let source = ProofAssembly::from_chunks(id, parts);
        let out = OutgoingProof::new(id, source.store(), CellBitmap::with_len(8));
        let none = CellBitmap::with_len(8);
        let action = out
            .partial_action_from_metadata(peer(), Some(&meta(&none, &none)))
            .unwrap();
        assert!(action.send.is_none());
    }

    #[test]
    fn relay_needs_peer_chunks_and_serves_its_own() {
        let (id, parts) = proof_id(1000, 8);
        let mut relay = ProofAssembly::new(id);
        let mut first = CellBitmap::with_len(8);
        first.set(0);
        first.set(1);
        relay.merge(&ChunkBody {
            present: first.clone(),
            chunks: vec![parts[0].clone(), parts[1].clone()],
        });
        let out = OutgoingProof::new(id, relay.store(), CellBitmap::all_set(8));
        let action = out
            .partial_action_from_metadata(
                peer(),
                Some(&meta(&CellBitmap::all_set(8), &CellBitmap::all_set(8))),
            )
            .unwrap();
        assert!(action.need);
        assert!(action.send.is_none());
        let action = out
            .partial_action_from_metadata(
                peer(),
                Some(&meta(&CellBitmap::with_len(8), &CellBitmap::all_set(8))),
            )
            .unwrap();
        let (bytes, _) = action.send.unwrap();
        assert_eq!(ChunkBody::decode_for(&bytes, &id).unwrap().present, first);
    }

    #[test]
    fn assembly_completes_and_counts_duplicates() {
        let (id, parts) = proof_id(1000, 4);
        let mut asm = ProofAssembly::new(id);
        let body = |idx: &[usize]| {
            let mut present = CellBitmap::with_len(4);
            idx.iter().for_each(|&i| present.set(i));
            ChunkBody {
                present,
                chunks: idx.iter().map(|&i| parts[i].clone()).collect(),
            }
        };
        let out = asm.merge(&body(&[0, 1]));
        assert_eq!((out.added, out.duplicate, out.held), (2, 0, 2));
        let out = asm.merge(&body(&[1, 2]));
        assert_eq!((out.added, out.duplicate), (1, 1));
        assert!(out.completed.is_none());
        let out = asm.merge(&body(&[3]));
        assert_eq!(out.completed.as_deref(), Some(parts.concat().as_slice()));
        assert!(asm.is_complete());
        let out = asm.merge(&body(&[3]));
        assert!(out.completed.is_none());
        assert_eq!(out.duplicate, 1);
    }

    #[test]
    fn decode_rejects_wrong_chunk_length() {
        let (id, parts) = proof_id(1000, 4);
        let mut present = CellBitmap::with_len(4);
        present.set(0);
        let mut chunk = parts[0].clone();
        chunk.push(0);
        let bytes = ChunkBody {
            present,
            chunks: vec![chunk],
        }
        .encode();
        assert!(ChunkBody::decode_for(&bytes, &id).is_err());
    }

    #[test]
    fn metadata_merges_monotonically() {
        let mut m = ProofMetadata::Unknown { chunks: 4 };
        let mut a = CellBitmap::with_len(4);
        a.set(0);
        assert!(m.update(&meta(&a, &a)).unwrap());
        assert!(!m.update(&meta(&a, &a)).unwrap());
        let mut b = CellBitmap::with_len(4);
        b.set(2);
        assert!(m.update(&meta(&b, &b)).unwrap());
        let merged = PartsMetadata::decode(m.as_slice()).unwrap();
        assert_eq!(merged.available.ones().collect::<Vec<_>>(), vec![0, 2]);
        assert!(m.update(&meta(&CellBitmap::with_len(5), &a)).is_err());
    }
}
