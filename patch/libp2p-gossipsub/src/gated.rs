//! proof-broadcast: pull-gated topics.
//!
//! On a gated topic every message belongs to a *group* (extracted from its
//! data by an application-supplied function). A message is published or
//! forwarded only to peers that asked for its group with a `WANT` control
//! message. Messages we publish or forward are kept per group, so a peer
//! asking late still receives everything we hold, followed by whatever we
//! forward afterwards. Gated messages are never advertised through IHAVE.

use std::collections::{HashMap, HashSet, VecDeque};

use libp2p_identity::PeerId;

use crate::types::{MessageId, RawMessage};

/// Extracts the group of a message on a gated topic from its data; `None`
/// leaves the message ungated (ordinary mesh forwarding).
pub type GroupFn = fn(&[u8]) -> Option<Vec<u8>>;

/// Groups kept per topic; the oldest are evicted beyond this.
const MAX_GROUPS: usize = 256;

#[derive(Clone)]
struct Stored {
    id: MessageId,
    message: RawMessage,
    /// Who sent it to us (never replayed back to them).
    from: Option<PeerId>,
}

pub(crate) struct GatedTopic {
    group_fn: GroupFn,
    wants: HashMap<Vec<u8>, HashSet<PeerId>>,
    store: HashMap<Vec<u8>, Vec<Stored>>,
    order: VecDeque<Vec<u8>>,
}

impl GatedTopic {
    pub(crate) fn new(group_fn: GroupFn) -> Self {
        Self {
            group_fn,
            wants: HashMap::new(),
            store: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub(crate) fn group(&self, data: &[u8]) -> Option<Vec<u8>> {
        (self.group_fn)(data)
    }

    /// Keep a message we published or forwarded, for peers asking later.
    pub(crate) fn store(
        &mut self,
        group: &[u8],
        id: &MessageId,
        message: &RawMessage,
        from: Option<PeerId>,
    ) {
        if !self.store.contains_key(group) {
            if self.order.len() == MAX_GROUPS {
                if let Some(old) = self.order.pop_front() {
                    self.store.remove(&old);
                }
            }
            self.order.push_back(group.to_vec());
        }
        let held = self.store.entry(group.to_vec()).or_default();
        if !held.iter().any(|s| &s.id == id) {
            held.push(Stored {
                id: id.clone(),
                message: message.clone(),
                from,
            });
        }
    }

    /// Peers that asked for `group`.
    pub(crate) fn wanters(&self, group: &[u8]) -> Vec<PeerId> {
        self.wants
            .get(group)
            .map(|peers| peers.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Record that `peer` wants `group`; returns the messages of the group we
    /// already hold that `peer` did not send us.
    pub(crate) fn want(&mut self, peer: PeerId, group: Vec<u8>) -> Vec<(MessageId, RawMessage)> {
        let held = self
            .store
            .get(&group)
            .map(|held| {
                held.iter()
                    .filter(|s| s.from != Some(peer))
                    .map(|s| (s.id.clone(), s.message.clone()))
                    .collect()
            })
            .unwrap_or_default();
        self.wants.entry(group).or_default().insert(peer);
        held
    }

    pub(crate) fn remove_peer(&mut self, peer: &PeerId) {
        for peers in self.wants.values_mut() {
            peers.remove(peer);
        }
    }
}
