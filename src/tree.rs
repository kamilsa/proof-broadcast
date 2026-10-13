//! The aggregation tree and every L2's place in it.
//!
//! The tree is built bottom-up from the subnets. The items of level 0 are
//! the subnets `0..subnets`. Each level groups consecutive items `arity` at a
//! time; a group of two or more becomes a tree node (one k→1 recursion over
//! its inputs), and a trailing single item is promoted unchanged to the next
//! level. Node ids run level by level, left to right, so the root is last.
//!
//! ```text
//! 16 subnets, arity 2: 8 + 4 + 2 + 1 = 15 nodes, depth 4
//! 16 subnets, arity 4: 4 + 1          =  5 nodes, depth 2
//!  5 subnets, arity 2: {0,1} {2,3} | {0..3} | root = {0..3} + subnet 4
//! ```
//!
//! An L2's tree node follows from its PeerId alone ([`Tree::position`]), so
//! any peer can tell which node a connected L2 aggregates for.

use libp2p::PeerId;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::proof::{Committees, MAX_SUBNETS, subnets_of};

/// One input of a tree node: a subnet proof, or a child node's aggregate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    Subnet(u16),
    Node(usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeNode {
    pub id: usize,
    /// 0 for the bottom level; the root has the highest level.
    pub level: usize,
    /// Committees the node's aggregate covers.
    pub mask: Committees,
    pub parent: Option<usize>,
    pub inputs: Vec<Input>,
}

#[derive(Clone, Debug)]
pub struct Tree {
    subnets: usize,
    arity: usize,
    nodes: Vec<TreeNode>,
}

impl Tree {
    /// `subnets` is clamped to `2..=64` and `arity` to at least 2.
    pub fn new(subnets: usize, arity: usize) -> Self {
        let subnets = subnets.clamp(2, MAX_SUBNETS);
        let arity = arity.max(2);
        let mut nodes: Vec<TreeNode> = Vec::new();
        let mut items: Vec<Input> = (0..subnets as u16).map(Input::Subnet).collect();
        let mut level = 0;
        while items.len() > 1 {
            let mut next = Vec::new();
            for group in items.chunks(arity) {
                if let [single] = group {
                    next.push(*single);
                    continue;
                }
                let id = nodes.len();
                let mut mask = 0;
                for input in group {
                    mask |= match *input {
                        Input::Subnet(s) => 1 << s,
                        Input::Node(child) => {
                            nodes[child].parent = Some(id);
                            nodes[child].mask
                        }
                    };
                }
                nodes.push(TreeNode {
                    id,
                    level,
                    mask,
                    parent: None,
                    inputs: group.to_vec(),
                });
                next.push(Input::Node(id));
            }
            items = next;
            level += 1;
        }
        Self {
            subnets,
            arity,
            nodes,
        }
    }

    pub fn subnets(&self) -> usize {
        self.subnets
    }

    pub fn arity(&self) -> usize {
        self.arity
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn nodes(&self) -> &[TreeNode] {
        &self.nodes
    }

    pub fn node(&self, id: usize) -> &TreeNode {
        &self.nodes[id]
    }

    pub fn root(&self) -> usize {
        self.nodes.len() - 1
    }

    /// Number of levels.
    pub fn depth(&self) -> usize {
        self.nodes.last().map_or(0, |root| root.level + 1)
    }

    /// Committees of one input.
    pub fn input_mask(&self, input: Input) -> Committees {
        match input {
            Input::Subnet(s) => 1 << s,
            Input::Node(id) => self.nodes[id].mask,
        }
    }

    /// Committees of each input of node `id`, in input order.
    pub fn input_masks(&self, id: usize) -> Vec<Committees> {
        self.nodes[id]
            .inputs
            .iter()
            .map(|&input| self.input_mask(input))
            .collect()
    }

    /// Whether a proof covering exactly `mask` is an input of node `id`.
    pub fn needs(&self, id: usize, mask: Committees) -> bool {
        self.nodes[id]
            .inputs
            .iter()
            .any(|&input| self.input_mask(input) == mask)
    }

    /// The node that merges subnet `s`'s proof.
    pub fn consumer_of_subnet(&self, s: u16) -> Option<usize> {
        self.nodes
            .iter()
            .position(|n| n.inputs.contains(&Input::Subnet(s)))
    }

    /// The tree node an L2 with this PeerId aggregates for: the first 8 bytes
    /// of `sha256(peer_id)` (little endian) modulo the node count.
    pub fn position(&self, peer: &PeerId) -> usize {
        let digest = Sha256::digest(peer.to_bytes());
        let word = u64::from_le_bytes(digest[..8].try_into().expect("8 bytes"));
        (word % self.nodes.len() as u64) as usize
    }

    /// The tree as JSON-friendly records (for `--dump-tree`).
    pub fn dump(&self) -> Vec<DumpNode> {
        self.nodes
            .iter()
            .map(|n| DumpNode {
                id: n.id,
                level: n.level,
                mask: n.mask,
                committees: subnets_of(n.mask),
                parent: n.parent,
                child_nodes: n
                    .inputs
                    .iter()
                    .filter_map(|i| match *i {
                        Input::Node(c) => Some(c),
                        Input::Subnet(_) => None,
                    })
                    .collect(),
                input_subnets: n
                    .inputs
                    .iter()
                    .filter_map(|i| match *i {
                        Input::Subnet(s) => Some(s),
                        Input::Node(_) => None,
                    })
                    .collect(),
            })
            .collect()
    }
}

/// One tree node as printed by `--dump-tree`.
#[derive(Debug, Clone, Serialize)]
pub struct DumpNode {
    pub id: usize,
    pub level: usize,
    pub mask: Committees,
    pub committees: Vec<u16>,
    pub parent: Option<usize>,
    pub child_nodes: Vec<usize>,
    pub input_subnets: Vec<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::keypair_from_seed;
    use crate::proof::{full_mask, mask_of};

    fn level_sizes(tree: &Tree) -> Vec<usize> {
        let mut sizes = vec![0; tree.depth()];
        for n in tree.nodes() {
            sizes[n.level] += 1;
        }
        sizes
    }

    #[test]
    fn sixteen_subnets_binary() {
        let t = Tree::new(16, 2);
        assert_eq!(t.len(), 15);
        assert_eq!(level_sizes(&t), vec![8, 4, 2, 1]);
        assert_eq!(t.depth(), 4);
        assert_eq!(t.node(0).mask, 0b11);
        assert_eq!(t.node(0).inputs, vec![Input::Subnet(0), Input::Subnet(1)]);
        assert_eq!(t.node(0).parent, Some(8));
        assert_eq!(t.node(8).mask, 0b1111);
        assert_eq!(t.node(8).inputs, vec![Input::Node(0), Input::Node(1)]);
        assert_eq!(t.root(), 14);
        assert_eq!(t.node(14).mask, full_mask(16));
        assert_eq!(t.node(14).parent, None);
        assert_eq!(t.consumer_of_subnet(5), Some(2));
        assert_eq!(t.input_masks(12), vec![0xf, 0xf0]);
        assert_eq!(t.input_masks(14), vec![0xff, 0xff00]);
        assert!(t.needs(14, 0xff));
        assert!(!t.needs(14, 0xf));
    }

    #[test]
    fn sixteen_subnets_arity_four() {
        let t = Tree::new(16, 4);
        assert_eq!(t.len(), 5);
        assert_eq!(level_sizes(&t), vec![4, 1]);
        assert_eq!(t.node(1).mask, 0xf0);
        assert_eq!(t.input_masks(4), vec![0xf, 0xf0, 0xf00, 0xf000]);
        assert_eq!(t.consumer_of_subnet(15), Some(3));
    }

    #[test]
    fn single_trailing_items_are_promoted() {
        let t = Tree::new(5, 2);
        assert_eq!(t.len(), 4);
        assert_eq!(t.node(2).mask, 0b1111);
        assert_eq!(t.node(2).level, 1);
        let root = t.node(3);
        assert_eq!(root.level, 2);
        assert_eq!(root.inputs, vec![Input::Node(2), Input::Subnet(4)]);
        assert_eq!(root.mask, full_mask(5));
        assert_eq!(t.consumer_of_subnet(4), Some(3));
        assert_eq!(t.input_masks(3), vec![0b1111, 0b10000]);
    }

    #[test]
    fn uneven_last_group_merges_fewer_inputs() {
        let t = Tree::new(10, 4);
        assert_eq!(t.len(), 4);
        assert_eq!(t.node(2).mask, mask_of(&[8, 9]));
        assert_eq!(t.node(3).inputs, vec![Input::Node(0), Input::Node(1), Input::Node(2)]);
        assert_eq!(t.depth(), 2);
    }

    #[test]
    fn arity_at_least_subnets_is_one_flat_root() {
        let t = Tree::new(4, 8);
        assert_eq!(t.len(), 1);
        assert_eq!(t.node(0).inputs.len(), 4);
        assert_eq!(t.depth(), 1);
        assert_eq!(t.consumer_of_subnet(3), Some(0));
    }

    #[test]
    fn every_subnet_has_exactly_one_consumer() {
        for subnets in 2..=64 {
            for arity in [2, 3, 4, 8] {
                let t = Tree::new(subnets, arity);
                for s in 0..subnets as u16 {
                    let consumers = t
                        .nodes()
                        .iter()
                        .filter(|n| n.inputs.contains(&Input::Subnet(s)))
                        .count();
                    assert_eq!(consumers, 1, "{subnets}/{arity} subnet {s}");
                }
                assert_eq!(t.node(t.root()).mask, full_mask(subnets));
                // Every non-root node has a parent that lists it as an input.
                for n in &t.nodes()[..t.root()] {
                    let parent = n.parent.expect("non-root has a parent");
                    assert!(t.node(parent).inputs.contains(&Input::Node(n.id)));
                    assert!(t.node(parent).level > n.level);
                }
            }
        }
    }

    #[test]
    fn position_is_deterministic_and_in_range() {
        let t = Tree::new(16, 2);
        let mut seen = vec![0; t.len()];
        for seed in 0..300 {
            let peer = PeerId::from(keypair_from_seed(seed).public());
            let pos = t.position(&peer);
            assert_eq!(pos, t.position(&peer));
            seen[pos] += 1;
        }
        assert!(seen.iter().all(|&n| n > 0), "300 peers reach every node: {seen:?}");
    }
}
