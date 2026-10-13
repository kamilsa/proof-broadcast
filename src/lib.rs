//! Shadow-compatible simulator for leanVM proof aggregation along a tree.
//!
//! L1 provers (one per `(subnet, prover)`) each produce a subnet proof. L2
//! provers are aggregators, each placed at one node of an aggregation tree
//! by its PeerId. A tree node merges its inputs (subnet proofs or child
//! aggregates) with one k→1 recursion; the root's aggregate is the global
//! proof. Peers handshake, announce the chunks they hold, and pull missing
//! proofs chunk by chunk over one request-response protocol (no gossipsub).
//! A peer relays a proof while still downloading it, to at most `fanout`
//! peers at a time.

pub mod assembly;
pub mod events;
pub mod fanout;
pub mod fetch;
pub mod network;
pub mod node;
pub mod proof;
pub mod protocol;
pub mod tree;

pub use node::{Cli, NodeReport, run};
pub use protocol::Role;
