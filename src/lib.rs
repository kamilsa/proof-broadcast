//! Shadow-compatible simulator for leanVM proof propagation.
//!
//! L1 provers (one per `(subnet, prover)`) each publish a proof; L2 provers
//! collect one proof per subnet and aggregate them with 2→1 recursion. Four
//! transports are compared: whole proofs over gossipsub, chunked proofs over
//! gossipsub 1.3 partial messages, chunks as plain gossipsub messages, and
//! pushed headers with chunks pulled on demand (pull-gated gossipsub).
//! Optionally, L2 provers also publish their intermediate aggregates for
//! other L2s to fetch.

pub mod aggregation;
pub mod chunked_mode;
pub mod events;
pub mod gossip_mode;
pub mod network;
pub mod node;
pub mod partial_mode;
pub mod proof;

pub use node::{Cli, Mode, NodeReport, Role, run};
