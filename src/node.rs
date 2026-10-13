//! One simulated prover: CLI, protocol handling and the run loop.
//!
//! Timeline (all processes start together under Shadow, so these instants
//! line up across hosts): connect and handshake during `warmup_secs`; at
//! `epoch = start + warmup_secs` each L1 prover waits its own
//! `publish_delay_ms` and produces its proof; every node exits at
//! `epoch + observe_secs`.
//!
//! Flow: an L1 announces (`Have`) its proof to aggregators of the tree node
//! that consumes its subnet. An L2 commits to the first proof announced for
//! each input of its node and pulls it chunk by chunk from the peers that
//! announced it. As chunks land it announces them to node-mates that need
//! the proof (cut-through: it serves a proof while still downloading it).
//! With every input held it runs one k→1 recursion and announces the
//! aggregate to the members of its parent node; at the root, that aggregate
//! is the global proof.
//!
//! Every proof is announced to, and served to, at most `fanout` peers at a
//! time (see [`crate::fanout`]).

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use clap::Parser;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use libp2p::request_response::{self, OutboundRequestId, ResponseChannel};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, Swarm};
use serde::Serialize;
use tokio::time::{self, Duration, Instant};
use tracing::{debug, info, warn};

use crate::assembly::{ChunkBits, ProofAssembly};
use crate::event;
use crate::fanout::{Fanout, rank};
use crate::fetch::{ChunkOutcome, ChunkRequest, Fetcher, HaveOutcome};
use crate::network::{RrTuning, SimBehaviour, SimBehaviourEvent, build_swarm, dial_peers, peer_id_from_seed};
use crate::proof::{MAX_CHUNKS, MAX_SUBNETS, ProofId, make_aggregate, make_proof, subnet_list, subnets_of};
use crate::protocol::{Holding, Request, Response, Role, Traffic};
use crate::tree::{DumpNode, Tree};

/// Emit `$leaf` for a subnet proof or `$agg` for an aggregate, with the
/// proof's identity fields followed by the given ones.
macro_rules! proof_event {
    ($id:expr, $leaf:literal, $agg:literal $(, $key:ident = $val:expr)* $(,)?) => {{
        let id: &ProofId = $id;
        if id.is_aggregate() {
            event!(
                $agg,
                committees = subnet_list(&id.subnets()),
                mask = id.committees,
                prover = id.prover,
                hash = id.label()
                $(, $key = $val)*
            );
        } else {
            event!($leaf, subnet = id.subnet, prover = id.prover, hash = id.label() $(, $key = $val)*);
        }
    }};
}

#[derive(Parser, Debug, Clone)]
#[command(name = "proof-broadcast-tree", about = "leanVM proof-aggregation-tree simulator node")]
pub struct Cli {
    #[arg(long, value_enum, default_value_t = Role::L2)]
    pub role: Role,

    /// Subnet this L1 prover proves.
    #[arg(long, default_value_t = 0)]
    pub subnet: u16,

    /// L1: index within its subnet. L2: index among L2 provers (labels the
    /// aggregates it produces).
    #[arg(long, default_value_t = 0)]
    pub prover: u16,

    /// Number of subnets (leaves of the tree).
    #[arg(long, default_value_t = 16)]
    pub subnets: usize,

    /// Tree fan-in: inputs one k→1 recursion merges (2 = leanVM 2→1).
    #[arg(long, default_value_t = 2)]
    pub aggregation_arity: usize,

    /// Deterministic seed (keypair and proof bytes).
    #[arg(long, default_value_t = 42)]
    pub seed: u64,

    #[arg(long, default_value = "0.0.0.0")]
    pub listen_ip: String,

    #[arg(long, default_value_t = 9000)]
    pub listen_port: u16,

    /// Print one libp2p PeerId per seed and exit (used by the launcher).
    #[arg(long, value_delimiter = ',')]
    pub dump_peer_ids: Vec<u64>,

    /// Print the tree, and the tree node of every `--dump-peer-ids` seed, as
    /// JSON and exit (used by the launcher).
    #[arg(long, default_value_t = false)]
    pub dump_tree: bool,

    /// Peer multiaddrs to dial (QUIC).
    #[arg(long = "peer")]
    pub peers: Vec<Multiaddr>,

    #[arg(long, default_value_t = 300)]
    pub proof_size_kib: usize,

    /// Chunks per proof.
    #[arg(long, default_value_t = 64)]
    pub chunk_count: usize,

    /// L1 publish delay after the warmup epoch.
    #[arg(long, default_value_t = 0)]
    pub publish_delay_ms: u64,

    /// Duration of one k→1 recursion, whatever its input count (leanVM 2→1:
    /// 0.287 s on an M4 Max).
    #[arg(long, default_value_t = 290)]
    pub aggregation_ms: u64,

    /// Most chunk requests outstanding to one peer.
    #[arg(long, default_value_t = 64)]
    pub max_inflight_per_peer: usize,

    /// Most peers one proof is announced and served to at a time.
    #[arg(long, default_value_t = 8)]
    pub fanout: usize,

    /// Chunk-progress announcements are batched over this interval (0 = at
    /// once).
    #[arg(long, default_value_t = 10)]
    pub have_interval_ms: u64,

    #[arg(long, default_value_t = 10_000)]
    pub request_timeout_ms: u64,

    #[arg(long, default_value_t = 15)]
    pub warmup_secs: u64,

    #[arg(long, default_value_t = 20)]
    pub observe_secs: u64,
}

impl Cli {
    pub fn validate(&self) -> Result<(), String> {
        if self.subnets < 2 || self.subnets > MAX_SUBNETS {
            return Err(format!("subnets must be in 2..={MAX_SUBNETS}, got {}", self.subnets));
        }
        if self.role == Role::L1 && self.subnet as usize >= self.subnets {
            return Err(format!(
                "subnet {} out of range for {} subnets",
                self.subnet, self.subnets
            ));
        }
        if self.chunk_count == 0 || self.chunk_count > MAX_CHUNKS {
            return Err(format!(
                "chunk count must be in 1..={MAX_CHUNKS}, got {}",
                self.chunk_count
            ));
        }
        if self.proof_size_kib == 0 {
            return Err("proof size must be positive".to_string());
        }
        if self.aggregation_arity < 2 || self.aggregation_arity > MAX_SUBNETS {
            return Err(format!(
                "aggregation arity must be in 2..={MAX_SUBNETS}, got {}",
                self.aggregation_arity
            ));
        }
        if self.max_inflight_per_peer == 0 {
            return Err("max inflight per peer must be positive".to_string());
        }
        if self.fanout == 0 {
            return Err("fanout must be positive".to_string());
        }
        if self.request_timeout_ms == 0 {
            return Err("request timeout must be positive".to_string());
        }
        Ok(())
    }

    pub fn tree(&self) -> Tree {
        Tree::new(self.subnets, self.aggregation_arity)
    }

    fn proof_len(&self) -> usize {
        self.proof_size_kib.saturating_mul(1024)
    }
}

/// `--dump-tree` output.
#[derive(Serialize)]
struct TreeDump {
    subnets: usize,
    arity: usize,
    depth: usize,
    nodes: Vec<DumpNode>,
    peers: Vec<PeerDump>,
}

#[derive(Serialize)]
struct PeerDump {
    seed: u64,
    peer_id: String,
    tree_node: usize,
}

/// The tree and the tree node of every seed's PeerId, as one JSON document.
pub fn dump_tree(cli: &Cli, seeds: &[u64]) -> String {
    let tree = cli.tree();
    let dump = TreeDump {
        subnets: tree.subnets(),
        arity: tree.arity(),
        depth: tree.depth(),
        nodes: tree.dump(),
        peers: seeds
            .iter()
            .map(|&seed| {
                let peer = peer_id_from_seed(seed);
                PeerDump {
                    seed,
                    peer_id: peer.to_string(),
                    tree_node: tree.position(&peer),
                }
            })
            .collect(),
    };
    serde_json::to_string(&dump).expect("serialize tree dump")
}

/// What a node observed, returned by [`run`] for in-process tests. Times are
/// milliseconds since the node started.
#[derive(Debug, Clone, Default)]
pub struct NodeReport {
    /// L1: the proof was produced and offered.
    pub published: bool,
    /// L2: our tree node and its level.
    pub tree_node: Option<usize>,
    pub level: Option<usize>,
    pub is_root: bool,
    /// L2: inputs of our node, and those fully held.
    pub inputs: usize,
    pub inputs_done: usize,
    /// L2: the proof committed to for each input, in completion order.
    pub committed: Vec<ProofId>,
    pub first_input_ms: Option<u64>,
    pub inputs_ms: Option<u64>,
    /// L2: when our node's aggregate was finished.
    pub node_aggregate_ms: Option<u64>,
    /// Root L2: when the global aggregate was finished.
    pub aggregate_ms: Option<u64>,
    /// Announced proofs declined because another proof fills their input.
    pub declined: usize,
    pub haves_sent: usize,
    pub haves_received: usize,
    pub chunk_requests: usize,
    pub chunk_failures: usize,
    pub chunks_received: usize,
    pub duplicate_chunks: usize,
    pub chunks_served: usize,
    /// Chunks served of a proof we were still downloading (cut-through).
    pub chunks_served_partial: usize,
    pub chunks_missing: usize,
    /// Chunk requests refused because the proof's fan-out was full.
    pub chunks_refused: usize,
    /// Most peers any one proof was served to at once (at most `fanout`).
    pub fanout_peak: usize,
    /// Most distinct peers any one proof of ours was sent chunks to.
    pub max_peers_per_proof: usize,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_data: u64,
    pub rx_data: u64,
}

/// A connected peer that said hello.
#[derive(Clone, Copy, Debug)]
struct PeerInfo {
    role: Role,
    /// L2: the tree node its PeerId maps to.
    node: Option<usize>,
}

enum Pending {
    Chunk(ChunkRequest),
    /// A `Have` we sent; its answer lists the proofs the peer will not fetch.
    Have,
    Control,
}

type JobFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

struct Node {
    cli: Cli,
    tree: Tree,
    swarm: Swarm<SimBehaviour>,
    traffic: Arc<Traffic>,
    start: Instant,
    /// L2: our tree node.
    position: Option<usize>,
    fetcher: Option<Fetcher>,
    /// Complete proofs we serve (own proof or aggregate, finished inputs).
    held: HashMap<[u8; 32], ProofAssembly>,
    peers: HashMap<PeerId, PeerInfo>,
    hello_sent: HashSet<PeerId>,
    fanout: Fanout,
    /// Proofs whose holdings or downstream slots changed since the last
    /// announcement round, and when that round is due.
    dirty: HashSet<[u8; 32]>,
    flush_at: Option<Instant>,
    pending: HashMap<OutboundRequestId, Pending>,
    jobs: FuturesUnordered<JobFuture>,
    report: NodeReport,
}

impl Node {
    fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    fn send(&mut self, peer: &PeerId, request: Request, pending: Pending) {
        let id = self.swarm.behaviour_mut().rr.send_request(peer, request);
        self.pending.insert(id, pending);
    }

    fn respond(&mut self, channel: ResponseChannel<Response>, response: Response) {
        if self.swarm.behaviour_mut().rr.send_response(channel, response).is_err() {
            debug!("response dropped: connection closed");
        }
    }

    /// Whether `peer` (hello'd) aggregates a node that takes `id` as input
    /// and has neither declined it nor told us it holds it.
    fn needs(&self, peer: &PeerId, id: &ProofId) -> bool {
        let Some(info) = self.peers.get(peer) else {
            return false;
        };
        info.role == Role::L2
            && info.node.is_some_and(|n| self.tree.needs(n, id.committees))
            && !self.fanout.is_done(&id.hash, peer)
    }

    /// A proof we hold (completely, or in part while fetching it).
    fn holding(&self, hash: &[u8; 32]) -> Option<&ProofAssembly> {
        self.held.get(hash).or_else(|| {
            self.fetcher
                .as_ref()
                .and_then(|f| f.assembly(hash))
                .filter(|a| a.held() > 0)
        })
    }

    /// Queue an announcement round for `hash`.
    fn mark(&mut self, hash: [u8; 32]) {
        self.dirty.insert(hash);
        if self.flush_at.is_none() {
            self.flush_at = Some(Instant::now() + Duration::from_millis(self.cli.have_interval_ms));
        }
    }

    /// Announcement round: fill free downstream slots of every changed proof
    /// and tell each downstream peer about chunks it has not heard of.
    fn flush(&mut self) {
        self.flush_at = None;
        for hash in std::mem::take(&mut self.dirty) {
            let Some(asm) = self.holding(&hash) else {
                continue;
            };
            let (id, bits, held) = (asm.id, asm.bits(), asm.held());
            let mut candidates: Vec<PeerId> = self
                .peers
                .keys()
                .copied()
                .filter(|p| self.needs(p, &id) && !self.fanout.is_active(&hash, p))
                .collect();
            candidates.sort_by_key(|p| rank(p, &hash));
            let added = self.fanout.fill(&hash, candidates);
            if !added.is_empty() {
                proof_event!(
                    &id,
                    "proof_offered",
                    "intermediate_offered",
                    peers = added.len(),
                    downstream = self.fanout.active(&hash),
                    held = held
                );
            }
            for peer in self.fanout.due(&hash, held) {
                self.send_have(peer, id, bits.clone());
            }
        }
    }

    fn send_have(&mut self, peer: PeerId, id: ProofId, chunks: ChunkBits) {
        self.report.haves_sent += 1;
        self.send(&peer, Request::Have { proofs: vec![Holding { id, chunks }] }, Pending::Have);
    }

    // ── L1 ──────────────────────────────────────────────────────────────

    fn publish(&mut self) {
        let proof = make_proof(self.cli.seed, self.cli.proof_len());
        let id = ProofId::for_proof(self.cli.subnet, self.cli.prover, &proof, self.cli.chunk_count);
        self.held.insert(id.hash, ProofAssembly::from_proof(id, &proof));
        self.mark(id.hash);
        self.report.published = true;
        event!(
            "proof_published",
            subnet = id.subnet,
            prover = id.prover,
            hash = id.label(),
            bytes = id.proof_len,
            chunks = id.chunk_count,
            consumer = self.tree.consumer_of_subnet(id.subnet).map_or(-1, |n| n as i64)
        );
    }

    // ── handshake ───────────────────────────────────────────────────────

    fn on_connected(&mut self, peer: PeerId) {
        if self.hello_sent.insert(peer) {
            let subnet = (self.cli.role == Role::L1).then_some(self.cli.subnet);
            self.send(&peer, Request::Hello { role: self.cli.role, subnet }, Pending::Control);
        }
    }

    fn on_disconnected(&mut self, peer: PeerId) {
        self.peers.remove(&peer);
        self.hello_sent.remove(&peer);
        for hash in self.fanout.peer_gone(&peer) {
            self.mark(hash);
        }
        if let Some(fetcher) = &mut self.fetcher {
            fetcher.on_peer_gone(&peer);
        }
        self.pump();
    }

    fn on_hello(&mut self, peer: PeerId, role: Role, subnet: Option<u16>) {
        let node = (role == Role::L2).then(|| self.tree.position(&peer));
        self.peers.insert(peer, PeerInfo { role, node });
        event!(
            "peer_hello",
            peer = peer,
            role = role,
            subnet = subnet.map_or(-1, i64::from),
            node = node.map_or(-1, |n| n as i64)
        );
        // Offer it whatever we hold that its node needs (fan-out permitting).
        let needed: Vec<[u8; 32]> = self
            .held
            .values()
            .chain(self.fetcher.iter().flat_map(|f| f.partial()))
            .filter(|a| self.needs(&peer, &a.id))
            .map(|a| a.id.hash)
            .collect();
        for hash in needed {
            self.mark(hash);
        }
    }

    // ── L2: pulling inputs ──────────────────────────────────────────────

    /// `peer` told us which chunks of which proofs it holds. Returns the
    /// hashes we will not fetch from it.
    fn on_have(&mut self, peer: PeerId, proofs: Vec<Holding>) -> Vec<[u8; 32]> {
        self.report.haves_received += 1;
        let mut unwanted = Vec::new();
        for Holding { id, chunks } in proofs {
            let Some(id) = id.checked().filter(|id| chunks.is_valid_for(id.chunks())) else {
                warn!(%peer, "malformed holding in Have");
                continue;
            };
            // A peer holding a whole proof needs nothing more of it from us.
            if chunks.is_full() && self.fanout.release(&id.hash, peer) {
                self.mark(id.hash);
            }
            let Some(fetcher) = &mut self.fetcher else {
                unwanted.push(id.hash);
                continue;
            };
            let outcome = fetcher.on_have(peer, &id, &chunks);
            match outcome {
                HaveOutcome::Committed => {
                    proof_event!(
                        &id,
                        "proof_committed",
                        "intermediate_committed",
                        from = peer,
                        peer_chunks = chunks.count()
                    );
                }
                HaveOutcome::Declined { first: true } => {
                    self.report.declined += 1;
                    proof_event!(&id, "proof_declined", "intermediate_declined", from = peer);
                }
                _ => {}
            }
            if !outcome.wanted() {
                unwanted.push(id.hash);
            }
        }
        self.pump();
        unwanted
    }

    /// Send every chunk request the fetcher can place now.
    fn pump(&mut self) {
        let Some(fetcher) = &mut self.fetcher else {
            return;
        };
        let requests = fetcher.next_requests();
        self.report.chunk_requests += requests.len();
        for req in requests {
            self.send(
                &req.peer,
                Request::GetChunk {
                    hash: req.hash,
                    index: req.index,
                },
                Pending::Chunk(req),
            );
        }
    }

    fn on_chunk(&mut self, req: ChunkRequest, data: Vec<u8>) {
        let Some(fetcher) = &mut self.fetcher else {
            return;
        };
        match fetcher.on_chunk(&req, &data) {
            ChunkOutcome::Added { id, held } => {
                self.report.chunks_received += 1;
                self.mark(id.hash);
                proof_event!(
                    &id,
                    "chunk_received",
                    "intermediate_chunk_received",
                    from = req.peer,
                    index = req.index,
                    held = held
                );
            }
            ChunkOutcome::Completed { id, proof } => {
                self.report.chunks_received += 1;
                proof_event!(
                    &id,
                    "chunk_received",
                    "intermediate_chunk_received",
                    from = req.peer,
                    index = req.index,
                    held = id.chunks()
                );
                self.input_complete(id, &proof, req.peer);
            }
            ChunkOutcome::Duplicate => self.report.duplicate_chunks += 1,
            ChunkOutcome::Malformed => {
                self.report.chunk_failures += 1;
                warn!(peer = %req.peer, index = req.index, "malformed chunk");
            }
            ChunkOutcome::Invalid { id } => {
                event!("proof_invalid", mask = id.committees, hash = id.label());
            }
            ChunkOutcome::Unexpected => {}
        }
        self.pump();
    }

    /// An input of our node is fully held: serve it, tell our node-mates,
    /// and merge once every input is in.
    fn input_complete(&mut self, id: ProofId, proof: &[u8], from: PeerId) {
        let now = self.elapsed_ms();
        self.held.insert(id.hash, ProofAssembly::from_proof(id, proof));
        self.report.first_input_ms.get_or_insert(now);
        self.report.committed.push(id);
        let fetcher = self.fetcher.as_ref().expect("L2 has a fetcher");
        let (done, all) = (fetcher.done(), fetcher.all_done());
        let sources = fetcher.holders(&id.hash);
        self.report.inputs_done = done;
        // Tell our sources we hold it all, so they free our slot (and those
        // still fetching gain us as a holder).
        for peer in &sources {
            self.send_have(*peer, id, ChunkBits::full(id.chunks()));
        }
        self.mark(id.hash);
        proof_event!(
            &id,
            "proof_complete",
            "intermediate_complete",
            from = from,
            inputs_done = done,
            sources = sources.len()
        );
        if all {
            self.report.inputs_ms = Some(now);
            let node = self.position.expect("L2 has a tree node");
            event!("inputs_complete", node = node, inputs = done);
            self.start_merge();
        }
    }

    fn start_merge(&mut self) {
        let node = self.position.expect("L2 has a tree node");
        let input_subnets: Vec<String> = self
            .tree
            .input_masks(node)
            .into_iter()
            .map(|m| subnet_list(&subnets_of(m)))
            .collect();
        event!(
            "aggregation_started",
            node = node,
            inputs = input_subnets.len(),
            input_subnets = input_subnets.join("/")
        );
        let duration = Duration::from_millis(self.cli.aggregation_ms);
        self.jobs.push(Box::pin(time::sleep(duration)));
    }

    fn on_merge_done(&mut self) {
        let node = self.position.expect("L2 has a tree node");
        let mask = self.tree.node(node).mask;
        let level = self.tree.node(node).level;
        let proof = make_aggregate(self.cli.seed, mask, self.cli.proof_len());
        let id = ProofId::for_aggregate(self.cli.prover, mask, &proof, self.cli.chunk_count);
        self.held.insert(id.hash, ProofAssembly::from_proof(id, &proof));
        self.report.node_aggregate_ms = Some(self.elapsed_ms());
        event!(
            "aggregation_done",
            node = node,
            committees = subnet_list(&subnets_of(mask)),
            hash = id.label()
        );
        event!(
            "node_aggregate_complete",
            node = node,
            level = level,
            committees = subnet_list(&subnets_of(mask)),
            mask = mask,
            hash = id.label()
        );
        if node == self.tree.root() {
            self.report.aggregate_ms = self.report.node_aggregate_ms;
            event!("aggregate_complete", subnets = self.tree.subnets(), node = node);
        } else {
            self.mark(id.hash);
        }
    }

    // ── serving ─────────────────────────────────────────────────────────

    fn on_get_chunk(&mut self, peer: PeerId, channel: ResponseChannel<Response>, hash: [u8; 32], index: u16) {
        let Some(asm) = self.holding(&hash) else {
            self.report.chunks_missing += 1;
            return self.respond(channel, Response::Missing);
        };
        let (complete, held) = (asm.is_complete(), asm.held());
        let chunk = asm.chunk(index as usize).map(<[u8]>::to_vec);
        if !self.fanout.admit(&hash, peer, held) {
            self.report.chunks_refused += 1;
            return self.respond(channel, Response::Busy);
        }
        let response = match chunk {
            Some(data) => {
                self.report.chunks_served += 1;
                if !complete {
                    self.report.chunks_served_partial += 1;
                }
                self.fanout.record_served(&hash, peer);
                Response::Chunk { data }
            }
            None => {
                self.report.chunks_missing += 1;
                Response::Missing
            }
        };
        self.respond(channel, response);
    }

    // ── events ──────────────────────────────────────────────────────────

    fn on_request(&mut self, peer: PeerId, request: Request, channel: ResponseChannel<Response>) {
        match request {
            Request::Hello { role, subnet } => {
                self.respond(channel, Response::Ack);
                self.on_hello(peer, role, subnet);
            }
            Request::Have { proofs } => {
                let unwanted = self.on_have(peer, proofs);
                self.respond(channel, Response::Interest { unwanted });
            }
            Request::GetChunk { hash, index } => self.on_get_chunk(peer, channel, hash, index),
        }
    }

    fn on_response(&mut self, peer: PeerId, request_id: OutboundRequestId, response: Response) {
        match (self.pending.remove(&request_id), response) {
            (Some(Pending::Chunk(req)), Response::Chunk { data }) => self.on_chunk(req, data),
            (Some(Pending::Have), Response::Interest { unwanted }) => {
                for hash in unwanted {
                    if self.fanout.release(&hash, peer) {
                        self.mark(hash);
                    }
                }
            }
            (Some(Pending::Chunk(req)), _) => {
                // `Missing` or `Busy`: ask the other holders instead.
                self.report.chunk_failures += 1;
                if let Some(fetcher) = &mut self.fetcher {
                    fetcher.on_failure(&req, true);
                }
                self.pump();
            }
            (Some(Pending::Have | Pending::Control) | None, _) => {}
        }
    }

    fn on_outbound_failure(&mut self, peer: PeerId, request_id: OutboundRequestId, error: String) {
        if let Some(Pending::Chunk(req)) = self.pending.remove(&request_id) {
            self.report.chunk_failures += 1;
            debug!(%peer, %error, index = req.index, "chunk request failed");
            if let Some(fetcher) = &mut self.fetcher {
                fetcher.on_failure(&req, false);
            }
            self.pump();
        }
    }

    fn handle_event(&mut self, event: SwarmEvent<SimBehaviourEvent>) {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => self.on_connected(peer_id),
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established: 0,
                ..
            } => self.on_disconnected(peer_id),
            SwarmEvent::Behaviour(SimBehaviourEvent::Rr(event)) => match event {
                request_response::Event::Message { peer, message, .. } => match message {
                    request_response::Message::Request { request, channel, .. } => {
                        self.on_request(peer, request, channel)
                    }
                    request_response::Message::Response { request_id, response } => {
                        self.on_response(peer, request_id, response)
                    }
                },
                request_response::Event::OutboundFailure {
                    peer,
                    request_id,
                    error,
                    ..
                } => self.on_outbound_failure(peer, request_id, error.to_string()),
                request_response::Event::InboundFailure { peer, error, .. } => {
                    debug!(%peer, %error, "inbound request failed");
                }
                request_response::Event::ResponseSent { .. } => {}
            },
            _ => {}
        }
    }

    fn finish(&mut self) {
        let (tx, rx) = (self.traffic.tx(), self.traffic.rx());
        let ordering = std::sync::atomic::Ordering::Relaxed;
        self.report.tx_bytes = tx;
        self.report.rx_bytes = rx;
        self.report.tx_data = self.traffic.tx_data.load(ordering);
        self.report.rx_data = self.traffic.rx_data.load(ordering);
        self.report.fanout_peak = self.fanout.peak();
        for (hash, peers, chunks) in self.fanout.served() {
            self.report.max_peers_per_proof = self.report.max_peers_per_proof.max(peers);
            let mask = self.holding(&hash).map_or(0, |a| a.id.committees);
            event!(
                "proof_served",
                hash = crate::events::hex_bytes(&hash[..8]),
                mask = mask,
                peers = peers,
                chunks = chunks
            );
        }
        event!(
            "bytes",
            tx = tx,
            rx = rx,
            tx_data = self.report.tx_data,
            rx_data = self.report.rx_data
        );
        event!(
            "run_end",
            role = self.cli.role,
            node = self.position.map_or(-1, |n| n as i64),
            level = self.report.level.map_or(-1, |l| l as i64),
            inputs = self.report.inputs,
            inputs_done = self.report.inputs_done,
            node_aggregated = self.report.node_aggregate_ms.is_some(),
            aggregated = self.report.aggregate_ms.is_some(),
            peers = self.peers.len(),
            declined = self.report.declined,
            haves_sent = self.report.haves_sent,
            haves_received = self.report.haves_received,
            chunk_requests = self.report.chunk_requests,
            chunk_failures = self.report.chunk_failures,
            chunks_received = self.report.chunks_received,
            duplicate_chunks = self.report.duplicate_chunks,
            chunks_served = self.report.chunks_served,
            chunks_served_partial = self.report.chunks_served_partial,
            chunks_missing = self.report.chunks_missing,
            chunks_refused = self.report.chunks_refused,
            fanout = self.fanout.limit(),
            fanout_peak = self.report.fanout_peak,
            max_peers_per_proof = self.report.max_peers_per_proof
        );
    }
}

/// Run one node until `warmup_secs + observe_secs` have passed.
pub async fn run(cli: Cli) -> NodeReport {
    info!(
        role = %cli.role,
        subnet = cli.subnet,
        prover = cli.prover,
        seed = cli.seed,
        peers = cli.peers.len(),
        arity = cli.aggregation_arity,
        fanout = cli.fanout,
        "proof-broadcast-tree starting"
    );
    let tuning = RrTuning {
        request_timeout: Duration::from_millis(cli.request_timeout_ms),
        ..RrTuning::default()
    };
    let (mut swarm, local_peer_id, traffic) = build_swarm(cli.seed, &cli.listen_ip, cli.listen_port, tuning);
    info!(%local_peer_id, "swarm built");
    dial_peers(&mut swarm, &cli.peers);

    let tree = cli.tree();
    let mut report = NodeReport::default();
    let (position, fetcher) = if cli.role == Role::L2 {
        let node = tree.position(&local_peer_id);
        let masks = tree.input_masks(node);
        let tn = tree.node(node);
        report.tree_node = Some(node);
        report.level = Some(tn.level);
        report.is_root = node == tree.root();
        report.inputs = masks.len();
        event!(
            "tree_assigned",
            node = node,
            level = tn.level,
            depth = tree.depth(),
            committees = subnet_list(&subnets_of(tn.mask)),
            inputs = masks
                .iter()
                .map(|&m| subnet_list(&subnets_of(m)))
                .collect::<Vec<_>>()
                .join("/"),
            parent = tn.parent.map_or(-1, |p| p as i64),
            root = report.is_root
        );
        (Some(node), Some(Fetcher::new(&masks, cli.max_inflight_per_peer)))
    } else {
        (None, None)
    };

    let start = Instant::now();
    let epoch = start + Duration::from_secs(cli.warmup_secs);
    let publish_at = epoch + Duration::from_millis(cli.publish_delay_ms);
    let deadline = epoch + Duration::from_secs(cli.observe_secs);
    let is_l1 = cli.role == Role::L1;
    let fanout = cli.fanout;

    let mut node = Node {
        cli,
        tree,
        swarm,
        traffic,
        start,
        position,
        fetcher,
        held: HashMap::new(),
        peers: HashMap::new(),
        hello_sent: HashSet::new(),
        fanout: Fanout::new(fanout),
        dirty: HashSet::new(),
        flush_at: None,
        pending: HashMap::new(),
        jobs: FuturesUnordered::new(),
        report,
    };

    let mut tick = time::interval(Duration::from_millis(100));
    let mut warmup_logged = false;
    let mut publish_done = false;

    loop {
        tokio::select! {
            event = node.swarm.select_next_some() => node.handle_event(event),
            Some(()) = node.jobs.next(), if !node.jobs.is_empty() => node.on_merge_done(),
            _ = time::sleep_until(node.flush_at.unwrap_or(deadline)), if node.flush_at.is_some() => {
                node.flush();
            }
            _ = time::sleep_until(epoch), if !warmup_logged => {
                warmup_logged = true;
                let connected = node.swarm.connected_peers().count();
                let l2_peers = node.peers.values().filter(|p| p.role == Role::L2).count();
                event!(
                    "warmup_complete",
                    connected = connected,
                    hello = node.peers.len(),
                    l2_peers = l2_peers
                );
            }
            _ = time::sleep_until(publish_at), if is_l1 && !publish_done => {
                publish_done = true;
                node.publish();
            }
            _ = tick.tick() => {
                if Instant::now() >= deadline {
                    node.finish();
                    break;
                }
            }
        }
    }
    node.report
}
