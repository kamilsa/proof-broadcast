//! One simulated prover: CLI, swarm event handling and the run loop.
//!
//! Timeline (all processes start together under Shadow, so these instants
//! line up across hosts): connect and form meshes during `warmup_secs`; at
//! `epoch = start + warmup_secs` each L1 prover waits its own
//! `publish_delay_ms` and publishes; every node exits at
//! `epoch + observe_secs`.

use std::future::Future;
use std::pin::Pin;

use clap::{Parser, ValueEnum};
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use libp2p::gossipsub::{self, IdentTopic, MessageAcceptance};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, Swarm};
use tokio::time::{self, Duration, Instant};
use tracing::{info, warn};

use crate::aggregation::{Aggregator, Step, Subnets, subnet_list};
use crate::chunked_mode::{
    ChunkMessage, ChunkedProof, ChunkedState, HeaderMessage, chunk_group, chunk_messages,
};
use crate::event;
use crate::gossip_mode::ProofMessage;
use crate::network::{
    GossipTuning, MeshTuning, SimBehaviour, SimBehaviourEvent, build_swarm, dial_peers,
    gossip_byte_totals, mesh_peer_count, proofs_chunked_pull_topic, proofs_chunked_topic,
    proofs_headers_topic, proofs_topic, subscribe_partial, topic_peer_count,
};
use crate::partial_mode::{
    CellBitmap, ChunkBody, OutgoingProof, PartialState, PartsMetadata, ProofAssembly,
};
use crate::proof::{
    Committees, CoverageLedger, FetchPolicy, MAX_CHUNKS, MAX_SUBNETS, ProofId, Verdict,
    make_aggregate, make_proof, mask_of, split, subnets_of,
};

/// Propagation protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// Whole proofs as gossipsub messages on `/proofs/1`.
    Gossipsub,
    /// Chunked proofs via gossipsub 1.3 partial messages.
    Partial,
    /// Every proof chunk as its own gossipsub message on `/proofs_chunked/1`.
    #[value(name = "gossipsub-chunked")]
    GossipsubChunked,
    /// Headers pushed on `/proofs_headers/1`; chunks on the pull-gated
    /// `/proofs_chunked_pull/1`, sent only to peers that asked (WANT).
    #[value(name = "gossipsub-chunked-pull")]
    GossipsubChunkedPull,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Gossipsub => "gossipsub",
            Self::Partial => "partial",
            Self::GossipsubChunked => "gossipsub-chunked",
            Self::GossipsubChunkedPull => "gossipsub-chunked-pull",
        })
    }
}

/// Prover role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Role {
    /// Subnet prover: publishes one proof, never subscribes or relays.
    L1,
    /// Aggregating prover: collects one proof per subnet and aggregates.
    L2,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::L1 => "l1",
            Self::L2 => "l2",
        })
    }
}

#[derive(Parser, Debug, Clone)]
#[command(name = "proof-broadcast", about = "leanVM proof-propagation simulator node")]
pub struct Cli {
    #[arg(long, value_enum, default_value_t = Mode::Gossipsub)]
    pub mode: Mode,

    #[arg(long, value_enum, default_value_t = Role::L2)]
    pub role: Role,

    /// Subnet this L1 prover proves.
    #[arg(long, default_value_t = 0)]
    pub subnet: u16,

    /// L1: index within its subnet. L2: index among L2 provers (labels the
    /// intermediate aggregates it publishes).
    #[arg(long, default_value_t = 0)]
    pub prover: u16,

    /// Number of subnets an L2 must collect.
    #[arg(long, default_value_t = 16)]
    pub subnets: usize,

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

    /// Peer multiaddrs to dial (QUIC).
    #[arg(long = "peer")]
    pub peers: Vec<Multiaddr>,

    #[arg(long, default_value_t = 300)]
    pub proof_size_kib: usize,

    /// Chunks per proof in `partial` and `gossipsub-chunked` modes.
    #[arg(long, default_value_t = 64)]
    pub chunk_count: usize,

    /// `gossipsub-chunked`: after each new chunk, also send IDONTWANT for it
    /// to every mesh peer (as ec-sim). Gossipsub already sends IDONTWANT on
    /// receipt for messages above 1000 bytes.
    #[arg(long, default_value_t = false)]
    pub chunked_send_idontwant: bool,

    /// L1 publish delay after the warmup epoch.
    #[arg(long, default_value_t = 0)]
    pub publish_delay_ms: u64,

    /// Longest an L1 waits past its publish time for fanout peers.
    #[arg(long, default_value_t = 10)]
    pub publish_grace_secs: u64,

    /// Duration of one 2→1 recursion (leanVM: 0.287 s on an M4 Max).
    #[arg(long, default_value_t = 290)]
    pub aggregation_ms: u64,

    /// Concurrent 2→1 recursions an L2 can run.
    #[arg(long, default_value_t = 1)]
    pub aggregation_workers: usize,

    /// L2: publish intermediate aggregates (never the final one) on the
    /// proofs topic, so other L2s can fetch them instead of recursing.
    #[arg(long, default_value_t = false)]
    pub intermediate_proofs: bool,

    /// Smallest aggregate, in committees, an L2 publishes.
    #[arg(long, default_value_t = 2)]
    pub intermediate_min_committees: usize,

    /// Which advertised proofs an L2 fetches.
    #[arg(long, value_enum, default_value_t = FetchPolicy::Disjoint)]
    pub intermediate_fetch: FetchPolicy,

    #[arg(long, default_value_t = 15)]
    pub warmup_secs: u64,

    #[arg(long, default_value_t = 20)]
    pub observe_secs: u64,

    #[arg(long, default_value_t = false)]
    pub flood_publish: bool,

    #[arg(long, default_value_t = 0)]
    pub gossip_lazy: usize,

    #[arg(long, default_value_t = 0.0)]
    pub gossip_factor: f64,

    #[arg(long, default_value_t = 8)]
    pub proofs_mesh_n: usize,

    #[arg(long, default_value_t = 6)]
    pub proofs_mesh_n_low: usize,

    #[arg(long, default_value_t = 12)]
    pub proofs_mesh_n_high: usize,

    #[arg(long, default_value_t = 3)]
    pub proofs_mesh_outbound_min: usize,
}

impl Cli {
    pub fn gossip_tuning(&self) -> GossipTuning {
        GossipTuning {
            flood_publish: self.flood_publish,
            gossip_lazy: self.gossip_lazy,
            gossip_factor: self.gossip_factor,
            mesh: MeshTuning {
                mesh_n: self.proofs_mesh_n,
                mesh_n_low: self.proofs_mesh_n_low,
                mesh_n_high: self.proofs_mesh_n_high,
                mesh_outbound_min: self.proofs_mesh_outbound_min,
            },
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.subnets == 0 || self.subnets > MAX_SUBNETS {
            return Err(format!(
                "subnets must be in 1..={MAX_SUBNETS}, got {}",
                self.subnets
            ));
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
        if self.aggregation_workers == 0 {
            return Err("aggregation workers must be positive".to_string());
        }
        if self.intermediate_min_committees < 2 {
            return Err(format!(
                "intermediate min committees must be at least 2, got {}",
                self.intermediate_min_committees
            ));
        }
        self.gossip_tuning().mesh.validate()
    }

    fn proof_len(&self) -> usize {
        self.proof_size_kib.saturating_mul(1024)
    }

    /// Whether a finished merge covering `covered` committees is published.
    fn publishes_intermediate(&self, covered: usize) -> bool {
        self.intermediate_proofs
            && covered >= self.intermediate_min_committees
            && covered < self.subnets
    }
}

/// What a node observed, returned by [`run`] for in-process tests. Times are
/// milliseconds since the node started.
#[derive(Debug, Clone, Default)]
pub struct NodeReport {
    pub published: bool,
    /// Committees covered by fully received proofs.
    pub subnets_done: usize,
    pub first_proof_ms: Option<u64>,
    pub all_subnets_ms: Option<u64>,
    pub aggregate_ms: Option<u64>,
    /// First proof claimed per subnet (L2).
    pub committed: Vec<Option<[u8; 32]>>,
    /// Gossipsub mode: proofs received whose committees were already claimed.
    pub redundant_proofs: usize,
    /// Partial mode: chunks received that were already held.
    pub duplicate_chunks: usize,
    /// Subnet proofs declined because their subnet was already claimed.
    pub declined: usize,
    /// Own intermediate aggregates published.
    pub intermediates_published: usize,
    /// Other L2s' aggregates fully received.
    pub intermediates_fetched: usize,
    /// Other L2s' aggregates declined (overlapping what we hold).
    pub intermediates_declined: usize,
    /// 2→1 recursions started.
    pub merges_run: usize,
    /// Recursions whose result was discarded (subsumed while running).
    pub merges_discarded: usize,
    /// Held items dropped for a subsuming aggregate.
    pub items_dropped: usize,
    /// `gossipsub-chunked`: chunks received, and those of proofs not relayed.
    pub chunks_received: usize,
    pub chunks_ignored: usize,
    /// `gossipsub-chunked`: fully received proofs that were not used (their
    /// committees were already covered).
    pub proofs_unused: usize,
    /// `gossipsub-chunked`: proofs used although they were not relayed.
    pub used_unrelayed: usize,
    /// `gossipsub-chunked`: explicit IDONTWANT messages sent (peer count).
    pub idontwant_sent: usize,
    /// `gossipsub-chunked-pull`: WANTs sent (one per chosen proof).
    pub wants_sent: usize,
    /// `gossipsub-chunked-pull`: chunks of proofs we never asked for.
    pub chunks_unwanted: usize,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

type JobFuture = Pin<Box<dyn Future<Output = Subnets> + Send>>;

struct Node {
    cli: Cli,
    swarm: Swarm<SimBehaviour>,
    /// Where proofs (or, in `gossipsub-chunked-pull`, their headers) go.
    topic: IdentTopic,
    /// `gossipsub-chunked-pull`: the pull-gated chunk topic.
    data_topic: Option<IdentTopic>,
    start: Instant,
    ledger: CoverageLedger,
    aggregator: Aggregator,
    jobs: FuturesUnordered<JobFuture>,
    partial: PartialState,
    chunked: ChunkedState,
    report: NodeReport,
}

impl Node {
    fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    fn l1_ready(&self) -> bool {
        let connected = self.swarm.connected_peers().count();
        let subscribed = topic_peer_count(&self.swarm, &self.topic);
        subscribed >= self.cli.proofs_mesh_n.min(connected).max(1)
    }

    /// Publish a complete proof we produced (an L1 proof, or an L2's
    /// intermediate aggregate) in the configured mode.
    fn publish_proof(&mut self, id: ProofId, proof: Vec<u8>) -> Result<(), String> {
        match self.cli.mode {
            Mode::Gossipsub => self
                .swarm
                .behaviour_mut()
                .gossipsub
                .publish(self.topic.clone(), ProofMessage::new(&id, proof).encode())
                .map(|_| ())
                .map_err(|e| e.to_string()),
            Mode::Partial => {
                let source = ProofAssembly::from_chunks(id, split(&proof, id.chunks()));
                let outgoing =
                    OutgoingProof::new(id, source.store(), CellBitmap::with_len(id.chunks()));
                self.partial.assemblies.insert(id.hash, source);
                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish_partial(self.topic.hash(), outgoing)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }
            Mode::GossipsubChunked => {
                let gossipsub = &mut self.swarm.behaviour_mut().gossipsub;
                let mut failed = None;
                for chunk in chunk_messages(&id, &proof) {
                    if let Err(err) = gossipsub.publish(self.topic.clone(), chunk.encode()) {
                        failed.get_or_insert(err.to_string());
                    }
                }
                failed.map_or(Ok(()), Err)
            }
            Mode::GossipsubChunkedPull => {
                let data_topic = self.data_topic.clone().expect("pull mode has a data topic");
                let gossipsub = &mut self.swarm.behaviour_mut().gossipsub;
                gossipsub
                    .publish(self.topic.clone(), HeaderMessage::new(&id).encode())
                    .map_err(|e| e.to_string())?;
                // Held by gossipsub until peers ask for this proof.
                for chunk in chunk_messages(&id, &proof) {
                    gossipsub
                        .publish(data_topic.clone(), chunk.encode())
                        .map_err(|e| e.to_string())?;
                }
                Ok(())
            }
        }
    }

    // ── L1 ──────────────────────────────────────────────────────────────

    fn publish(&mut self, late_ms: u64) {
        let proof = make_proof(self.cli.seed, self.cli.proof_len());
        let id = ProofId::for_proof(self.cli.subnet, self.cli.prover, &proof, self.cli.chunk_count);
        let fanout = topic_peer_count(&self.swarm, &self.topic);
        match self.publish_proof(id, proof) {
            Ok(()) => {
                self.report.published = true;
                event!(
                    "proof_published",
                    subnet = id.subnet,
                    prover = id.prover,
                    hash = id.label(),
                    bytes = id.proof_len,
                    chunks = id.chunk_count,
                    topic_peers = fanout,
                    late_ms = late_ms
                );
            }
            Err(err) => {
                warn!(%err, "proof publish failed");
                event!("publish_failed", subnet = id.subnet, prover = id.prover);
            }
        }
    }

    // ── L2: shared ──────────────────────────────────────────────────────

    fn verdict(&self, id: &ProofId) -> Verdict {
        self.ledger.verdict(id, &self.aggregator.units())
    }

    /// Claim `id` for download; a subsuming aggregate reserves its committees.
    fn claim(&mut self, id: &ProofId, verdict: Verdict) {
        self.ledger.commit(id);
        if verdict == Verdict::Subsume {
            self.aggregator.reserve(id.committees);
        }
        self.report.committed = self.committed();
    }

    fn committed(&self) -> Vec<Option<[u8; 32]>> {
        (0..self.ledger.subnets())
            .map(|s| self.ledger.committed(s))
            .collect()
    }

    /// Count a declined proof; true the first time it is declined.
    fn decline(&mut self, id: &ProofId) -> bool {
        if !self.ledger.decline(id) {
            return false;
        }
        if id.is_aggregate() {
            self.report.intermediates_declined += 1;
        } else {
            self.report.declined += 1;
        }
        true
    }

    /// A claimed proof (subnet proof or aggregate) is fully held.
    fn proof_complete(&mut self, id: &ProofId, from: PeerId) {
        let Some(new) = self.ledger.complete(id) else {
            return;
        };
        self.use_proof(id, from, new, true);
    }

    /// `id` is fully held and goes into the aggregation pool. `new` are the
    /// committees it newly covers; `relayed` whether we also forward it.
    fn use_proof(&mut self, id: &ProofId, from: PeerId, new: Committees, relayed: bool) {
        let now = self.elapsed_ms();
        self.report.first_proof_ms.get_or_insert(now);
        self.report.subnets_done = self.ledger.subnets_done();
        if id.is_aggregate() {
            self.report.intermediates_fetched += 1;
            event!(
                "intermediate_complete",
                committees = subnet_list(&id.subnets()),
                mask = id.committees,
                covered = id.covered(),
                prover = id.prover,
                hash = id.label(),
                from = from,
                new = subnet_list(&subnets_of(new)),
                subnets_done = self.report.subnets_done,
                relayed = relayed
            );
        } else {
            event!(
                "proof_complete",
                subnet = id.subnet,
                prover = id.prover,
                hash = id.label(),
                from = from,
                subnets_done = self.report.subnets_done,
                relayed = relayed
            );
        }
        if self.ledger.all_done() && self.report.all_subnets_ms.is_none() {
            self.report.all_subnets_ms = Some(now);
            event!("all_subnets_complete", subnets = self.ledger.subnets());
        }
        let step = self.aggregator.add_item(id.subnets());
        self.after_aggregation_step(step);
    }

    fn after_aggregation_step(&mut self, step: Step) {
        for item in &step.dropped {
            self.report.items_dropped += 1;
            event!(
                "item_dropped",
                subnets = subnet_list(item),
                covered = item.len()
            );
        }
        if self.aggregator.is_complete() && self.report.aggregate_ms.is_none() {
            self.report.aggregate_ms = Some(self.elapsed_ms());
            event!("aggregate_complete", subnets = self.ledger.subnets());
        }
        let duration = Duration::from_millis(self.cli.aggregation_ms);
        for job in step.jobs {
            self.report.merges_run += 1;
            event!(
                "aggregation_started",
                left = job.left.len(),
                right = job.right.len(),
                covered = job.covered(),
                left_subnets = subnet_list(&job.left),
                right_subnets = subnet_list(&job.right)
            );
            let merged = job.merged();
            self.jobs.push(Box::pin(async move {
                time::sleep(duration).await;
                merged
            }));
        }
    }

    fn on_job_done(&mut self, item: Subnets) {
        let step = self.aggregator.job_done(item.clone());
        event!(
            "aggregation_done",
            covered = item.len(),
            subnets = subnet_list(&item),
            kept = step.kept
        );
        if !step.kept {
            self.report.merges_discarded += 1;
        } else if self.cli.publishes_intermediate(item.len()) {
            self.publish_intermediate(&item);
        }
        self.after_aggregation_step(step);
    }

    /// Advertise a finished merge to the other L2 provers.
    fn publish_intermediate(&mut self, item: &[u16]) {
        let mask = mask_of(item);
        let proof = make_aggregate(self.cli.seed, mask, self.cli.proof_len());
        let id = ProofId::for_aggregate(self.cli.prover, mask, &proof, self.cli.chunk_count);
        self.ledger.own(&id);
        match self.publish_proof(id, proof) {
            Ok(()) => {
                self.report.intermediates_published += 1;
                event!(
                    "intermediate_published",
                    committees = subnet_list(item),
                    mask = mask,
                    covered = item.len(),
                    prover = id.prover,
                    hash = id.label(),
                    bytes = id.proof_len,
                    chunks = id.chunk_count
                );
            }
            Err(err) => {
                warn!(%err, "intermediate publish failed");
                event!(
                    "intermediate_publish_failed",
                    committees = subnet_list(item),
                    mask = mask
                );
            }
        }
    }

    // ── L2: gossipsub ───────────────────────────────────────────────────

    fn on_message(&mut self, source: PeerId, message_id: gossipsub::MessageId, data: &[u8]) {
        let validate = |node: &mut Self, acceptance| {
            node.swarm
                .behaviour_mut()
                .gossipsub
                .report_message_validation_result(&message_id, &source, acceptance);
        };
        let Some(id) = ProofMessage::decode(data)
            .ok()
            .and_then(|msg| msg.id(self.cli.chunk_count))
        else {
            validate(self, MessageAcceptance::Reject);
            return;
        };
        let verdict = self.verdict(&id);
        let redundant = match verdict {
            Verdict::Free | Verdict::Subsume => {
                self.claim(&id, verdict);
                validate(self, MessageAcceptance::Accept);
                false
            }
            // Same bytes are deduplicated by message id; nothing to do.
            Verdict::Mine => {
                validate(self, MessageAcceptance::Ignore);
                return;
            }
            Verdict::Taken => {
                validate(self, MessageAcceptance::Ignore);
                self.report.redundant_proofs += 1;
                self.decline(&id);
                true
            }
        };
        if id.is_aggregate() {
            event!(
                "intermediate_received",
                committees = subnet_list(&id.subnets()),
                mask = id.committees,
                covered = id.covered(),
                prover = id.prover,
                hash = id.label(),
                from = source,
                bytes = data.len(),
                redundant = redundant,
                subsume = verdict == Verdict::Subsume
            );
        } else {
            event!(
                "proof_received",
                subnet = id.subnet,
                prover = id.prover,
                hash = id.label(),
                from = source,
                bytes = data.len(),
                redundant = redundant
            );
        }
        if !redundant {
            self.proof_complete(&id, source);
        }
    }

    // ── L2: gossipsub-chunked ───────────────────────────────────────────

    fn on_chunk(&mut self, source: PeerId, message_id: gossipsub::MessageId, data: &[u8]) {
        let validate = |node: &mut Self, acceptance| {
            node.swarm
                .behaviour_mut()
                .gossipsub
                .report_message_validation_result(&message_id, &source, acceptance);
        };
        let Some((chunk, id)) = ChunkMessage::decode(data)
            .ok()
            .and_then(|chunk| chunk.id().map(|id| (chunk, id)))
        else {
            validate(self, MessageAcceptance::Reject);
            return;
        };
        // The first chunk of a proof decides whether it is relayed: only if
        // no other proof covering its committees was seen before.
        let relay = match self.chunked.proofs.get(&id.hash) {
            Some(proof) => proof.relay,
            None => {
                let relay = self.first_chunk(&id, source);
                self.chunked.proofs.insert(
                    id.hash,
                    ChunkedProof {
                        assembly: ProofAssembly::new(id),
                        relay,
                    },
                );
                relay
            }
        };
        validate(
            self,
            if relay { MessageAcceptance::Accept } else { MessageAcceptance::Ignore },
        );
        let proof = self.chunked.proofs.get_mut(&id.hash).expect("inserted above");
        let out = proof.assembly.merge_one(chunk.index as usize, &chunk.data);
        if out.added == 0 {
            return;
        }
        self.report.chunks_received += 1;
        if !relay {
            self.report.chunks_ignored += 1;
        }
        if self.cli.chunked_send_idontwant {
            self.report.idontwant_sent += self
                .swarm
                .behaviour_mut()
                .gossipsub
                .send_idontwant_to_mesh(self.topic.hash(), [message_id.clone()]);
        }
        if id.is_aggregate() {
            event!(
                "intermediate_chunk_received",
                committees = subnet_list(&id.subnets()),
                mask = id.committees,
                prover = id.prover,
                hash = id.label(),
                from = source,
                index = chunk.index,
                added = out.added,
                dup = out.duplicate,
                held = out.held,
                relayed = relay
            );
        } else {
            event!(
                "chunk_received",
                subnet = id.subnet,
                prover = id.prover,
                hash = id.label(),
                from = source,
                index = chunk.index,
                added = out.added,
                dup = out.duplicate,
                held = out.held,
                relayed = relay
            );
        }
        if out.invalid {
            event!("proof_invalid", subnet = id.subnet, mask = id.committees, hash = id.label());
        }
        if out.completed.is_some() {
            self.chunked_proof_complete(&id, source, relay);
        }
    }

    /// Relay decision for a proof seen for the first time.
    fn first_chunk(&mut self, id: &ProofId, from: PeerId) -> bool {
        let verdict = self.verdict(id);
        match verdict {
            Verdict::Free | Verdict::Subsume => {
                self.ledger.commit(id);
                self.report.committed = self.committed();
                if id.is_aggregate() {
                    event!(
                        "intermediate_committed",
                        committees = subnet_list(&id.subnets()),
                        mask = id.committees,
                        covered = id.covered(),
                        prover = id.prover,
                        hash = id.label(),
                        from = from,
                        peer_chunks = 1,
                        subsume = verdict == Verdict::Subsume
                    );
                } else {
                    event!(
                        "proof_committed",
                        subnet = id.subnet,
                        prover = id.prover,
                        hash = id.label(),
                        from = from,
                        peer_chunks = 1
                    );
                }
                true
            }
            Verdict::Mine => false,
            Verdict::Taken => {
                if self.decline(id) {
                    if id.is_aggregate() {
                        event!(
                            "intermediate_declined",
                            committees = subnet_list(&id.subnets()),
                            mask = id.committees,
                            covered = id.covered(),
                            prover = id.prover,
                            hash = id.label(),
                            from = from
                        );
                    } else {
                        event!(
                            "proof_declined",
                            subnet = id.subnet,
                            prover = id.prover,
                            hash = id.label(),
                            from = from
                        );
                    }
                }
                false
            }
        }
    }

    /// A proof is fully received (relayed or not). The first complete proof
    /// covering committees we still need is used; the rest are counted.
    fn chunked_proof_complete(&mut self, id: &ProofId, from: PeerId, relayed: bool) {
        let subsume = self.cli.intermediate_fetch == FetchPolicy::Subsume;
        let fit = self.aggregator.fits(id.committees, subsume);
        let new = fit.and_then(|_| self.ledger.adopt(id));
        let Some(new) = new else {
            self.report.proofs_unused += 1;
            if id.is_aggregate() {
                event!(
                    "intermediate_unused",
                    committees = subnet_list(&id.subnets()),
                    mask = id.committees,
                    prover = id.prover,
                    hash = id.label(),
                    from = from,
                    relayed = relayed
                );
            } else {
                event!(
                    "proof_unused",
                    subnet = id.subnet,
                    prover = id.prover,
                    hash = id.label(),
                    from = from,
                    relayed = relayed
                );
            }
            return;
        };
        if !relayed {
            self.report.used_unrelayed += 1;
        }
        if fit == Some(true) {
            // Drop the held items this proof contains when it joins the pool.
            self.aggregator.reserve(id.committees);
        }
        self.use_proof(id, from, new, relayed);
    }

    // ── L2: gossipsub-chunked-pull ──────────────────────────────────────

    /// A proof header: choose it (forward the header, ask its sender for the
    /// chunks) only if no other proof covering its committees was seen.
    /// Proofs we do not choose cost us their header only.
    fn on_header(&mut self, source: PeerId, message_id: gossipsub::MessageId, data: &[u8]) {
        let validate = |node: &mut Self, acceptance| {
            node.swarm
                .behaviour_mut()
                .gossipsub
                .report_message_validation_result(&message_id, &source, acceptance);
        };
        let Some(id) = HeaderMessage::decode(data).ok().and_then(|h| h.id()) else {
            validate(self, MessageAcceptance::Reject);
            return;
        };
        let verdict = self.verdict(&id);
        match verdict {
            Verdict::Free | Verdict::Subsume => {
                self.claim(&id, verdict);
                self.chunked.proofs.insert(
                    id.hash,
                    ChunkedProof {
                        assembly: ProofAssembly::new(id),
                        relay: true,
                    },
                );
                validate(self, MessageAcceptance::Accept);
                let data_topic = self.data_topic.clone().expect("pull mode has a data topic");
                if self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .want_group(data_topic, vec![id.group_id()], source)
                {
                    self.report.wants_sent += 1;
                }
                if id.is_aggregate() {
                    event!(
                        "intermediate_committed",
                        committees = subnet_list(&id.subnets()),
                        mask = id.committees,
                        covered = id.covered(),
                        prover = id.prover,
                        hash = id.label(),
                        from = source,
                        peer_chunks = 0,
                        subsume = verdict == Verdict::Subsume
                    );
                } else {
                    event!(
                        "proof_committed",
                        subnet = id.subnet,
                        prover = id.prover,
                        hash = id.label(),
                        from = source,
                        peer_chunks = 0
                    );
                }
            }
            Verdict::Mine => validate(self, MessageAcceptance::Ignore),
            Verdict::Taken => {
                validate(self, MessageAcceptance::Ignore);
                if self.decline(&id) {
                    if id.is_aggregate() {
                        event!(
                            "intermediate_declined",
                            committees = subnet_list(&id.subnets()),
                            mask = id.committees,
                            covered = id.covered(),
                            prover = id.prover,
                            hash = id.label(),
                            from = source
                        );
                    } else {
                        event!(
                            "proof_declined",
                            subnet = id.subnet,
                            prover = id.prover,
                            hash = id.label(),
                            from = source
                        );
                    }
                }
            }
        }
    }

    /// A chunk on the pull-gated topic: only proofs we asked for are sent to
    /// us. Accepting forwards it to the peers that asked us for that proof.
    fn on_pull_chunk(&mut self, source: PeerId, message_id: gossipsub::MessageId, data: &[u8]) {
        let validate = |node: &mut Self, acceptance| {
            node.swarm
                .behaviour_mut()
                .gossipsub
                .report_message_validation_result(&message_id, &source, acceptance);
        };
        let Some((chunk, id)) = ChunkMessage::decode(data)
            .ok()
            .and_then(|chunk| chunk.id().map(|id| (chunk, id)))
        else {
            validate(self, MessageAcceptance::Reject);
            return;
        };
        let Some(proof) = self.chunked.proofs.get_mut(&id.hash) else {
            self.report.chunks_unwanted += 1;
            validate(self, MessageAcceptance::Ignore);
            return;
        };
        let out = proof.assembly.merge_one(chunk.index as usize, &chunk.data);
        validate(self, MessageAcceptance::Accept);
        if out.added == 0 {
            return;
        }
        self.report.chunks_received += 1;
        if id.is_aggregate() {
            event!(
                "intermediate_chunk_received",
                committees = subnet_list(&id.subnets()),
                mask = id.committees,
                prover = id.prover,
                hash = id.label(),
                from = source,
                index = chunk.index,
                added = out.added,
                dup = out.duplicate,
                held = out.held,
                relayed = true
            );
        } else {
            event!(
                "chunk_received",
                subnet = id.subnet,
                prover = id.prover,
                hash = id.label(),
                from = source,
                index = chunk.index,
                added = out.added,
                dup = out.duplicate,
                held = out.held,
                relayed = true
            );
        }
        if out.invalid {
            event!("proof_invalid", subnet = id.subnet, mask = id.committees, hash = id.label());
        }
        if out.completed.is_some() {
            self.proof_complete(&id, source);
        }
    }

    // ── L2: partial messages ────────────────────────────────────────────

    fn on_partial(
        &mut self,
        peer: PeerId,
        group_id: &[u8],
        message: Option<Vec<u8>>,
        metadata: Option<Vec<u8>>,
    ) {
        let Some(id) = ProofId::from_group_id(group_id) else {
            return;
        };
        let body = match message.as_deref().map(|b| ChunkBody::decode_for(b, &id)) {
            None => None,
            Some(Ok(body)) => Some(body),
            Some(Err(_)) => {
                let topic = self.topic.hash();
                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .report_invalid_partial(peer, &topic);
                return;
            }
        };
        let verdict = self.verdict(&id);
        match verdict {
            Verdict::Mine => {
                // Republish when we gained chunks, or when a peer's metadata
                // may be the first it heard of our request.
                let gained = body.is_none_or(|body| self.merge_chunks(&id, peer, &body));
                if gained {
                    self.republish(&id);
                }
            }
            Verdict::Taken => {
                if self.decline(&id) {
                    if id.is_aggregate() {
                        event!(
                            "intermediate_declined",
                            committees = subnet_list(&id.subnets()),
                            mask = id.committees,
                            covered = id.covered(),
                            prover = id.prover,
                            hash = id.label(),
                            from = peer
                        );
                    } else {
                        event!(
                            "proof_declined",
                            subnet = id.subnet,
                            prover = id.prover,
                            hash = id.label(),
                            from = peer
                        );
                    }
                }
            }
            Verdict::Free | Verdict::Subsume => {
                // Commit only to a proof this peer can actually serve.
                let peer_chunks = body.as_ref().map_or(0, |b| b.present.count()).max(
                    metadata
                        .as_deref()
                        .and_then(|m| PartsMetadata::decode(m).ok())
                        .map_or(0, |m| m.available.count()),
                );
                if peer_chunks == 0 {
                    return;
                }
                self.claim(&id, verdict);
                self.partial.assemblies.insert(id.hash, ProofAssembly::new(id));
                if id.is_aggregate() {
                    event!(
                        "intermediate_committed",
                        committees = subnet_list(&id.subnets()),
                        mask = id.committees,
                        covered = id.covered(),
                        prover = id.prover,
                        hash = id.label(),
                        from = peer,
                        peer_chunks = peer_chunks,
                        subsume = verdict == Verdict::Subsume
                    );
                } else {
                    event!(
                        "proof_committed",
                        subnet = id.subnet,
                        prover = id.prover,
                        hash = id.label(),
                        from = peer,
                        peer_chunks = peer_chunks
                    );
                }
                if let Some(body) = body {
                    self.merge_chunks(&id, peer, &body);
                }
                self.republish(&id);
            }
        }
    }

    /// Merge received chunks; true if any were new.
    fn merge_chunks(&mut self, id: &ProofId, peer: PeerId, body: &ChunkBody) -> bool {
        let Some(assembly) = self.partial.assemblies.get_mut(&id.hash) else {
            return false;
        };
        let out = assembly.merge(body);
        if out.added == 0 && out.duplicate == 0 {
            return false;
        }
        self.report.duplicate_chunks += out.duplicate;
        if id.is_aggregate() {
            event!(
                "intermediate_chunk_received",
                committees = subnet_list(&id.subnets()),
                mask = id.committees,
                prover = id.prover,
                hash = id.label(),
                from = peer,
                added = out.added,
                dup = out.duplicate,
                held = out.held
            );
        } else {
            event!(
                "chunk_received",
                subnet = id.subnet,
                prover = id.prover,
                hash = id.label(),
                from = peer,
                added = out.added,
                dup = out.duplicate,
                held = out.held
            );
        }
        if out.invalid {
            event!("proof_invalid", subnet = id.subnet, mask = id.committees, hash = id.label());
        }
        if out.completed.is_some() {
            self.proof_complete(id, peer);
        }
        out.added > 0
    }

    /// Advertise what we hold of `id` and request the rest.
    fn republish(&mut self, id: &ProofId) {
        let Some(assembly) = self.partial.assemblies.get(&id.hash) else {
            return;
        };
        let outgoing = OutgoingProof::new(*id, assembly.store(), CellBitmap::all_set(id.chunks()));
        let _ = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish_partial(self.topic.hash(), outgoing);
    }

    fn handle_event(&mut self, event: SwarmEvent<SimBehaviourEvent>) {
        if self.cli.role != Role::L2 {
            return;
        }
        match event {
            SwarmEvent::Behaviour(SimBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            })) if message.topic == self.topic.hash() => match self.cli.mode {
                Mode::GossipsubChunked => {
                    self.on_chunk(propagation_source, message_id, &message.data)
                }
                Mode::GossipsubChunkedPull => {
                    self.on_header(propagation_source, message_id, &message.data)
                }
                Mode::Gossipsub | Mode::Partial => {
                    self.on_message(propagation_source, message_id, &message.data)
                }
            },
            SwarmEvent::Behaviour(SimBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            })) if self.data_topic.as_ref().is_some_and(|t| message.topic == t.hash()) => {
                self.on_pull_chunk(propagation_source, message_id, &message.data);
            }
            SwarmEvent::Behaviour(SimBehaviourEvent::Gossipsub(gossipsub::Event::Partial {
                topic_hash,
                peer_id,
                group_id,
                message,
                metadata,
            })) if topic_hash == self.topic.hash() => {
                self.on_partial(peer_id, &group_id, message, metadata);
            }
            _ => {}
        }
    }

    fn finish(&mut self) {
        let (tx, rx) = gossip_byte_totals(&self.swarm);
        self.report.tx_bytes = tx;
        self.report.rx_bytes = rx;
        self.report.committed = self.committed();
        event!("bytes", tx = tx, rx = rx);
        event!(
            "run_end",
            role = self.cli.role,
            subnets_done = self.report.subnets_done,
            aggregated = self.report.aggregate_ms.is_some(),
            redundant_proofs = self.report.redundant_proofs,
            duplicate_chunks = self.report.duplicate_chunks,
            declined = self.report.declined,
            intermediates_published = self.report.intermediates_published,
            intermediates_fetched = self.report.intermediates_fetched,
            intermediates_declined = self.report.intermediates_declined,
            merges_run = self.report.merges_run,
            merges_discarded = self.report.merges_discarded,
            items_dropped = self.report.items_dropped,
            chunks_received = self.report.chunks_received,
            chunks_ignored = self.report.chunks_ignored,
            proofs_unused = self.report.proofs_unused,
            used_unrelayed = self.report.used_unrelayed,
            idontwant_sent = self.report.idontwant_sent,
            wants_sent = self.report.wants_sent,
            chunks_unwanted = self.report.chunks_unwanted
        );
    }
}

/// Run one node until `warmup_secs + observe_secs` have passed.
pub async fn run(cli: Cli) -> NodeReport {
    info!(
        mode = %cli.mode,
        role = %cli.role,
        subnet = cli.subnet,
        prover = cli.prover,
        seed = cli.seed,
        peers = cli.peers.len(),
        intermediate_proofs = cli.intermediate_proofs,
        intermediate_fetch = %cli.intermediate_fetch,
        "proof-broadcast starting"
    );
    let tuning = cli.gossip_tuning();
    let (mut swarm, local_peer_id) = build_swarm(cli.seed, &cli.listen_ip, cli.listen_port, &tuning);
    info!(%local_peer_id, "swarm built");

    let topic = match cli.mode {
        Mode::GossipsubChunked => proofs_chunked_topic(),
        Mode::GossipsubChunkedPull => proofs_headers_topic(),
        Mode::Gossipsub | Mode::Partial => proofs_topic(),
    };
    let data_topic = (cli.mode == Mode::GossipsubChunkedPull).then(proofs_chunked_pull_topic);
    if let Some(data_topic) = &data_topic {
        // Every node gates it: L1s (not subscribed) too, to serve their chunks.
        swarm
            .behaviour_mut()
            .gossipsub
            .gate_topic(data_topic.hash(), chunk_group);
        if cli.role == Role::L2 {
            swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(data_topic)
                .expect("subscribe to the pull chunk topic");
        }
    }
    match (cli.role, cli.mode) {
        (Role::L2, Mode::Gossipsub | Mode::GossipsubChunked | Mode::GossipsubChunkedPull) => {
            swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&topic)
                .expect("subscribe to proofs topic");
        }
        (Role::L2, Mode::Partial) => subscribe_partial(&mut swarm, &topic),
        // L1 provers never subscribe; partial mode still needs the topic
        // enabled locally to answer requests for its own proof.
        (Role::L1, Mode::Partial) => swarm
            .behaviour_mut()
            .gossipsub
            .enable_partials_for_topic(topic.hash(), false),
        (Role::L1, Mode::Gossipsub | Mode::GossipsubChunked | Mode::GossipsubChunkedPull) => {}
    }
    dial_peers(&mut swarm, &cli.peers);

    let start = Instant::now();
    let epoch = start + Duration::from_secs(cli.warmup_secs);
    let publish_at = epoch + Duration::from_millis(cli.publish_delay_ms);
    let publish_giveup = publish_at + Duration::from_secs(cli.publish_grace_secs);
    let deadline = epoch + Duration::from_secs(cli.observe_secs);

    let subnets = cli.subnets;
    let workers = cli.aggregation_workers;
    let policy = cli.intermediate_fetch;
    let is_l1 = cli.role == Role::L1;
    let mut node = Node {
        cli,
        swarm,
        topic,
        data_topic,
        start,
        ledger: CoverageLedger::new(subnets, policy),
        aggregator: Aggregator::new(subnets, workers),
        jobs: FuturesUnordered::new(),
        partial: PartialState::default(),
        chunked: ChunkedState::default(),
        report: NodeReport::default(),
    };

    let mut tick = time::interval(Duration::from_millis(100));
    let mut warmup_logged = false;
    let mut publish_due = false;

    loop {
        tokio::select! {
            event = node.swarm.select_next_some() => node.handle_event(event),
            Some(item) = node.jobs.next(), if !node.jobs.is_empty() => node.on_job_done(item),
            _ = time::sleep_until(epoch), if !warmup_logged => {
                warmup_logged = true;
                let connected = node.swarm.connected_peers().count();
                let mesh = mesh_peer_count(&node.swarm, &node.topic);
                let topic_peers = topic_peer_count(&node.swarm, &node.topic);
                event!(
                    "warmup_complete",
                    connected = connected,
                    mesh = mesh,
                    topic_peers = topic_peers
                );
            }
            _ = time::sleep_until(publish_at), if is_l1 && !publish_due => {
                publish_due = true;
            }
            _ = tick.tick() => {
                let now = Instant::now();
                if now >= deadline {
                    node.finish();
                    break;
                }
            }
        }
        if publish_due && !node.report.published {
            let now = Instant::now();
            if node.l1_ready() || now >= publish_giveup {
                let late_ms = now.saturating_duration_since(publish_at).as_millis() as u64;
                node.publish(late_ms);
                // A failed publish is not retried.
                node.report.published = true;
            }
        }
    }
    node.report
}
