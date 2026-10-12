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

use crate::aggregation::{Aggregator, Job, Subnets, subnet_list};
use crate::event;
use crate::gossip_mode::ProofMessage;
use crate::network::{
    GossipTuning, MeshTuning, SimBehaviour, SimBehaviourEvent, build_swarm, dial_peers,
    gossip_byte_totals, mesh_peer_count, proofs_topic, subscribe_partial, topic_peer_count,
};
use crate::partial_mode::{
    CellBitmap, ChunkBody, OutgoingProof, PartialState, PartsMetadata, ProofAssembly,
};
use crate::proof::{MAX_CHUNKS, ProofId, SubnetLedger, Verdict, make_proof, split};

/// Propagation protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// Whole proofs as gossipsub messages on `/proofs/1`.
    Gossipsub,
    /// Chunked proofs via gossipsub 1.3 partial messages.
    Partial,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Gossipsub => "gossipsub",
            Self::Partial => "partial",
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

    /// Index of this L1 prover within its subnet.
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

    /// Chunks per proof in `partial` mode.
    #[arg(long, default_value_t = 64)]
    pub chunk_count: usize,

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
        if self.subnets == 0 || self.subnets > u16::MAX as usize {
            return Err(format!("subnets must be in 1..=65535, got {}", self.subnets));
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
        self.gossip_tuning().mesh.validate()
    }

    fn proof_len(&self) -> usize {
        self.proof_size_kib.saturating_mul(1024)
    }
}

/// What a node observed, returned by [`run`] for in-process tests. Times are
/// milliseconds since the node started.
#[derive(Debug, Clone, Default)]
pub struct NodeReport {
    pub published: bool,
    pub subnets_done: usize,
    pub first_proof_ms: Option<u64>,
    pub all_subnets_ms: Option<u64>,
    pub aggregate_ms: Option<u64>,
    /// Hash chosen per subnet (L2).
    pub committed: Vec<Option<[u8; 32]>>,
    /// Gossipsub mode: proofs received from an already-served subnet.
    pub redundant_proofs: usize,
    /// Partial mode: chunks received that were already held.
    pub duplicate_chunks: usize,
    /// Proofs declined because their subnet was already chosen.
    pub declined: usize,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

type JobFuture = Pin<Box<dyn Future<Output = Subnets> + Send>>;

struct Node {
    cli: Cli,
    swarm: Swarm<SimBehaviour>,
    topic: IdentTopic,
    start: Instant,
    ledger: SubnetLedger,
    aggregator: Aggregator,
    jobs: FuturesUnordered<JobFuture>,
    partial: PartialState,
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

    // ── L1 ──────────────────────────────────────────────────────────────

    fn publish(&mut self, late_ms: u64) {
        let proof = make_proof(self.cli.seed, self.cli.proof_len());
        let id = ProofId::for_proof(self.cli.subnet, self.cli.prover, &proof, self.cli.chunk_count);
        let fanout = topic_peer_count(&self.swarm, &self.topic);
        let result = match self.cli.mode {
            Mode::Gossipsub => {
                let msg = ProofMessage {
                    subnet: id.subnet,
                    prover: id.prover,
                    data: proof,
                };
                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(self.topic.clone(), msg.encode())
                    .map(|_| ())
            }
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
            }
        };
        match result {
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

    /// The chosen proof for `id.subnet` is fully held.
    fn proof_complete(&mut self, id: &ProofId, from: PeerId) {
        if !self.ledger.complete(id.subnet) {
            return;
        }
        let now = self.elapsed_ms();
        self.report.first_proof_ms.get_or_insert(now);
        self.report.subnets_done = self.ledger.subnets_done();
        event!(
            "proof_complete",
            subnet = id.subnet,
            prover = id.prover,
            hash = id.label(),
            from = from,
            subnets_done = self.report.subnets_done
        );
        if self.ledger.all_done() {
            self.report.all_subnets_ms = Some(now);
            event!("all_subnets_complete", subnets = self.ledger.subnets());
        }
        let jobs = self.aggregator.add_leaf(id.subnet);
        self.after_aggregation_step(jobs);
    }

    fn after_aggregation_step(&mut self, jobs: Vec<Job>) {
        if self.aggregator.is_complete() && self.report.aggregate_ms.is_none() {
            self.report.aggregate_ms = Some(self.elapsed_ms());
            event!("aggregate_complete", subnets = self.ledger.subnets());
        }
        let duration = Duration::from_millis(self.cli.aggregation_ms);
        for job in jobs {
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
        event!(
            "aggregation_done",
            covered = item.len(),
            subnets = subnet_list(&item)
        );
        let jobs = self.aggregator.job_done(item);
        self.after_aggregation_step(jobs);
    }

    // ── L2: gossipsub ───────────────────────────────────────────────────

    fn on_message(&mut self, source: PeerId, message_id: gossipsub::MessageId, data: &[u8]) {
        let validate = |node: &mut Self, acceptance| {
            node.swarm
                .behaviour_mut()
                .gossipsub
                .report_message_validation_result(&message_id, &source, acceptance);
        };
        let Ok(msg) = ProofMessage::decode(data) else {
            validate(self, MessageAcceptance::Reject);
            return;
        };
        let id = ProofId::for_proof(msg.subnet, msg.prover, &msg.data, self.cli.chunk_count);
        match self.ledger.verdict(&id) {
            Verdict::Free => {
                self.ledger.commit(&id);
                validate(self, MessageAcceptance::Accept);
                event!(
                    "proof_received",
                    subnet = id.subnet,
                    prover = id.prover,
                    hash = id.label(),
                    from = source,
                    bytes = data.len(),
                    redundant = false
                );
                self.proof_complete(&id, source);
            }
            // Same bytes are deduplicated by message id; nothing to do.
            Verdict::Mine => validate(self, MessageAcceptance::Ignore),
            Verdict::Taken => {
                validate(self, MessageAcceptance::Ignore);
                self.report.redundant_proofs += 1;
                if self.ledger.decline(&id) {
                    self.report.declined += 1;
                }
                event!(
                    "proof_received",
                    subnet = id.subnet,
                    prover = id.prover,
                    hash = id.label(),
                    from = source,
                    bytes = data.len(),
                    redundant = true
                );
            }
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
        match self.ledger.verdict(&id) {
            Verdict::Mine => {
                // Republish when we gained chunks, or when a peer's metadata
                // may be the first it heard of our request.
                let gained = body.is_none_or(|body| self.merge_chunks(&id, peer, &body));
                if gained {
                    self.republish(&id);
                }
            }
            Verdict::Taken => {
                if self.ledger.decline(&id) {
                    self.report.declined += 1;
                    event!(
                        "proof_declined",
                        subnet = id.subnet,
                        prover = id.prover,
                        hash = id.label(),
                        from = peer
                    );
                }
            }
            Verdict::Free => {
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
                self.ledger.commit(&id);
                self.report.committed = (0..self.ledger.subnets())
                    .map(|s| self.ledger.committed(s))
                    .collect();
                self.partial.assemblies.insert(id.hash, ProofAssembly::new(id));
                event!(
                    "proof_committed",
                    subnet = id.subnet,
                    prover = id.prover,
                    hash = id.label(),
                    from = peer,
                    peer_chunks = peer_chunks
                );
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
        if out.invalid {
            event!("proof_invalid", subnet = id.subnet, hash = id.label());
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
            })) if message.topic == self.topic.hash() => {
                self.on_message(propagation_source, message_id, &message.data);
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
        self.report.committed = (0..self.ledger.subnets())
            .map(|s| self.ledger.committed(s))
            .collect();
        event!("bytes", tx = tx, rx = rx);
        event!(
            "run_end",
            role = self.cli.role,
            subnets_done = self.report.subnets_done,
            aggregated = self.report.aggregate_ms.is_some(),
            redundant_proofs = self.report.redundant_proofs,
            duplicate_chunks = self.report.duplicate_chunks,
            declined = self.report.declined
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
        "proof-broadcast starting"
    );
    let tuning = cli.gossip_tuning();
    let (mut swarm, local_peer_id) = build_swarm(cli.seed, &cli.listen_ip, cli.listen_port, &tuning);
    info!(%local_peer_id, "swarm built");

    let topic = proofs_topic();
    match (cli.role, cli.mode) {
        (Role::L2, Mode::Gossipsub) => {
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
        (Role::L1, Mode::Gossipsub) => {}
    }
    dial_peers(&mut swarm, &cli.peers);

    let start = Instant::now();
    let epoch = start + Duration::from_secs(cli.warmup_secs);
    let publish_at = epoch + Duration::from_millis(cli.publish_delay_ms);
    let publish_giveup = publish_at + Duration::from_secs(cli.publish_grace_secs);
    let deadline = epoch + Duration::from_secs(cli.observe_secs);

    let subnets = cli.subnets;
    let workers = cli.aggregation_workers;
    let is_l1 = cli.role == Role::L1;
    let mut node = Node {
        cli,
        swarm,
        topic,
        start,
        ledger: SubnetLedger::new(subnets),
        aggregator: Aggregator::new(subnets, workers),
        jobs: FuturesUnordered::new(),
        partial: PartialState::default(),
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
