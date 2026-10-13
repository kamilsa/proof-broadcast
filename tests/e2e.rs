//! In-process end-to-end runs: real swarms over localhost QUIC.
//!
//! `subnets` × 2 L1 provers, and `per_node` aggregators for every tree node
//! (seeds are searched so their PeerIds land on each node). Peers are wired
//! along the tree as the launcher does: an L1 dials the members of the node
//! consuming its subnet; an L2 dials its node-mates and the members of its
//! parent node. Every L2 must finish its node's aggregate and the root
//! members the global one, and no proof is ever served to more than
//! `fanout` peers at once.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU16, Ordering};

use clap::Parser;
use futures::future::join_all;
use proof_broadcast_tree::network::peer_id_from_seed;
use proof_broadcast_tree::tree::Tree;
use proof_broadcast_tree::{Cli, NodeReport, run};

const PROVERS_PER_SUBNET: usize = 2;
const L2_PER_NODE: usize = 2;
const DEFAULT_FANOUT: usize = 8;
const AGGREGATION_MS: u64 = 200;
const PROOF_KIB: usize = 64;
const CHUNKS: usize = 16;

static NEXT_PORT: AtomicU16 = AtomicU16::new(0);

fn base_port() -> u16 {
    // Give each network its own port block; offset by pid for parallel runs.
    let block = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
    20_000 + (std::process::id() % 100) as u16 * 400 + block * 40
}

fn addr(port: u16) -> String {
    format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
}

/// `per_node` seeds (from 1000 up) whose PeerIds map to each tree node, as
/// `(seed, node)` in node order.
fn l2_seeds(tree: &Tree, per_node: usize) -> Vec<(u64, usize)> {
    let mut by_node: Vec<Vec<u64>> = vec![Vec::new(); tree.len()];
    let mut seed = 1000;
    while by_node.iter().any(|s| s.len() < per_node) {
        let node = tree.position(&peer_id_from_seed(seed));
        if by_node[node].len() < per_node {
            by_node[node].push(seed);
        }
        seed += 1;
    }
    by_node
        .into_iter()
        .enumerate()
        .flat_map(|(node, seeds)| seeds.into_iter().map(move |s| (s, node)))
        .collect()
}

struct Network {
    tree: Tree,
    fanout: usize,
    l1: Vec<NodeReport>,
    /// `(tree node, report)` per L2.
    l2: Vec<(usize, NodeReport)>,
}

async fn run_tree(subnets: usize, arity: usize) -> Network {
    run_tree_with(subnets, arity, L2_PER_NODE, DEFAULT_FANOUT).await
}

async fn run_tree_with(subnets: usize, arity: usize, per_node: usize, fanout: usize) -> Network {
    let tree = Tree::new(subnets, arity);
    let l2 = l2_seeds(&tree, per_node);
    let base = base_port();
    let l1_count = subnets * PROVERS_PER_SUBNET;
    let l2_port = |i: usize| base + (l1_count + i) as u16;
    let members = |node: usize| -> Vec<usize> {
        (0..l2.len()).filter(|&j| l2[j].1 == node).collect()
    };
    let common = |seed: u64, port: u16| {
        vec![
            "proof-broadcast-tree".to_string(),
            format!("--seed={seed}"),
            "--listen-ip=127.0.0.1".to_string(),
            format!("--listen-port={port}"),
            format!("--subnets={subnets}"),
            format!("--aggregation-arity={arity}"),
            format!("--proof-size-kib={PROOF_KIB}"),
            format!("--chunk-count={CHUNKS}"),
            format!("--aggregation-ms={AGGREGATION_MS}"),
            format!("--fanout={fanout}"),
            "--warmup-secs=4".to_string(),
            "--observe-secs=10".to_string(),
        ]
    };

    let mut clis = Vec::new();
    for i in 0..l1_count {
        let subnet = i / PROVERS_PER_SUBNET;
        let mut args = common(100 + i as u64, base + i as u16);
        args.push("--role=l1".into());
        args.push(format!("--subnet={subnet}"));
        args.push(format!("--prover={}", i % PROVERS_PER_SUBNET));
        args.push(format!("--publish-delay-ms={}", i * 100));
        let consumer = tree.consumer_of_subnet(subnet as u16).expect("every subnet is consumed");
        for j in members(consumer) {
            args.push(format!("--peer={}", addr(l2_port(j))));
        }
        clis.push(Cli::parse_from(args));
    }
    for (i, &(seed, node)) in l2.iter().enumerate() {
        let mut args = common(seed, l2_port(i));
        args.push("--role=l2".into());
        args.push(format!("--prover={i}"));
        let mates = members(node).into_iter().filter(|&j| j > i);
        let parents = tree.node(node).parent.map(members).unwrap_or_default();
        for j in mates.chain(parents) {
            args.push(format!("--peer={}", addr(l2_port(j))));
        }
        clis.push(Cli::parse_from(args));
    }
    for cli in &clis {
        cli.validate().expect("valid test config");
    }

    let handles: Vec<_> = clis.into_iter().map(|cli| tokio::spawn(run(cli))).collect();
    let mut reports: Vec<NodeReport> = join_all(handles)
        .await
        .into_iter()
        .map(|r| r.expect("node task"))
        .collect();
    let l2_reports = reports.split_off(l1_count);
    Network {
        tree,
        fanout,
        l1: reports,
        l2: l2.iter().map(|&(_, node)| node).zip(l2_reports).collect(),
    }
}

fn check(label: &str, net: &Network) {
    let proof_len = (PROOF_KIB * 1024) as u64;
    assert!(net.l1.iter().all(|r| r.published), "{label}: every L1 publishes");
    for r in net.l1.iter().chain(net.l2.iter().map(|(_, r)| r)) {
        assert!(r.fanout_peak <= net.fanout, "{label}: fan-out {} over {}", r.fanout_peak, net.fanout);
    }
    for (i, (node, r)) in net.l2.iter().enumerate() {
        eprintln!(
            "{label} L2 {i} node {node}: inputs={}/{} inputs_ms={:?} node_agg={:?} agg={:?} \
             rx_data={} chunks={} dup={} fail={} served={} (partial {}) refused={} \
             fanout_peak={} declined={}",
            r.inputs_done, r.inputs, r.inputs_ms, r.node_aggregate_ms, r.aggregate_ms,
            r.rx_data, r.chunks_received, r.duplicate_chunks, r.chunk_failures,
            r.chunks_served, r.chunks_served_partial, r.chunks_refused, r.fanout_peak,
            r.declined
        );
        assert_eq!(r.tree_node, Some(*node), "{label}: L2 {i} sits where its PeerId maps");
        let want: BTreeSet<u64> = net.tree.input_masks(*node).into_iter().collect();
        let got: BTreeSet<u64> = r.committed.iter().map(|id| id.committees).collect();
        assert_eq!(r.inputs_done, r.inputs, "{label}: L2 {i} held every input: {r:?}");
        assert_eq!(got, want, "{label}: L2 {i} held exactly one proof per input");
        assert_eq!(r.committed.len(), want.len());
        let inputs_ms = r.inputs_ms.expect("inputs complete");
        let done = r.node_aggregate_ms.expect("node aggregate");
        assert!(done >= inputs_ms + AGGREGATION_MS, "{label}: L2 {i} ran one recursion");
        assert_eq!(r.aggregate_ms.is_some(), r.is_root, "{label}: only the root is global");
        assert_eq!(r.chunks_received, r.inputs * CHUNKS);
        assert_eq!(r.duplicate_chunks, 0, "{label}: L2 {i} got duplicate chunks");
        // Each chunk response frame: 4-byte length, 4-byte variant, 8-byte
        // vec length, then the data: nothing beyond one copy of each input.
        let frames = (r.inputs * CHUNKS) as u64 * 16;
        assert_eq!(r.rx_data, r.inputs as u64 * proof_len + frames, "{label}: L2 {i}");
    }
    // A parent finishes only after one of its children did.
    let first_done: HashMap<usize, u64> = net.l2.iter().fold(HashMap::new(), |mut m, (n, r)| {
        let t = r.node_aggregate_ms.expect("node aggregate");
        m.entry(*n).and_modify(|v: &mut u64| *v = (*v).min(t)).or_insert(t);
        m
    });
    for n in net.tree.nodes() {
        if let Some(p) = n.parent {
            assert!(first_done[&p] > first_done[&n.id], "{label}: node {p} after child {}", n.id);
        }
    }
    let served: usize = net.l1.iter().map(|r| r.chunks_served).sum::<usize>()
        + net.l2.iter().map(|(_, r)| r.chunks_served).sum::<usize>();
    let received: usize = net.l2.iter().map(|(_, r)| r.chunks_received).sum();
    assert_eq!(served, received, "{label}: every served chunk was used once");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binary_tree_of_four_subnets() {
    let net = run_tree(4, 2).await;
    assert_eq!(net.tree.len(), 3);
    check("4/2", &net);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binary_tree_of_eight_subnets_is_three_levels_deep() {
    let net = run_tree(8, 2).await;
    assert_eq!(net.tree.len(), 7);
    assert_eq!(net.tree.depth(), 3);
    check("8/2", &net);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn arity_four_tree_of_eight_subnets() {
    let net = run_tree(8, 4).await;
    assert_eq!(net.tree.len(), 3);
    assert_eq!(net.tree.depth(), 2);
    check("8/4", &net);
    for (_, r) in &net.l2 {
        let expected = if r.is_root { 2 } else { 4 };
        assert_eq!(r.inputs, expected);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn uneven_tree_promotes_a_subnet_to_the_root() {
    // 5 subnets, arity 2: the root merges {0..3} with subnet 4's proof.
    let net = run_tree(5, 2).await;
    assert_eq!(net.tree.len(), 4);
    check("5/2", &net);
}

/// Fan-out 1 with four aggregators per node: every proof reaches a node's
/// aggregators along a relay chain, mostly forwarded while still arriving.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fanout_one_relays_through_node_mates() {
    let net = run_tree_with(4, 2, 4, 1).await;
    check("4/2 fanout 1", &net);
    let partial: usize = net.l2.iter().map(|(_, r)| r.chunks_served_partial).sum();
    assert!(partial > 0, "chunks were relayed before their proof was complete");
    for r in &net.l1 {
        assert!(r.max_peers_per_proof <= 4);
    }
}
