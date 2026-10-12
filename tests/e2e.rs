//! In-process end-to-end runs: real swarms over localhost QUIC.
//!
//! 2 subnets × 2 L1 provers + 4 L2 provers. L1s dial every L2; L2s dial each
//! other. Every L2 must collect one proof per subnet and finish aggregating.

use std::sync::atomic::{AtomicU16, Ordering};

use clap::Parser;
use futures::future::join_all;
use proof_broadcast::{Cli, Mode, NodeReport, run};

const SUBNETS: usize = 2;
const PROVERS_PER_SUBNET: usize = 2;
const L2_COUNT: usize = 4;
const AGGREGATION_MS: u64 = 200;

static NEXT_PORT: AtomicU16 = AtomicU16::new(0);

fn base_port() -> u16 {
    // Separate the two modes' port ranges; offset by pid for parallel runs.
    let block = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
    30_000 + (std::process::id() % 500) as u16 * 40 + block * 20
}

fn addr(port: u16) -> String {
    format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
}

async fn run_network(mode: Mode) -> (Vec<NodeReport>, Vec<NodeReport>) {
    let base = base_port();
    let l1_count = SUBNETS * PROVERS_PER_SUBNET;
    let l2_port = |i: usize| base + (l1_count + i) as u16;
    let common = |seed: u64, port: u16| {
        vec![
            "proof-broadcast".to_string(),
            format!("--mode={}", mode),
            format!("--seed={seed}"),
            "--listen-ip=127.0.0.1".to_string(),
            format!("--listen-port={port}"),
            format!("--subnets={SUBNETS}"),
            "--proof-size-kib=64".to_string(),
            "--chunk-count=16".to_string(),
            format!("--aggregation-ms={AGGREGATION_MS}"),
            "--warmup-secs=4".to_string(),
            "--observe-secs=10".to_string(),
            "--proofs-mesh-n=3".to_string(),
            "--proofs-mesh-n-low=2".to_string(),
            "--proofs-mesh-n-high=4".to_string(),
            "--proofs-mesh-outbound-min=1".to_string(),
        ]
    };

    let mut clis = Vec::new();
    for i in 0..l1_count {
        let mut args = common(100 + i as u64, base + i as u16);
        args.push("--role=l1".into());
        args.push(format!("--subnet={}", i / PROVERS_PER_SUBNET));
        args.push(format!("--prover={}", i % PROVERS_PER_SUBNET));
        args.push(format!("--publish-delay-ms={}", i * 150));
        for j in 0..L2_COUNT {
            args.push(format!("--peer={}", addr(l2_port(j))));
        }
        clis.push(Cli::parse_from(args));
    }
    for i in 0..L2_COUNT {
        let mut args = common(200 + i as u64, l2_port(i));
        args.push("--role=l2".into());
        for j in (i + 1)..L2_COUNT {
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
    let l2 = reports.split_off(l1_count);
    (reports, l2)
}

fn check(mode: Mode, l1: &[NodeReport], l2: &[NodeReport]) {
    assert!(l1.iter().all(|r| r.published), "{mode}: every L1 publishes");
    for (i, r) in l2.iter().enumerate() {
        eprintln!(
            "{mode} L2 {i}: rx={} tx={} redundant={} dup_chunks={} declined={} all={:?} agg={:?}",
            r.rx_bytes, r.tx_bytes, r.redundant_proofs, r.duplicate_chunks, r.declined,
            r.all_subnets_ms, r.aggregate_ms
        );
        assert_eq!(r.subnets_done, SUBNETS, "{mode}: L2 {i} collected every subnet: {r:?}");
        assert!(r.committed.iter().all(Option::is_some), "{mode}: L2 {i} chose every subnet");
        let first = r.first_proof_ms.expect("first proof");
        let aggregated = r.aggregate_ms.expect("aggregate completes");
        assert!(
            aggregated >= first + (SUBNETS as u64 - 1) * AGGREGATION_MS,
            "{mode}: L2 {i} aggregation takes (subnets-1) recursions: {r:?}"
        );
        assert!(aggregated >= r.all_subnets_ms.expect("all subnets"));
        assert!(r.rx_bytes > 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gossipsub_mode_delivers_one_proof_per_subnet() {
    let (l1, l2) = run_network(Mode::Gossipsub).await;
    check(Mode::Gossipsub, &l1, &l2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partial_mode_delivers_one_proof_per_subnet() {
    let (l1, l2) = run_network(Mode::Partial).await;
    check(Mode::Partial, &l1, &l2);
    // L1s never subscribe, so they never receive anyone's proof.
    for r in &l1 {
        assert_eq!(r.subnets_done, 0);
    }
}
